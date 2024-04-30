use std::ffi::c_int;
use std::ffi::OsString;
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Child;
use std::process::Command;
use std::process::ExitCode;

use caps::errors::CapsError;
use caps::CapSet;
use caps::Capability;
use cijail::EndpointSet;
use cijail::Error;
use clap::Parser;
use libseccomp::error::SeccompError;
use libseccomp::notify_id_valid;
use libseccomp::ScmpFd;
use libseccomp::ScmpNotifReq;
use libseccomp::ScmpNotifResp;
use libseccomp::ScmpNotifRespFlags;
use log::error;
use log::info;
use nix::sys::prctl::set_no_new_privs;
use passfd::FdPassingExt;
use socketpair::socketpair_stream;
use socketpair::SocketpairStream;

use crate::Logger;

mod logger;
mod socket;
mod tracer;

pub(crate) use self::logger::*;

pub(crate) const CIJAIL_ENDPOINTS: &str = "CIJAIL_ENDPOINTS";
const CIJAIL_DRY_RUN: &str = "CIJAIL_DRY_RUN";
const CIJAIL_ALLOW_LOOPBACK: &str = "CIJAIL_ALLOW_LOOPBACK";
const CIJAIL_TRACER: &str = "CIJAIL_TRACER";

fn install_seccomp_notify_filter() -> Result<ScmpFd, Error> {
    use libseccomp::*;
    let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
    filter.add_arch(ScmpArch::native())?;
    for name in [
        "connect", "sendto", "sendmsg", "sendmmsg", "write", "send", "open", "openat",
    ] {
        filter.add_rule(ScmpAction::Notify, ScmpSyscall::from_name(name)?)?;
    }
    for name in ["unshare", "setns", "mount", "umount", "process_vm_writev"] {
        filter.add_rule(
            ScmpAction::Errno(libc::EPERM),
            ScmpSyscall::from_name(name)?,
        )?;
    }
    filter.load()?;
    Ok(filter.get_notify_fd()?)
}

fn drop_capabilities() -> Result<(), CapsError> {
    const CAP: Capability = Capability::CAP_SYS_PTRACE;
    if caps::has_cap(None, CapSet::Effective, Capability::CAP_SETPCAP)?
        && caps::has_cap(None, CapSet::Bounding, CAP)?
    {
        info!("dropping `{}` from the `{:?}` set", CAP, CapSet::Bounding);
        caps::drop(None, CapSet::Bounding, CAP)?;
    }
    for set in [
        CapSet::Permitted,
        CapSet::Effective,
        CapSet::Inheritable,
        CapSet::Ambient,
    ] {
        if caps::has_cap(None, set, CAP)? {
            info!("dropping `{}` from the `{:?}` set", CAP, set);
            caps::drop(None, set, CAP)?;
        }
    }
    for set in [
        CapSet::Permitted,
        CapSet::Effective,
        CapSet::Inheritable,
        CapSet::Ambient,
        CapSet::Bounding,
    ] {
        let capabilities = caps::read(None, set)?;
        eprintln!("{:?}: {:?}", set, capabilities);
    }
    Ok(())
}

fn spawn_tracee_process(
    socket: SocketpairStream,
    mut args: Vec<OsString>,
) -> Result<Child, Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Err("please specify the command to run".into());
    }
    let arg0 = args.remove(0);
    let mut child = Command::new(arg0.clone());
    child.args(args.clone());
    unsafe {
        let socket = socket.as_raw_fd();
        child.pre_exec(move || {
            drop_capabilities().map_err(|_| {
                std::io::Error::new(ErrorKind::Other, "failed to drop capabilities")
            })?;
            set_no_new_privs()?;
            let notify_fd = install_seccomp_notify_filter()?;
            // allow the first `sendmsg` call
            let tmp_thread = std::thread::spawn(move || -> Result<(), SeccompError> {
                let request = ScmpNotifReq::receive(notify_fd)?;
                notify_id_valid(notify_fd, request.id)?;
                let response = ScmpNotifResp::new_continue(request.id, ScmpNotifRespFlags::empty());
                response.respond(notify_fd)?;
                Ok(())
            });
            // this is the first `sendmsg` call that we allow via the temporary thread above
            socket.send_fd(notify_fd)?;
            tmp_thread
                .join()
                .map_err(|_| Error::map("failed to join thread"))?
                .map_err(Error::Seccomp)?;
            // file descriptors seem to close automatically
            Ok(())
        })
    };
    let child = child.spawn().map_err(move |e| {
        let args = [arg0.to_string_lossy()]
            .into_iter()
            .chain(args.iter().map(|x| x.to_string_lossy()))
            .collect::<Vec<_>>()
            .join(" ");
        format!("failed to run `{}`: {}", args, e)
    })?;
    Ok(child)
}

fn spawn_tracer_process(
    socket: SocketpairStream,
    allowed_endpoints: EndpointSet,
    is_dry_run: bool,
    allow_loopback: bool,
) -> Result<Child, Box<dyn std::error::Error>> {
    let arg0 = std::env::args_os()
        .next()
        .ok_or_else(|| Error::map("can not find zeroth argument"))?;
    let mut child = Command::new(arg0.clone());
    child.env(CIJAIL_TRACER, "1");
    child.env(CIJAIL_ENDPOINTS, allowed_endpoints.to_base64()?);
    child.env(CIJAIL_DRY_RUN, bool_to_str(is_dry_run));
    child.env(CIJAIL_ALLOW_LOOPBACK, bool_to_str(allow_loopback));
    unsafe {
        let socket = socket.as_raw_fd();
        child.pre_exec(move || {
            let notify_fd = socket.as_raw_fd().recv_fd()?;
            // File descriptors seem to close automatically,
            // hence we remap notify fd to stdin fd.
            check(libc::dup2(notify_fd, 0))?;
            Ok(())
        })
    };
    let child = child
        .spawn()
        .map_err(move |e| format!("failed to run `{}`: {}", arg0.to_string_lossy(), e))?;
    Ok(child)
}

#[derive(Parser)]
#[command(
    about = "CI/CD pipeline process jail that filters outgoing network traffic.",
    long_about = None,
    arg_required_else_help = true,
    trailing_var_arg = true
)]
struct Args {
    /// Print version.
    #[clap(long, action)]
    version: bool,
    /// Do not enforce restrictions, but print all decisions (overrides CIJAIL_DRY_RUN environment variable).
    #[clap(long, action)]
    dry_run: bool,
    /// Allow to connect to any address and port in the loopback network (overrides
    /// CIJAIL_ALLOW_LOOPBACK environment variable).
    #[clap(long, action)]
    allow_loopback: bool,
    /// Command to run.
    #[arg(allow_hyphen_values = true)]
    command: Vec<OsString>,
}

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    Logger::init().map_err(|_| "failed to set logger")?;
    match do_main() {
        Ok(code) => Ok(code),
        Err(e) => {
            error!("{}", e);
            Ok(ExitCode::FAILURE)
        }
    }
}

fn do_main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let is_dry_run = env_to_bool(CIJAIL_DRY_RUN)?;
    let allow_loopback = env_to_bool(CIJAIL_ALLOW_LOOPBACK)?;
    if std::env::var_os(CIJAIL_TRACER).is_some() {
        return tracer::main(0, is_dry_run, allow_loopback);
    }
    let args = Args::parse();
    if args.version {
        let version = env!("CIJAIL_VERSION");
        println!("{}", version);
        return Ok(ExitCode::SUCCESS);
    }
    // resolve DNS names *before* the tracee process is spawned
    let allowed_endpoints: EndpointSet = match std::env::var(CIJAIL_ENDPOINTS) {
        Ok(endpoints) => EndpointSet::parse_with_dns_name_resolution(endpoints.as_str())?,
        Err(_) => Default::default(),
    };
    let (socket0, socket1) = socketpair_stream()?;
    let mut tracee = spawn_tracee_process(socket0, args.command)?;
    let mut tracer = spawn_tracer_process(
        socket1,
        allowed_endpoints,
        is_dry_run || args.dry_run,
        allow_loopback || args.allow_loopback,
    )?;
    let status = tracee.wait()?;
    tracer.kill()?;
    tracer.wait()?;
    Ok(match status.code() {
        Some(code) => (if is_dry_run { 99 } else { code as u8 }).into(),
        None => {
            error!("terminated by signal");
            ExitCode::FAILURE
        }
    })
}

fn check(ret: c_int) -> Result<c_int, std::io::Error> {
    if ret == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn env_to_bool(name: &str) -> Result<bool, std::io::Error> {
    match std::env::var(name) {
        Ok(value) => str_to_bool(value.as_str()),
        Err(_) => Ok(false),
    }
}

fn str_to_bool(s: &str) -> Result<bool, std::io::Error> {
    let s = s.trim();
    match s {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(std::io::Error::new(
            ErrorKind::Other,
            format!("invalid boolean: `{}`", s),
        )),
    }
}

fn bool_to_str(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}
