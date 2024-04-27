use std::ffi::c_int;
use std::ffi::OsString;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Child;
use std::process::Command;
use std::process::ExitCode;

use caps::errors::CapsError;
use caps::CapSet;
use caps::Capability;
use clap::Parser;
use libseccomp::error::SeccompError;
use libseccomp::notify_id_valid;
use libseccomp::ScmpFd;
use libseccomp::ScmpNotifReq;
use libseccomp::ScmpNotifResp;
use libseccomp::ScmpNotifRespFlags;
use nix::sys::prctl::set_no_new_privs;
use passfd::FdPassingExt;
use socketpair::socketpair_stream;
use socketpair::SocketpairStream;

use crate::Logger;
use cijail::EndpointSet;
use cijail::Error;

mod logger;
mod socket;
mod tracer;

pub(crate) use self::logger::*;

pub(crate) const CIJAIL_ENDPOINTS: &str = "CIJAIL_ENDPOINTS";
const CIJAIL_TRACER: &str = "CIJAIL_TRACER";

fn install_seccomp_notify_filter() -> Result<ScmpFd, Error> {
    use libseccomp::*;
    let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
    filter.add_arch(ScmpArch::native())?;
    for name in ["connect", "sendto", "sendmsg", "sendmmsg"] {
        filter.add_rule(ScmpAction::Notify, ScmpSyscall::from_name(name)?)?;
    }
    filter.load()?;
    Ok(filter.get_notify_fd()?)
}

fn drop_capabilities() -> Result<(), CapsError> {
    // We drop `CAP_SYS_PTRACE` capability to ensure that
    // the tracee can't modify tracer's memory.
    caps::drop(None, CapSet::Ambient, Capability::CAP_SYS_PTRACE)?;
    if caps::has_cap(None, CapSet::Effective, Capability::CAP_SETPCAP)? {
        caps::drop(None, CapSet::Bounding, Capability::CAP_SYS_PTRACE)?;
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
            drop_capabilities().map_err(Error::map)?;
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
        let arg0 = arg0.to_string_lossy();
        let args = args
            .iter()
            .map(|x| x.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        format!("failed to run `{} {}`: {}", arg0, args, e)
    })?;
    Ok(child)
}

fn spawn_tracer_process(
    socket: SocketpairStream,
    allowed_endpoints: EndpointSet,
) -> Result<Child, Box<dyn std::error::Error>> {
    let arg0 = std::env::args_os()
        .next()
        .ok_or_else(|| Error::map("can not find zeroth argument"))?;
    let mut child = Command::new(arg0.clone());
    child.env(CIJAIL_TRACER, "1");
    child.env(CIJAIL_ENDPOINTS, allowed_endpoints.to_string());
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
    /// Command to run.
    #[arg(allow_hyphen_values = true)]
    command: Vec<OsString>,
}

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    Logger::init().map_err(|_| "failed to set logger")?;
    if std::env::var_os(CIJAIL_TRACER).is_some() {
        return tracer::main(0);
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
    let mut tracer = spawn_tracer_process(socket1, allowed_endpoints)?;
    let status = tracee.wait()?;
    tracer.kill()?;
    tracer.wait()?;
    Ok(match status.code() {
        Some(code) => (code as u8).into(),
        None => {
            eprintln!("terminated by signal");
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
