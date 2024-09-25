use std::ffi::c_int;
use std::ffi::OsString;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::process::Child;
use std::process::Command;
use std::process::ExitCode;

use caps::errors::CapsError;
use caps::CapSet;
use caps::Capability;
use cijail::bool_to_str;
use cijail::env_to_bool;
use cijail::EndpointSet;
use cijail::Error;
use cijail::Logger;
use cijail::ProxyConfig;
use cijail::CIJAIL_DRY_RUN;
use cijail::CIJAIL_ENDPOINTS;
use cijail::CIJAIL_PROXY_PID;
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
use nix::sys::wait::waitpid;
use nix::sys::wait::WaitStatus;
use nix::unistd::fork;
use nix::unistd::ForkResult;
use nix::unistd::Pid;
use passfd::FdPassingExt;
use socketpair::socketpair_stream;
use socketpair::SocketpairStream;

mod socket;
mod tracer;

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
    let set = CapSet::Ambient;
    if caps::has_cap(None, set, CAP)? {
        info!("dropping `{}` from the `{:?}` set", CAP, set);
        caps::drop(None, set, CAP)?;
    }
    Ok(())
}

fn exec_tracee(mut command: Command, socket: RawFd) -> Result<(), i32> {
    drop_capabilities().map_err(|_| 1)?;
    set_no_new_privs().map_err(|_| 1)?;
    let notify_fd = install_seccomp_notify_filter().map_err(|_| KERNEL_TOO_OLD)?;
    // allow the first `sendmsg` call
    let tmp_thread = std::thread::spawn(move || -> Result<(), SeccompError> {
        for _ in 0..1 {
            let request = ScmpNotifReq::receive(notify_fd)?;
            notify_id_valid(notify_fd, request.id)?;
            let response = ScmpNotifResp::new_continue(request.id, ScmpNotifRespFlags::empty());
            response.respond(notify_fd)?;
        }
        Ok(())
    });
    // this is the first `sendmsg` call that we allow via the temporary thread above
    socket.send_fd(notify_fd).map_err(|_| 1)?;
    tmp_thread.join().map_err(|_| 1)?.map_err(|_| 1)?;
    // file descriptors seem to close automatically
    command.exec();
    Err(EXEC_FAILED)
}

fn spawn_tracee_process(
    socket: SocketpairStream,
    mut args: Vec<OsString>,
    proxy_config: ProxyConfig,
) -> Result<Pid, Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Err("please specify the command to run".into());
    }
    let arg0 = args.remove(0);
    let mut command = Command::new(arg0.clone());
    command.args(args.clone());
    proxy_config.setenv(&mut command);
    let socket = socket.as_raw_fd();
    let child_pid = match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => child,
        Ok(ForkResult::Child) => {
            let ret = match exec_tracee(command, socket) {
                Ok(_) => 0,
                Err(_) => EXEC_FAILED,
            };
            unsafe { libc::_exit(ret) }
        }
        Err(e) => return Err(format!("failed to fork: {}", e).into()),
    };
    Ok(child_pid)
}

fn spawn_tracer_process(
    socket: SocketpairStream,
    allowed_endpoints: &EndpointSet,
    is_dry_run: bool,
    allow_loopback: bool,
    proxy_pid: u32,
) -> Result<Child, Box<dyn std::error::Error>> {
    let arg0 = std::env::args_os()
        .next()
        .ok_or_else(|| Error::map("can not find zeroth argument"))?;
    let mut child = Command::new(arg0.clone());
    child.env(CIJAIL_TRACER, "1");
    child.env(CIJAIL_ENDPOINTS, allowed_endpoints.to_base64()?);
    child.env(CIJAIL_DRY_RUN, bool_to_str(is_dry_run));
    child.env(CIJAIL_ALLOW_LOOPBACK, bool_to_str(allow_loopback));
    child.env(CIJAIL_PROXY_PID, proxy_pid.to_string());
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

fn spawn_proxy_process(
    allowed_endpoints: &EndpointSet,
    is_dry_run: bool,
    allow_loopback: bool,
) -> Result<(Child, ProxyConfig), Box<dyn std::error::Error>> {
    let mut sockets = socketpair_stream()?;
    let arg0 = std::env::args_os()
        .next()
        .ok_or_else(|| Error::map("can not find zeroth argument"))?;
    let arg0 = format!("{}-proxy", arg0.to_string_lossy());
    let mut child = Command::new(arg0.clone());
    child.env(CIJAIL_ENDPOINTS, allowed_endpoints.to_base64()?);
    child.env(CIJAIL_DRY_RUN, bool_to_str(is_dry_run));
    child.env(CIJAIL_ALLOW_LOOPBACK, bool_to_str(allow_loopback));
    unsafe {
        let socket = sockets.0.as_raw_fd();
        child.pre_exec(move || {
            // File descriptors seem to close automatically,
            // hence we remap socketpair fd to stdin fd.
            check(libc::dup2(socket, 0))?;
            Ok(())
        })
    };
    let child = child
        .spawn()
        .map_err(move |e| format!("failed to run `{}`: {}", arg0, e))?;
    let config = ProxyConfig::read(&mut sockets.1)?;
    Ok((child, config))
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
    Logger::init("cijail").map_err(|_| "failed to set logger")?;
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
    let mut allowed_endpoints: EndpointSet = match std::env::var(CIJAIL_ENDPOINTS) {
        Ok(endpoints) => EndpointSet::parse_with_dns_name_resolution(endpoints.as_str())?,
        Err(_) => Default::default(),
    };
    let (socket0, socket1) = socketpair_stream()?;
    let (mut proxy, proxy_config) = spawn_proxy_process(
        &allowed_endpoints,
        is_dry_run || args.dry_run,
        allow_loopback || args.allow_loopback,
    )?;
    allowed_endpoints.allow_socketaddr(proxy_config.http_url.socketaddr);
    allowed_endpoints.allow_socketaddr(proxy_config.https_url.socketaddr);
    let tracee_args = args.command.clone();
    let tracee = spawn_tracee_process(socket0, args.command, proxy_config)?;
    let mut tracer = spawn_tracer_process(
        socket1,
        &allowed_endpoints,
        is_dry_run || args.dry_run,
        allow_loopback || args.allow_loopback,
        proxy.id(),
    )?;
    let status = waitpid(tracee, None)?;
    tracer.kill()?;
    tracer.wait()?;
    proxy.kill()?;
    proxy.wait()?;
    Ok(match status {
        WaitStatus::Exited(_, code) => {
            if code == EXEC_FAILED || code == KERNEL_TOO_OLD {
                let args = tracee_args
                    .into_iter()
                    .map(|x| x.to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                if code == EXEC_FAILED {
                    error!("failed to execute `{}`: does the file exist?", args);
                }
                if code == KERNEL_TOO_OLD {
                    error!(
                        "failed to run `{}`: your kernel version is likely too old: \
                        must be at least 5.0.0 to support SECCOMP_FILTER_FLAG_NEW_LISTENER",
                        args
                    )
                }
            }
            (if is_dry_run { DRY_RUN } else { code as u8 }).into()
        }
        WaitStatus::Signaled(_, signal, _) => {
            error!("terminated by {:?}", signal);
            ExitCode::FAILURE
        }
        // should not be reachable
        _ => ExitCode::FAILURE,
    })
}

fn check(ret: c_int) -> Result<c_int, std::io::Error> {
    if ret == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

const EXEC_FAILED: i32 = 111;
const KERNEL_TOO_OLD: i32 = 88;
const DRY_RUN: u8 = 99;
