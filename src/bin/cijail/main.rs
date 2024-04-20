use std::env::args_os;
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
use libseccomp::notify_id_valid;
use libseccomp::ScmpFd;
use libseccomp::ScmpNotifReq;
use libseccomp::ScmpNotifResp;
use libseccomp::ScmpNotifRespFlags;
use passfd::FdPassingExt;
use prctl::set_no_new_privileges;
use socketpair::socketpair_stream;
use socketpair::SocketpairStream;

mod error;

use crate::error::*;

fn install_seccomp_notify_filter() -> Result<ScmpFd, Error> {
    use libseccomp::*;
    let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
    filter.add_arch(ScmpArch::native())?;
    for name in ["connect", "sendto", "sendmsg", "sendmmsg", "close"] {
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

fn spawn_target_process(socket: SocketpairStream) -> Result<Child, Box<dyn std::error::Error>> {
    let arg0 = args_os()
        .nth(1)
        .ok_or_else(|| format!("please specify the command to run"))?;
    let args = args_os().skip(2).collect::<Vec<OsString>>();
    let mut child = Command::new(arg0.clone());
    child.args(args.clone());
    unsafe {
        let socket = socket.as_raw_fd();
        child.pre_exec(move || {
            drop_capabilities().map_err(Error::map)?;
            set_no_new_privileges(true).map_err(Error::to_io_error)?;
            let notify_fd = install_seccomp_notify_filter()?;
            // allow the first `sendmsg` call
            let tmp_thread = std::thread::spawn(move || {
                let request = ScmpNotifReq::receive(notify_fd).unwrap();
                notify_id_valid(notify_fd, request.id).unwrap();
                let response = ScmpNotifResp::new_continue(request.id, ScmpNotifRespFlags::empty());
                response.respond(notify_fd).unwrap();
            });
            // this is the first `sendmsg` call that we allow via the temporary thread above
            socket.send_fd(notify_fd)?;
            tmp_thread.join().unwrap();
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

fn spawn_tracer_process(socket: SocketpairStream) -> Result<Child, Box<dyn std::error::Error>> {
    let arg0 = "./target/debug/cijail-tracer";
    let mut child = Command::new(arg0);
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
        .map_err(move |e| format!("failed to run `{}`: {}", arg0, e))?;
    Ok(child)
}

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let (socket0, socket1) = socketpair_stream()?;
    let mut target = spawn_target_process(socket0)?;
    let mut tracer = spawn_tracer_process(socket1)?;
    let status = target.wait()?;
    eprintln!("target finished {:?}", status);
    Command::new("kill")
        .args([tracer.id().to_string()])
        .status()
        .unwrap();
    tracer.wait()?;
    Ok(ExitCode::SUCCESS)
}

fn check(ret: c_int) -> Result<c_int, std::io::Error> {
    if ret == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}
