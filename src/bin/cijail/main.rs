use std::env::args_os;
use std::ffi::c_int;
use std::ffi::OsString;
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Child;
use std::process::Command;
use std::process::ExitCode;

use libseccomp::error::SeccompError;
use libseccomp::ScmpFd;
use passfd::FdPassingExt;
use prctl::set_no_new_privileges;
use socketpair::socketpair_stream;
use socketpair::SocketpairStream;

fn install_seccomp_notify_filter() -> Result<ScmpFd, SeccompError> {
    use libseccomp::*;
    let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
    filter.add_arch(ScmpArch::native())?;
    let names = [
        "connect",
        "sendto",
        "sendmmsg",
    ];
    for name in names {
        filter.add_rule(ScmpAction::Notify, ScmpSyscall::from_name(name)?)?;
    }
    filter.load()?;
    let notify_fd = filter.get_notify_fd()?;
    Ok(notify_fd)
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
            set_no_new_privileges(true).map_err(to_io_error)?;
            let notify_fd = install_seccomp_notify_filter()
                .map_err(|e| std::io::Error::new(ErrorKind::Other, e.to_string()))?;
            socket.send_fd(notify_fd)?;
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

fn to_io_error(ret: i32) -> std::io::Error {
    std::io::Error::from_raw_os_error(ret)
}

fn check(ret: c_int) -> Result<(), std::io::Error> {
    if ret == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
