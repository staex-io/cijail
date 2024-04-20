use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::process::ExitCode;

use libc::sockaddr;
use libseccomp::notify_id_valid;
use libseccomp::ScmpFd;
use libseccomp::ScmpNotifReq;
use libseccomp::ScmpNotifResp;
use libseccomp::ScmpNotifRespFlags;
use nix::sys::uio::process_vm_readv;
use nix::sys::uio::RemoteIoVec;
use nix::unistd::Pid;
use os_socketaddr::OsSocketAddr;

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let notify_fd: ScmpFd = 0;
    loop {
        let request = ScmpNotifReq::receive(notify_fd)?;
        notify_id_valid(notify_fd, request.id)?;
        let syscall = request.data.syscall.get_name()?;
        let response = match syscall.as_str() {
            "connect" => {
                let sockaddr = read_socket_addr(
                    request.pid as i32,
                    request.data.args[1] as usize,
                    request.data.args[2] as u32)?;
                match sockaddr {
                    Some(sockaddr) => {
                        eprintln!("connect {:?}", sockaddr);
                        ScmpNotifResp::new_continue(request.id, ScmpNotifRespFlags::empty())
                    }
                    None => {
                        ScmpNotifResp::new_continue(request.id, ScmpNotifRespFlags::empty())
                    }
                }
            }
            "sendto" => {
                let sockaddr = read_socket_addr(
                    request.pid as i32,
                    request.data.args[4] as usize,
                    request.data.args[5] as u32)?;
                match sockaddr {
                    Some(sockaddr) => {
                        eprintln!("sendto {:?}", sockaddr);
                        ScmpNotifResp::new_continue(request.id, ScmpNotifRespFlags::empty())
                    }
                    None => {
                        ScmpNotifResp::new_continue(request.id, ScmpNotifRespFlags::empty())
                    }
                }
            }
            "sendmmsg" => {
                let vlen = request.data.args[2];
                eprintln!("sendmmsg {}", vlen);
                ScmpNotifResp::new_continue(request.id, ScmpNotifRespFlags::empty())
            }
            _ => {
                eprintln!("{}", syscall);
                ScmpNotifResp::new_continue(request.id, ScmpNotifRespFlags::empty())
            }
        };
        response.respond(notify_fd)?;
    }
}

fn read_socket_addr(pid: i32, base: usize, len: u32) -> Result<Option<SocketAddr>, std::io::Error> {
    let mut buf = vec![0_u8; len as usize];
    let mut slice = vec![IoSliceMut::new(buf.as_mut_slice())];
    let remote_vec = vec![RemoteIoVec {
        base,
        len: len as usize,
    }];
    process_vm_readv(
        Pid::from_raw(pid),
        slice.as_mut_slice(),
        remote_vec.as_slice(),
    )?;
    let sockaddr = unsafe {
        OsSocketAddr::copy_from_raw(buf.as_mut_slice().as_ptr() as *const sockaddr, len)
    }
    .into_addr();
    Ok(sockaddr)
}
