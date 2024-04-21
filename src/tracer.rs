use std::fmt::Write;
use std::io::IoSliceMut;
use std::mem::size_of;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::process::ExitCode;
use std::slice::from_raw_parts;
use std::str::from_utf8;

use libc::sockaddr;
use libseccomp::notify_id_valid;
use libseccomp::ScmpNotifReq;
use libseccomp::ScmpNotifResp;
use libseccomp::ScmpNotifRespFlags;
use log::error;
use log::info;
use nix::sys::uio::process_vm_readv;
use nix::sys::uio::RemoteIoVec;
use nix::unistd::Pid;
use os_socketaddr::OsSocketAddr;

use crate::socket;
use crate::AllowedDnsNames;
use crate::AllowedEndpoints;
use crate::DnsPacket;

pub(crate) fn main(notify_fd: RawFd) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let allowed_endpoints: AllowedEndpoints = match std::env::var("CIJAIL_ALLOWED_ENDPOINTS") {
        Ok(string) => string.as_str().into(),
        Err(_) => Default::default(),
    };
    let allowed_dns_names: AllowedDnsNames = match std::env::var("CIJAIL_ALLOWED_DNS_NAMES") {
        Ok(string) => string.as_str().try_into()?,
        Err(_) => Default::default(),
    };
    let mut dns_names: Vec<String> = Vec::new();
    loop {
        dns_names.clear();
        let request = ScmpNotifReq::receive(notify_fd)?;
        notify_id_valid(notify_fd, request.id)?;
        let syscall = request.data.syscall.get_name()?;
        let socket_addresses = match syscall.as_str() {
            "connect" => {
                let sockaddr = read_socket_addr(
                    request.pid as i32,
                    request.data.args[1] as usize,
                    request.data.args[2] as u32,
                )?;
                sockaddr.into_iter().collect()
            }
            "sendto" => {
                let sockaddr = read_socket_addr(
                    request.pid as i32,
                    request.data.args[4] as usize,
                    request.data.args[5] as u32,
                )?;
                sockaddr.into_iter().collect()
            }
            "sendmsg" => {
                let sockaddr = read_msghdr(request.pid as i32, request.data.args[1] as usize)?;
                sockaddr.into_iter().collect()
            }
            "sendmmsg" => read_mmsghdr(
                request.pid as i32,
                request.data.args[1] as usize,
                request.data.args[2] as usize,
                &mut dns_names,
            )?,
            _ => Vec::new(),
        };
        let response = if (socket_addresses.is_empty()
            || allowed_endpoints.contain_any(socket_addresses.as_slice()))
            && (dns_names.is_empty() || allowed_dns_names.contain_any(dns_names.as_slice()))
        {
            ScmpNotifResp::new_continue(request.id, ScmpNotifRespFlags::empty())
        } else {
            let error = -libc::ENETUNREACH;
            ScmpNotifResp::new_error(request.id, error, ScmpNotifRespFlags::empty())
        };
        if !socket_addresses.is_empty() || !dns_names.is_empty() {
            info!(
                "{} {}{} {}",
                if response.error == 0 { "allow" } else { "deny" },
                syscall,
                socket_addresses
                    .iter()
                    .fold(String::with_capacity(4096), |mut acc, x| {
                        let _ = write!(&mut acc, " {}", x);
                        acc
                    }),
                dns_names.join(" "),
            );
        }
        response.respond(notify_fd)?;
    }
}

fn read_socket_addr(pid: i32, base: usize, len: u32) -> Result<Option<SocketAddr>, std::io::Error> {
    if base == 0 {
        return Ok(None);
    }
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
    let sockaddr =
        unsafe { OsSocketAddr::copy_from_raw(buf.as_mut_slice().as_ptr() as *const sockaddr, len) }
            .into_addr();
    Ok(sockaddr)
}

fn read_msghdr(pid: i32, base: usize) -> Result<Option<SocketAddr>, std::io::Error> {
    if base == 0 {
        return Ok(None);
    }
    let len = size_of::<socket::msghdr>();
    let mut buf = vec![0_u8; len];
    process_vm_readv(
        Pid::from_raw(pid),
        &mut [IoSliceMut::new(buf.as_mut_slice())],
        &[RemoteIoVec { base, len }],
    )?;
    let message = buf.as_mut_slice().as_ptr() as *const socket::msghdr;
    let message = unsafe { from_raw_parts::<socket::msghdr>(message, 1) }[0];
    read_socket_addr(pid, message.msg_name as usize, message.msg_namelen)
}

fn read_mmsghdr(
    pid: i32,
    base: usize,
    len: usize,
    dns_names: &mut Vec<String>,
) -> Result<Vec<SocketAddr>, std::io::Error> {
    let (messages, _storage) = read_array::<socket::mmsghdr>(pid, base, len)?;
    let mut sockaddrs: Vec<SocketAddr> = Vec::with_capacity(messages.len());
    for message in messages {
        let base = message.msg_hdr.msg_name as usize;
        if let Ok(Some(addr)) = read_socket_addr(pid, base, message.msg_hdr.msg_namelen) {
            sockaddrs.push(addr);
        }
        if let Ok((iovecs, _storage)) = read_array::<socket::iovec>(
            pid,
            message.msg_hdr.msg_iov as usize,
            message.msg_hdr.msg_iovlen,
        ) {
            info!("iovecs {}", iovecs.len());
            for iovec in iovecs {
                let bytes = read_bytes(pid, iovec.iov_base as usize, iovec.iov_len)?;
                info!("bytes {}", bytes.len());
                match DnsPacket::read(bytes.as_slice()) {
                    Ok((packet, _)) => {
                        for question in packet.questions {
                            match from_utf8(question.name.as_slice()) {
                                Ok(name) => {
                                    info!("dns name `{}`", name);
                                    dns_names.push(name.to_string());
                                }
                                Err(e) => {
                                    error!("failed to read dns name: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("failed to read dns packet: {}", e);
                    }
                }
            }
        }
    }
    Ok(sockaddrs)
}

fn read_array<'a, T>(
    pid: i32,
    base: usize,
    len: usize,
) -> Result<(&'a [T], Vec<u8>), std::io::Error> {
    if base == 0 || len == 0 {
        return Ok((&[], Vec::new()));
    }
    let len_in_bytes = len * size_of::<socket::mmsghdr>();
    let mut buf = vec![0_u8; len_in_bytes];
    process_vm_readv(
        Pid::from_raw(pid),
        &mut [IoSliceMut::new(buf.as_mut_slice())],
        &[RemoteIoVec {
            base,
            len: len_in_bytes,
        }],
    )?;
    let messages = buf.as_mut_slice().as_ptr() as *const T;
    let messages = unsafe { from_raw_parts::<T>(messages, len) };
    Ok((messages, buf))
}

fn read_bytes(pid: i32, base: usize, len: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut buf = vec![0_u8; len];
    process_vm_readv(
        Pid::from_raw(pid),
        &mut [IoSliceMut::new(buf.as_mut_slice())],
        &[RemoteIoVec { base, len }],
    )?;
    Ok(buf)
}
