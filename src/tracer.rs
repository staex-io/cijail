use std::fmt::Write;
use std::io::ErrorKind;
use std::io::IoSliceMut;
use std::mem::size_of;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::process::ExitCode;
use std::slice::from_raw_parts;
use std::str::from_utf8;

use caps::CapSet;
use caps::Capability;
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
use crate::DnsName;
use crate::DnsNameError;
use crate::DnsPacket;
use crate::EndpointSet;

pub(crate) fn main(notify_fd: RawFd) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if caps::has_cap(None, CapSet::Effective, Capability::CAP_SYS_PTRACE)? {
        error!("tracer process does not have CAP_SYS_PTRACE capability");
        return Ok(ExitCode::FAILURE);
    }
    let allowed_endpoints: EndpointSet = match std::env::var("CIJAIL_ALLOWED_ENDPOINTS") {
        Ok(string) => EndpointSet::parse_no_dns_name_resolution(string.as_str())?,
        Err(_) => Default::default(),
    };
    let mut dns_names: Vec<DnsName> = Vec::new();
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
                read_dns_packet(
                    request.pid as i32,
                    request.data.args[1] as usize,
                    request.data.args[2] as usize,
                    &mut dns_names,
                )?;
                sockaddr.into_iter().collect()
            }
            "sendmsg" => {
                let sockaddr = read_msghdr(
                    request.pid as i32,
                    request.data.args[1] as usize,
                    &mut dns_names,
                )?;
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
            || allowed_endpoints.contains_any_socket_address(socket_addresses.as_slice()))
            && (dns_names.is_empty()
                || allowed_endpoints.contains_any_dns_name(dns_names.as_slice()))
        {
            ScmpNotifResp::new_continue(request.id, ScmpNotifRespFlags::empty())
        } else {
            let error = -libc::ENETUNREACH;
            ScmpNotifResp::new_error(request.id, error, ScmpNotifRespFlags::empty())
        };
        if !socket_addresses.is_empty() || !dns_names.is_empty() {
            let mut buf = String::with_capacity(4096);
            write!(
                &mut buf,
                "{}",
                if response.error == 0 { "allow" } else { "deny" }
            )?;
            write!(&mut buf, " {}", syscall)?;
            for addr in socket_addresses.iter() {
                write!(&mut buf, " {}", addr)?;
            }
            for name in dns_names.iter() {
                write!(&mut buf, " {}", name)?;
            }
            info!("{}", buf);
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

fn read_msghdr(
    pid: i32,
    base: usize,
    dns_names: &mut Vec<DnsName>,
) -> Result<Option<SocketAddr>, std::io::Error> {
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
    let socketaddr = read_socket_addr(pid, message.msg_name as usize, message.msg_namelen)?;
    if let Ok((iovecs, _storage)) =
        read_array::<socket::iovec>(pid, message.msg_iov as usize, message.msg_iovlen)
    {
        for iovec in iovecs {
            read_dns_packet(pid, iovec.iov_base as usize, iovec.iov_len, dns_names)?;
        }
    }
    Ok(socketaddr)
}

fn read_mmsghdr(
    pid: i32,
    base: usize,
    len: usize,
    dns_names: &mut Vec<DnsName>,
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
            for iovec in iovecs {
                read_dns_packet(pid, iovec.iov_base as usize, iovec.iov_len, dns_names)?;
            }
        }
    }
    Ok(sockaddrs)
}

fn read_dns_packet(
    pid: i32,
    base: usize,
    len: usize,
    dns_names: &mut Vec<DnsName>,
) -> Result<(), std::io::Error> {
    let bytes = read_bytes(pid, base, len)?;
    if let Ok((packet, _)) = DnsPacket::read(bytes.as_slice()) {
        for question in packet.questions {
            match from_utf8(question.name.as_slice()) {
                Ok(name) => {
                    dns_names.push(name.parse().map_err(|e: DnsNameError| {
                        std::io::Error::new(ErrorKind::Other, e.to_string())
                    })?);
                }
                Err(e) => {
                    error!("failed to read dns name: {}", e);
                }
            }
        }
    }
    Ok(())
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
