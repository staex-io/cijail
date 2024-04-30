use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fmt::Write;
use std::fs::File;
use std::io::ErrorKind;
use std::io::IoSliceMut;
use std::mem::size_of;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::os::unix::process::parent_id;
use std::path::PathBuf;
use std::process::ExitCode;
use std::slice::from_raw_parts;
use std::str::from_utf8;

use cijail::DnsName;
use cijail::DnsPacket;
use cijail::Error;
use libc::sockaddr;
use libc::AT_FDCWD;
use libseccomp::notify_id_valid;
use libseccomp::ScmpNotifReq;
use libseccomp::ScmpNotifResp;
use libseccomp::ScmpNotifRespFlags;
use log::info;
use nix::errno::Errno;
use nix::fcntl::readlink;
use nix::sys::stat::stat;
use nix::sys::stat::FileStat;
use nix::sys::uio::process_vm_readv;
use nix::sys::uio::RemoteIoVec;
use nix::unistd::Pid;
use os_socketaddr::OsSocketAddr;

use crate::socket;
use crate::EndpointSet;
use crate::CIJAIL_ENDPOINTS;

pub(crate) fn main(
    notify_fd: RawFd,
    is_dry_run: bool,
    allow_loopback: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let allowed_endpoints: EndpointSet = match std::env::var(CIJAIL_ENDPOINTS) {
        Ok(string) => EndpointSet::from_base64(string.as_str())?,
        Err(_) => Default::default(),
    };
    let immutable_context = ImmutableContext::new()?;
    let mut mutable_context = MutableContext::new();
    loop {
        mutable_context.clear();
        let request = ScmpNotifReq::receive(notify_fd)?;
        let mut context = Context {
            notify_fd,
            request,
            mutable: &mut mutable_context,
            immutable: &immutable_context,
        };
        context.validate()?;
        let syscall = context.handle_syscall()?;
        if allow_loopback {
            context
                .mutable
                .sockaddrs
                .retain(|sockaddr| !sockaddr.ip().is_loopback());
        }
        let response = if context.mutable.is_continue(&allowed_endpoints) {
            ScmpNotifResp::new_continue(context.request.id, ScmpNotifRespFlags::empty())
        } else {
            let error = if !context.mutable.denied_paths.is_empty() {
                libc::ENOMEDIUM
            } else {
                libc::ENETUNREACH
            };
            ScmpNotifResp::new_error(context.request.id, -error, ScmpNotifRespFlags::empty())
        };
        if !mutable_context.is_empty() {
            let mut buf = String::with_capacity(4096);
            if is_dry_run {
                write!(&mut buf, "DRYRUN ")?;
            }
            write!(
                &mut buf,
                "{}",
                if response.error == 0 { "allow" } else { "deny" }
            )?;
            write!(&mut buf, " {}", syscall)?;
            for addr in mutable_context.sockaddrs.iter() {
                match allowed_endpoints.resolve_socketaddr(addr) {
                    Some(dns_name) => write!(&mut buf, " {}:{}", dns_name, addr.port())?,
                    None => write!(&mut buf, " {}", addr)?,
                }
            }
            for name in mutable_context.dns_names.iter() {
                write!(&mut buf, " {}", name)?;
            }
            for path in mutable_context.denied_paths.iter() {
                write!(&mut buf, " {}", path.display())?;
            }
            info!("{}", buf);
        }
        if is_dry_run {
            ScmpNotifResp::new_continue(request.id, ScmpNotifRespFlags::empty())
                .respond(notify_fd)?;
        } else {
            response.respond(notify_fd)?;
        }
    }
}

#[derive(PartialEq, Eq, Hash)]
struct ProhibitedFile {
    device: u64,
    inode: u64,
}

impl ProhibitedFile {
    fn new(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self::from_stat(stat(path)?))
    }

    fn from_stat(st: FileStat) -> Self {
        Self {
            device: st.st_dev,
            inode: st.st_ino,
        }
    }
}

struct Context<'a> {
    notify_fd: RawFd,
    request: ScmpNotifReq,
    mutable: &'a mut MutableContext,
    immutable: &'a ImmutableContext,
}

impl Context<'_> {
    fn validate(&self) -> Result<(), std::io::Error> {
        notify_id_valid(self.notify_fd, self.request.id)
            .map_err(|e| std::io::Error::new(ErrorKind::Other, e.to_string()))
    }

    fn handle_syscall(&mut self) -> Result<String, std::io::Error> {
        let syscall = self
            .request
            .data
            .syscall
            .get_name()
            .map_err(|e| std::io::Error::new(ErrorKind::Other, e.to_string()))?;
        match syscall.as_str() {
            "connect" => {
                self.read_socket_addr(
                    self.request.data.args[1] as usize,
                    self.request.data.args[2] as u32,
                )?;
            }
            "sendto" => {
                self.read_socket_addr(
                    self.request.data.args[4] as usize,
                    self.request.data.args[5] as u32,
                )?;
                self.read_dns_packet(
                    self.request.data.args[1] as usize,
                    self.request.data.args[2] as usize,
                )?;
            }
            "sendmsg" => {
                self.read_msghdr(self.request.data.args[1] as usize)?;
            }
            "sendmmsg" => self.read_mmsghdr(
                self.request.data.args[1] as usize,
                self.request.data.args[2] as usize,
            )?,
            "write" | "send" => {
                let fd = self.request.data.args[0] as RawFd;
                let filename = format!("/proc/{}/fd/{}", self.request.pid, fd);
                self.check_path(filename.as_bytes())?;
                if self.is_socket(fd)? {
                    self.read_dns_packet(
                        self.request.data.args[1] as usize,
                        self.request.data.args[2] as usize,
                    )?;
                }
            }
            "open" => {
                let path = self.read_path(self.request.data.args[0] as usize)?;
                self.check_path(path.as_slice())?;
            }
            "openat" => {
                let path = self.read_path(self.request.data.args[1] as usize)?;
                let dirfd = self.request.data.args[0] as i32;
                if path.first() == Some(&b'/') {
                    self.check_path(path.as_slice())?;
                } else if dirfd == AT_FDCWD {
                    let mut new_path =
                        readlink(format!("/proc/{}/cwd", self.request.pid).as_str())?
                            .into_encoded_bytes();
                    new_path.push(b'/');
                    new_path.extend(path);
                    self.check_path(new_path.as_slice())?;
                } else {
                    let mut new_path = format!("/proc/{}/{}", self.request.pid, dirfd).into_bytes();
                    new_path.push(b'/');
                    new_path.extend(path);
                    self.check_path(new_path.as_slice())?;
                }
            }
            _ => {}
        }
        Ok(syscall)
    }

    fn read_bytes(&mut self, base: usize, len: usize) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = vec![0_u8; len];
        self.read_memory(base, len, &mut buf)?;
        Ok(buf)
    }

    fn read_array<'a, T>(
        &mut self,
        base: usize,
        len: usize,
    ) -> Result<(&'a [T], Vec<u8>), std::io::Error> {
        if base == 0 || len == 0 {
            return Ok((&[], Vec::new()));
        }
        let len_in_bytes = len * size_of::<socket::mmsghdr>();
        let mut buf = vec![0_u8; len_in_bytes];
        self.read_memory(base, len_in_bytes, &mut buf)?;
        let messages = buf.as_mut_slice().as_ptr() as *const T;
        let messages = unsafe { from_raw_parts::<T>(messages, len) };
        Ok((messages, buf))
    }

    fn read_dns_packet(&mut self, base: usize, len: usize) -> Result<(), std::io::Error> {
        let bytes = self.read_bytes(base, len)?;
        let bytes = &bytes[..bytes.len().min(MAX_DNS_PACKET_SIZE)];
        if let Ok((packet, _)) = DnsPacket::read_questions_only(bytes) {
            for question in packet.questions {
                if let Ok(name) = from_utf8(question.name.as_slice()) {
                    if let Ok(dns_name) = DnsName::parse_no_punycode(name) {
                        self.mutable.dns_names.push(dns_name);
                    }
                }
            }
        }
        Ok(())
    }

    fn read_socket_addr(&mut self, base: usize, len: u32) -> Result<(), std::io::Error> {
        if base == 0 {
            return Ok(());
        }
        let mut buf = vec![0_u8; len as usize];
        self.read_memory(base, len as usize, &mut buf)?;
        self.validate()?;
        let sockaddr = unsafe {
            OsSocketAddr::copy_from_raw(buf.as_mut_slice().as_ptr() as *const sockaddr, len)
        }
        .into_addr();
        self.mutable.sockaddrs.extend(sockaddr);
        Ok(())
    }

    fn read_msghdr(&mut self, base: usize) -> Result<(), std::io::Error> {
        if base == 0 {
            return Ok(());
        }
        let len = size_of::<socket::msghdr>();
        let mut buf = vec![0_u8; len];
        self.read_memory(base, len, &mut buf)?;
        let message = buf.as_mut_slice().as_ptr() as *const socket::msghdr;
        let message = unsafe { from_raw_parts::<socket::msghdr>(message, 1) }[0];
        self.read_socket_addr(message.msg_name as usize, message.msg_namelen)?;
        if let Ok((iovecs, _storage)) =
            self.read_array::<socket::iovec>(message.msg_iov as usize, message.msg_iovlen)
        {
            for iovec in iovecs {
                self.read_dns_packet(iovec.iov_base as usize, iovec.iov_len)?;
            }
        }
        Ok(())
    }

    fn read_mmsghdr(&mut self, base: usize, len: usize) -> Result<(), std::io::Error> {
        let (messages, _storage) = self.read_array::<socket::mmsghdr>(base, len)?;
        for message in messages {
            let base = message.msg_hdr.msg_name as usize;
            self.read_socket_addr(base, message.msg_hdr.msg_namelen)?;
            if let Ok((iovecs, _storage)) = self.read_array::<socket::iovec>(
                message.msg_hdr.msg_iov as usize,
                message.msg_hdr.msg_iovlen,
            ) {
                for iovec in iovecs {
                    self.read_dns_packet(iovec.iov_base as usize, iovec.iov_len)?;
                }
            }
        }
        Ok(())
    }

    fn read_path(&mut self, base: usize) -> Result<Vec<u8>, std::io::Error> {
        let mut path = self.read_bytes(base, libc::PATH_MAX as usize)?;
        path.truncate(
            path.iter()
                .position(|x| *x == 0_u8)
                .ok_or_else(|| Error::map("invalid path"))?,
        );
        Ok(path)
    }

    fn check_path(&mut self, path: &[u8]) -> Result<(), std::io::Error> {
        let file_status = stat(path);
        self.validate()?;
        match file_status {
            Err(Errno::ENOENT) | Err(Errno::ENOTDIR) => Ok(()),
            Err(e) => Err(e.into()),
            Ok(stat) => {
                let file = ProhibitedFile::from_stat(stat);
                if self.immutable.prohibited_files.contains(&file) {
                    self.mutable
                        .denied_paths
                        .push(OsStr::from_bytes(path).into());
                }
                Ok(())
            }
        }
    }

    fn is_socket(&self, fd: RawFd) -> Result<bool, std::io::Error> {
        let path = format!("/proc/{}/fd/{}", self.request.pid, fd);
        match readlink(path.as_str()) {
            Err(Errno::ENOENT) | Err(Errno::ENOTDIR) => Ok(false),
            Err(e) => Err(e.into()),
            Ok(target) => Ok(target.into_encoded_bytes().starts_with(SOCKET_PREFIX)),
        }
    }

    fn read_memory(
        &mut self,
        base: usize,
        len: usize,
        buf: &mut [u8],
    ) -> Result<(), std::io::Error> {
        let pid = Pid::from_raw(self.request.pid as i32);
        match process_vm_readv(
            pid,
            &mut [IoSliceMut::new(buf)],
            &[RemoteIoVec { base, len }],
        ) {
            Ok(_) => {}
            Err(nix::errno::Errno::EPERM) => {
                let file = self.mutable.get_memory_file(pid)?;
                file.read_at(&mut buf[..len], base as u64)?;
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    ErrorKind::Other,
                    format!("failed to read tracee process memory: {}", e),
                ));
            }
        }
        self.validate()
    }
}

struct MutableContext {
    dns_names: Vec<DnsName>,
    denied_paths: Vec<PathBuf>,
    sockaddrs: Vec<SocketAddr>,
    memory_files: HashMap<Pid, File>,
}

impl MutableContext {
    fn new() -> Self {
        Self {
            dns_names: Default::default(),
            denied_paths: Default::default(),
            sockaddrs: Default::default(),
            memory_files: Default::default(),
        }
    }

    fn clear(&mut self) {
        self.dns_names.clear();
        self.denied_paths.clear();
        self.sockaddrs.clear();
    }

    fn is_continue(&mut self, allowed_endpoints: &EndpointSet) -> bool {
        (self.sockaddrs.is_empty()
            || allowed_endpoints.contains_any_socket_address(self.sockaddrs.as_slice()))
            && (self.dns_names.is_empty()
                || allowed_endpoints.contains_any_dns_name(self.dns_names.as_slice()))
            && self.denied_paths.is_empty()
    }

    fn is_empty(&self) -> bool {
        self.sockaddrs.is_empty() && self.dns_names.is_empty() && self.denied_paths.is_empty()
    }

    fn get_memory_file(&mut self, pid: Pid) -> Result<&mut File, std::io::Error> {
        match self.memory_files.entry(pid) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => {
                let path = format!("/proc/{}/mem", pid);
                let file = File::open(path)?;
                Ok(entry.insert(file))
            }
        }
    }
}

struct ImmutableContext {
    prohibited_files: HashSet<ProhibitedFile>,
}

impl ImmutableContext {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut prohibited_files: HashSet<ProhibitedFile> = HashSet::with_capacity(3);
        prohibited_files.insert(ProhibitedFile::new(
            format!("/proc/{}/mem", std::process::id()).as_str(),
        )?);
        prohibited_files.insert(ProhibitedFile::new(
            format!("/proc/{}/mem", parent_id()).as_str(),
        )?);
        if let Ok(file) = ProhibitedFile::new("/dev/mem") {
            prohibited_files.insert(file);
        }
        Ok(Self { prohibited_files })
    }
}

/// A value that is large enough to hold any DNS/EDNS packet.
const MAX_DNS_PACKET_SIZE: usize = 4096;
const SOCKET_PREFIX: &[u8] = b"socket:";
