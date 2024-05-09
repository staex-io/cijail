use std::ffi::OsStr;
use std::fmt::Debug;
use std::fmt::Display;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::str::FromStr;

use bincode::Decode;
use bincode::Encode;
use nix::sys::socket::sockaddr;
use nix::sys::socket::NetlinkAddr;
use nix::sys::socket::SockaddrIn;
use nix::sys::socket::SockaddrIn6;
use nix::sys::socket::SockaddrLike;
use nix::sys::socket::UnixAddr;

use crate::Error;

#[derive(PartialEq, Eq, Hash, Clone, Encode, Decode)]
pub enum AnySocketAddr {
    Ip(SocketAddr),
    Unix(Vec<u8>),
    Netlink,
}

impl AnySocketAddr {
    pub fn new(addr: &[u8], len: u32) -> Result<Self, Error> {
        let addr = addr.as_ptr() as *const sockaddr;
        if let Some(addr) = unsafe { SockaddrIn::from_raw(addr, Some(len)) } {
            return Ok(Self::Ip(SocketAddr::new(
                IpAddr::V4(addr.ip()),
                addr.port(),
            )));
        }
        if let Some(addr) = unsafe { SockaddrIn6::from_raw(addr, Some(len)) } {
            return Ok(Self::Ip(SocketAddr::new(
                IpAddr::V6(addr.ip()),
                addr.port(),
            )));
        }
        if let Some(addr) = unsafe { UnixAddr::from_raw(addr, Some(len)) } {
            return Ok(Self::Unix(unix_addr_to_vec(addr)));
        }
        if let Some(_addr) = unsafe { NetlinkAddr::from_raw(addr, Some(len)) } {
            return Ok(Self::Netlink);
        }
        Err(Error::map(format!(
            "unknown socket address family: {}",
            unsafe { (*addr).sa_family }
        )))
    }
}

impl Display for AnySocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{}", addr),
            Self::Unix(unix) => write!(f, "{}", Path::new(OsStr::from_bytes(unix)).display()),
            Self::Netlink => write!(f, "[netlink]"),
        }
    }
}

impl Debug for AnySocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl FromStr for AnySocketAddr {
    type Err = Error;
    fn from_str(other: &str) -> Result<Self, Self::Err> {
        match other.as_bytes().first() {
            Some(&b'@') => Ok(Self::Unix(unix_addr_to_vec(
                UnixAddr::new_abstract(other[1..].as_bytes())
                    .map_err(|_| Error::map(format!("invalid unix socket address: {}", other)))?,
            ))),
            Some(&b'/') => Ok(Self::Unix(unix_addr_to_vec(
                UnixAddr::new(other.as_bytes())
                    .map_err(|_| Error::map(format!("invalid unix socket address: {}", other)))?,
            ))),
            _ => {
                if other == "[netlink]" {
                    Ok(Self::Netlink)
                } else {
                    Ok(Self::Ip(other.parse().map_err(Error::map)?))
                }
            }
        }
    }
}

impl From<SocketAddr> for AnySocketAddr {
    fn from(other: SocketAddr) -> Self {
        Self::Ip(other)
    }
}

fn unix_addr_to_vec(unix: UnixAddr) -> Vec<u8> {
    match (unix.path(), unix.as_abstract()) {
        (Some(path), _) => {
            let mut vec = path.as_os_str().as_bytes().to_vec();
            if let Some(n) = vec.iter().position(|x| x == &0_u8) {
                vec.truncate(n);
            }
            vec
        }
        (_, Some(bytes)) => {
            let mut vec: Vec<u8> = Vec::new();
            vec.push(b'@');
            vec.extend(match bytes.iter().position(|x| x == &0_u8) {
                Some(n) => &bytes[..n],
                None => bytes,
            });
            vec
        }
        _ => b"[unnamed]".to_vec(),
    }
}

#[cfg(test)]
mod tests {

    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn print() {
        assert_eq!(
            AnySocketAddr::Unix(unix_addr_to_vec(
                UnixAddr::new_abstract(b"/tmp/unix".as_slice()).unwrap()
            )),
            "@/tmp/unix".parse::<AnySocketAddr>().unwrap()
        );
        assert_eq!(
            AnySocketAddr::Unix(unix_addr_to_vec(
                UnixAddr::new(b"/tmp/unix".as_slice()).unwrap()
            )),
            "/tmp/unix".parse::<AnySocketAddr>().unwrap()
        );
        assert_eq!(
            AnySocketAddr::Netlink,
            "[netlink]".parse::<AnySocketAddr>().unwrap()
        );
        assert_eq!(
            AnySocketAddr::Ip("127.0.0.1:9999".parse().unwrap()),
            "127.0.0.1:9999".parse::<AnySocketAddr>().unwrap()
        );
    }
}
