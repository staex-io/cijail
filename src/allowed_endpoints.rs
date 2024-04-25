use std::collections::HashSet;
use std::fmt::Display;
use std::fmt::Formatter;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::str::FromStr;

use log::error;

pub(crate) struct AllowedEndpoints {
    socketaddrs: HashSet<SocketAddr>,
}

impl AllowedEndpoints {
    pub(crate) fn new() -> Self {
        Self {
            socketaddrs: Default::default(),
        }
    }

    pub(crate) fn contain(&self, addr: &SocketAddr) -> bool {
        self.socketaddrs.contains(addr)
    }

    pub(crate) fn contain_any(&self, addrs: &[SocketAddr]) -> bool {
        for addr in addrs {
            if self.contain(addr) {
                return true;
            }
        }
        false
    }
}

impl Default for AllowedEndpoints {
    fn default() -> Self {
        Self::new()
    }
}

impl FromStr for AllowedEndpoints {
    type Err = std::io::Error;
    fn from_str(other: &str) -> Result<Self, Self::Err> {
        let mut allowed_endpoints = AllowedEndpoints::new();
        for word in other.split_whitespace() {
            // with DNS name resolution
            match word.to_socket_addrs() {
                Ok(addrs) => allowed_endpoints.socketaddrs.extend(addrs.into_iter()),
                Err(e) => error!("failed to parse `{}` as socket address: {}", word, e),
            }
        }
        Ok(allowed_endpoints)
    }
}

impl From<&str> for AllowedEndpoints {
    fn from(other: &str) -> Self {
        let mut allowed_endpoints = AllowedEndpoints::new();
        for word in other.split_whitespace() {
            // no DNS name resolution
            match word.parse() {
                Ok(addr) => {
                    allowed_endpoints.socketaddrs.insert(addr);
                }
                Err(e) => error!("failed to parse `{}` as socket address: {}", word, e),
            }
        }
        allowed_endpoints
    }
}

impl Display for AllowedEndpoints {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(addr) = self.socketaddrs.iter().next() {
            write!(f, "{}", addr)?;
        }
        for addr in self.socketaddrs.iter().skip(1) {
            write!(f, " {}", addr)?;
        }
        Ok(())
    }
}
