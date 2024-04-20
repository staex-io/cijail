use std::collections::HashSet;
use std::net::AddrParseError;
use std::net::SocketAddr;
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
    type Err = AddrParseError;
    fn from_str(other: &str) -> Result<Self, Self::Err> {
        let mut allowed_endpoints = AllowedEndpoints::new();
        for word in other.trim().split_whitespace() {
            let socketaddr = match word.parse() {
                Ok(addr) => addr,
                Err(e) => {
                    error!("failed to parse `{}` as socket address: {}", word, e);
                    continue;
                }
            };
            allowed_endpoints.socketaddrs.insert(socketaddr);
        }
        Ok(allowed_endpoints)
    }
}
