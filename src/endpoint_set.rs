use std::collections::HashSet;
use std::fmt::Display;
use std::fmt::Formatter;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::str::FromStr;

use crate::DnsName;
use crate::Error;

#[derive(Default)]
pub(crate) struct EndpointSet {
    socketaddrs: HashSet<SocketAddr>,
    dns_names: HashSet<DnsName>,
}

impl EndpointSet {
    pub(crate) fn contains_any_socket_address(&self, addrs: &[SocketAddr]) -> bool {
        for addr in addrs.iter() {
            if self.socketaddrs.contains(addr) {
                return true;
            }
        }
        false
    }

    pub(crate) fn contains_any_dns_name(&self, names: &[DnsName]) -> bool {
        for name in names.iter() {
            if self.dns_names.contains(name) {
                return true;
            }
        }
        false
    }

    pub(crate) fn parse_no_dns_name_resolution(other: &str) -> Result<Self, Error> {
        Self::parse(
            other,
            ParseOptions {
                resolve_dns_names: false,
            },
        )
    }

    pub(crate) fn parse_with_dns_name_resolution(other: &str) -> Result<Self, Error> {
        Self::parse(
            other,
            ParseOptions {
                resolve_dns_names: true,
            },
        )
    }

    fn parse(other: &str, options: ParseOptions) -> Result<Self, Error> {
        let mut socketaddrs: HashSet<SocketAddr> = HashSet::new();
        let mut dns_names: HashSet<DnsName> = HashSet::new();
        for word in other.split_whitespace() {
            // with DNS name resolution
            let endpoint: Endpoint = word.parse().map_err(|e| {
                Error::map(format!("failed to parse `{}` as endpoint: {}", word, e))
            })?;
            match endpoint.address {
                Address::Ip(addr) => {
                    socketaddrs.insert(SocketAddr::new(addr, endpoint.port));
                }
                Address::DnsName(name) => {
                    if options.resolve_dns_names {
                        let addrs = (name.to_string(), endpoint.port)
                            .to_socket_addrs()
                            .map_err(|e| {
                                Error::map(format!(
                                    "failed to parse `{}` as socket address: {}",
                                    word, e
                                ))
                            })?;
                        socketaddrs.extend(addrs.into_iter());
                    }
                    dns_names.insert(name);
                }
            }
        }
        Ok(Self {
            socketaddrs,
            dns_names,
        })
    }
}

impl Display for EndpointSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        print_space_separated(f, self.socketaddrs.iter())?;
        print_space_separated(f, self.dns_names.iter())?;
        Ok(())
    }
}

struct ParseOptions {
    resolve_dns_names: bool,
}

enum Address {
    Ip(IpAddr),
    DnsName(DnsName),
}

impl FromStr for Address {
    type Err = Error;
    fn from_str(other: &str) -> Result<Self, Self::Err> {
        match other.parse::<IpAddr>() {
            Ok(addr) => Ok(Self::Ip(addr)),
            Err(_) => Ok(Self::DnsName(other.parse::<DnsName>()?)),
        }
    }
}

struct Endpoint {
    address: Address,
    port: u16,
}

impl FromStr for Endpoint {
    type Err = Error;
    fn from_str(other: &str) -> Result<Self, Self::Err> {
        let colon_index = other.rfind(':').ok_or_else(|| Error::map("no port"))?;
        Ok(Endpoint {
            address: other[..colon_index].parse()?,
            port: other[(colon_index + 1)..].parse().map_err(Error::map)?,
        })
    }
}

fn print_space_separated<T: Display>(
    f: &mut Formatter<'_>,
    mut iter: impl Iterator<Item = T>,
) -> std::fmt::Result {
    if let Some(x) = iter.next() {
        write!(f, "{}", x)?;
    }
    for x in iter {
        write!(f, " {}", x)?;
    }
    Ok(())
}
