use std::collections::HashSet;
use std::fmt::Display;
use std::fmt::Formatter;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::str::FromStr;

use crate::DnsName;
use crate::Error;

#[derive(Default)]
#[cfg_attr(test, derive(Clone, PartialEq, Debug))]
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
            let endpoint: Endpoint = word.parse().map_err(|e| {
                Error::map(format!("failed to parse `{}` as endpoint: {}", word, e))
            })?;
            match endpoint {
                Endpoint::SocketAddr(socketaddr) => {
                    socketaddrs.insert(socketaddr);
                }
                Endpoint::DnsNameAndPort { name, port } => {
                    if options.resolve_dns_names {
                        if let Some(port) = port {
                            let addrs =
                                (name.to_string(), port).to_socket_addrs().map_err(|e| {
                                    Error::map(format!(
                                        "failed to parse `{}` as socket address: {}",
                                        word, e
                                    ))
                                })?;
                            socketaddrs.extend(addrs.into_iter());
                        }
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
        if !self.socketaddrs.is_empty() {
            write!(f, " ")?;
        }
        print_space_separated(f, self.dns_names.iter())?;
        Ok(())
    }
}

struct ParseOptions {
    resolve_dns_names: bool,
}

enum Endpoint {
    SocketAddr(SocketAddr),
    DnsNameAndPort { name: DnsName, port: Option<u16> },
}

impl FromStr for Endpoint {
    type Err = Error;
    fn from_str(other: &str) -> Result<Self, Self::Err> {
        match other.parse::<SocketAddr>() {
            Ok(socketaddr) => Ok(Self::SocketAddr(socketaddr)),
            Err(_) => match other.rfind(':') {
                Some(colon_index) => Ok(Self::DnsNameAndPort {
                    name: other[..colon_index].parse()?,
                    port: Some(other[(colon_index + 1)..].parse().map_err(Error::map)?),
                }),
                None => Ok(Self::DnsNameAndPort {
                    name: other.parse()?,
                    port: None,
                }),
            },
        }
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use quickcheck::Arbitrary;

    use super::*;

    #[quickcheck_macros::quickcheck]
    fn count(endpoint_set: EndpointSet) {
        let string = endpoint_set.to_string();
        let words = string.split_whitespace().collect::<Vec<&str>>();
        assert_eq!(
            endpoint_set.socketaddrs.len() + endpoint_set.dns_names.len(),
            words.len(),
            "string = `{}`",
            string
        );
        let actual_set = EndpointSet::parse_no_dns_name_resolution(string.as_str()).unwrap();
        assert_eq!(endpoint_set, actual_set);
    }

    impl Arbitrary for EndpointSet {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            Self {
                socketaddrs: Arbitrary::arbitrary(g),
                dns_names: Arbitrary::arbitrary(g),
            }
        }
    }
}
