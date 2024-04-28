use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::Display;
use std::fmt::Formatter;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::str::FromStr;

use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine;
use bincode::decode_from_slice;
use bincode::encode_to_vec;
use bincode::Decode;
use bincode::Encode;

use crate::DnsName;
use crate::Error;

#[derive(Default, Encode, Decode)]
#[cfg_attr(test, derive(Clone, PartialEq, Debug))]
pub struct EndpointSet {
    socketaddrs: HashMap<SocketAddr, Option<DnsName>>,
    dns_names: HashSet<DnsName>,
}

impl EndpointSet {
    pub fn contains_any_socket_address(&self, addrs: &[SocketAddr]) -> bool {
        for addr in addrs.iter() {
            if self.socketaddrs.contains_key(addr) {
                return true;
            }
        }
        false
    }

    pub fn contains_any_dns_name(&self, names: &[DnsName]) -> bool {
        for name in names.iter() {
            if self.dns_names.contains(name) {
                return true;
            }
        }
        false
    }

    pub fn resolve_socketaddr(&self, socketaddr: &SocketAddr) -> Option<&DnsName> {
        match self.socketaddrs.get(socketaddr) {
            Some(option) => option.as_ref(),
            None => None,
        }
    }

    pub fn to_base64(&self) -> Result<String, Error> {
        let bytes = encode_to_vec(self, bincode::config::standard())?;
        Ok(BASE64_ENGINE.encode(bytes.as_slice()))
    }

    pub fn from_base64(other: &str) -> Result<Self, Error> {
        let bytes = BASE64_ENGINE.decode(other)?;
        let (set, _) = decode_from_slice(bytes.as_slice(), bincode::config::standard())?;
        Ok(set)
    }

    pub fn parse_with_dns_name_resolution(other: &str) -> Result<Self, Error> {
        Self::parse(other)
    }

    fn parse(other: &str) -> Result<Self, Error> {
        let mut socketaddrs: HashMap<SocketAddr, Option<DnsName>> = HashMap::new();
        let mut dns_names: HashSet<DnsName> = HashSet::new();
        for word in other.split_whitespace() {
            let endpoint: Endpoint = word.parse().map_err(|e| {
                Error::map(format!("failed to parse `{}` as endpoint: {}", word, e))
            })?;
            match endpoint {
                Endpoint::SocketAddr(socketaddr) => {
                    socketaddrs.insert(socketaddr, None);
                }
                Endpoint::DnsNameAndPort { name, port } => {
                    if let Some(port) = port {
                        let addrs = (name.to_string(), port).to_socket_addrs().map_err(|e| {
                            Error::map(format!(
                                "failed to parse `{}` as socket address: {}",
                                word, e
                            ))
                        })?;
                        for addr in addrs.into_iter() {
                            socketaddrs.insert(addr, Some(name.clone()));
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
        print_space_separated(f, self.socketaddrs.keys())?;
        if !self.socketaddrs.is_empty() {
            write!(f, " ")?;
        }
        print_space_separated(f, self.dns_names.iter())?;
        Ok(())
    }
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
    }

    #[quickcheck_macros::quickcheck]
    fn base64(expected: EndpointSet) {
        let string = expected.to_base64().unwrap();
        let actual = EndpointSet::from_base64(string.as_str()).unwrap();
        assert_eq!(expected, actual);
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
