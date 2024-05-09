use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Write;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::str::FromStr;

use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine;
use bincode::de::BorrowDecoder;
use bincode::de::Decoder;
use bincode::decode_from_slice;
use bincode::enc::Encoder;
use bincode::encode_to_vec;
use bincode::error::DecodeError;
use bincode::error::EncodeError;
use bincode::BorrowDecode;
use bincode::Decode;
use bincode::Encode;
use regex::Regex;

use crate::AnySocketAddr;
use crate::DnsName;
use crate::Error;
use crate::Uri;

#[derive(Default)]
#[cfg_attr(test, derive(Clone, Debug))]
pub struct EndpointSet {
    socketaddrs: HashMap<SocketAddr, Vec<DnsName>>,
    other_socketaddrs: HashSet<AnySocketAddr>,
    dns_names: HashMap<DnsName, Vec<SocketAddr>>,
    dns_name_patterns: Vec<Regex>,
    pub uris: Vec<Uri>,
}

impl EndpointSet {
    pub fn contains_any_socket_address(&self, addrs: &[AnySocketAddr]) -> bool {
        for addr in addrs.iter() {
            match addr {
                AnySocketAddr::Ip(addr) => {
                    if self.socketaddrs.contains_key(addr) {
                        return true;
                    }
                }
                _ => {
                    if self.other_socketaddrs.contains(addr) {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn contains_any_dns_name(&self, names: &[DnsName]) -> bool {
        for name in names.iter() {
            if self.dns_names.contains_key(name) {
                return true;
            }
            for pattern in self.dns_name_patterns.iter() {
                if pattern.is_match(name.as_str()) {
                    return true;
                }
            }
        }
        false
    }

    pub fn contains_uri(&self, other: &Uri) -> bool {
        let other = other.to_string();
        for uri in self.uris.iter() {
            if other.starts_with(uri.to_string().as_str()) {
                return true;
            }
        }
        false
    }

    pub fn resolve_socketaddr(&self, socketaddr: &SocketAddr) -> &[DnsName] {
        match self.socketaddrs.get(socketaddr) {
            Some(names) => names.as_slice(),
            None => &[],
        }
    }

    pub fn resolve_dns_name(&self, dns_name: &DnsName) -> &[SocketAddr] {
        match self.dns_names.get(dns_name) {
            Some(addrs) => addrs.as_slice(),
            None => &[],
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

    pub fn allow_socketaddr(&mut self, socketaddr: SocketAddr) {
        self.socketaddrs.insert(socketaddr, Vec::new());
    }

    fn parse(other: &str) -> Result<Self, Error> {
        let mut socketaddrs: HashMap<SocketAddr, Vec<DnsName>> = HashMap::new();
        let mut other_socketaddrs: HashSet<AnySocketAddr> = HashSet::new();
        let mut dns_names: HashMap<DnsName, Vec<SocketAddr>> = HashMap::new();
        let mut dns_name_patterns: Vec<Regex> = Vec::new();
        let mut uris: Vec<Uri> = Vec::new();
        for word in other.split_whitespace() {
            let endpoint: Endpoint = word.parse().map_err(|e| {
                Error::map(format!("failed to parse `{}` as endpoint: {}", word, e))
            })?;
            match endpoint {
                Endpoint::SocketAddr(socketaddr) => match socketaddr {
                    AnySocketAddr::Ip(socketaddr) => {
                        socketaddrs.entry(socketaddr).or_default();
                    }
                    _ => {
                        other_socketaddrs.insert(socketaddr);
                    }
                },
                Endpoint::DnsNameAndPort { name, port } => {
                    let mut name_socketaddrs: Vec<SocketAddr> = Vec::new();
                    if let Some(port) = port {
                        let addrs = (name.to_string(), port).to_socket_addrs().map_err(|e| {
                            Error::map(format!(
                                "failed to parse `{}` as socket address: {}",
                                word, e
                            ))
                        })?;
                        for addr in addrs.into_iter() {
                            socketaddrs.entry(addr).or_default().push(name.clone());
                            name_socketaddrs.push(addr);
                        }
                    }
                    dns_names
                        .entry(name)
                        .or_default()
                        .extend(name_socketaddrs.into_iter());
                }
                Endpoint::DnsNamePattern(regex) => {
                    dns_name_patterns.push(regex);
                }
                Endpoint::Uri(uri) => {
                    let addrs = (uri.host.as_str(), uri.port)
                        .to_socket_addrs()
                        .map_err(|e| {
                            Error::map(format!(
                                "failed to parse `{}:{}` as socket address: {}",
                                uri.host, uri.port, e
                            ))
                        })?;
                    dns_names
                        .entry(uri.host.clone())
                        .or_default()
                        .extend(addrs.into_iter());
                    uris.push(uri);
                }
            }
        }
        Ok(Self {
            socketaddrs,
            other_socketaddrs,
            dns_names,
            dns_name_patterns,
            uris,
        })
    }
}

impl Encode for EndpointSet {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        Encode::encode(&self.socketaddrs, encoder)?;
        Encode::encode(&self.other_socketaddrs, encoder)?;
        Encode::encode(&self.dns_names, encoder)?;
        let dns_name_patterns = self
            .dns_name_patterns
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<String>>();
        Encode::encode(&dns_name_patterns, encoder)?;
        let uris = self
            .uris
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<String>>();
        Encode::encode(&uris, encoder)?;
        Ok(())
    }
}

impl Decode for EndpointSet {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let socketaddrs = Decode::decode(decoder)?;
        let other_socketaddrs = Decode::decode(decoder)?;
        let dns_names = Decode::decode(decoder)?;
        let dns_name_patterns: Vec<String> = Decode::decode(decoder)?;
        let uris: Vec<String> = Decode::decode(decoder)?;
        Ok(Self {
            socketaddrs,
            other_socketaddrs,
            dns_names,
            dns_name_patterns: dns_name_patterns
                .into_iter()
                .map(|x| Regex::new(x.as_str()))
                .collect::<Result<Vec<Regex>, _>>()
                .map_err(|_| DecodeError::Other("invalid regex pattern"))?,
            uris: uris
                .into_iter()
                .map(|x| x.parse::<Uri>())
                .collect::<Result<Vec<Uri>, _>>()
                .map_err(|_| DecodeError::Other("invalid uri"))?,
        })
    }
}

impl<'de> BorrowDecode<'de> for EndpointSet {
    fn borrow_decode<D: BorrowDecoder<'de>>(decoder: &mut D) -> Result<Self, DecodeError> {
        let socketaddrs = BorrowDecode::borrow_decode(decoder)?;
        let other_socketaddrs = BorrowDecode::borrow_decode(decoder)?;
        let dns_names = BorrowDecode::borrow_decode(decoder)?;
        let dns_name_patterns: Vec<String> = BorrowDecode::borrow_decode(decoder)?;
        let uris: Vec<String> = BorrowDecode::borrow_decode(decoder)?;
        Ok(Self {
            socketaddrs,
            other_socketaddrs,
            dns_names,
            dns_name_patterns: dns_name_patterns
                .into_iter()
                .map(|x| Regex::new(x.as_str()))
                .collect::<Result<Vec<Regex>, _>>()
                .map_err(|_| DecodeError::Other("invalid regex pattern"))?,
            uris: uris
                .into_iter()
                .map(|x| x.parse::<Uri>())
                .collect::<Result<Vec<Uri>, _>>()
                .map_err(|_| DecodeError::Other("invalid uri"))?,
        })
    }
}

impl PartialEq for EndpointSet {
    fn eq(&self, other: &Self) -> bool {
        self.socketaddrs == other.socketaddrs
            && self.dns_names == other.dns_names
            && self
                .dns_name_patterns
                .iter()
                .map(|x| x.as_str())
                .eq(other.dns_name_patterns.iter().map(|x| x.as_str()))
    }
}

impl Display for EndpointSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        print_space_separated(f, self.socketaddrs.keys())?;
        if !self.socketaddrs.is_empty() {
            write!(f, " ")?;
        }
        print_space_separated(f, self.dns_names.keys())?;
        Ok(())
    }
}

enum Endpoint {
    SocketAddr(AnySocketAddr),
    DnsNameAndPort { name: DnsName, port: Option<u16> },
    DnsNamePattern(Regex),
    Uri(Uri),
}

impl FromStr for Endpoint {
    type Err = Error;
    fn from_str(other: &str) -> Result<Self, Self::Err> {
        match other.parse::<AnySocketAddr>() {
            Ok(socketaddr) => Ok(Self::SocketAddr(socketaddr)),
            Err(_) => {
                if let Ok(uri) = other.parse::<Uri>() {
                    Ok(Self::Uri(uri))
                } else if other.contains('*') {
                    Ok(Self::DnsNamePattern(glob_to_regex(other)?))
                } else {
                    match other.rfind(':') {
                        Some(colon_index) => Ok(Self::DnsNameAndPort {
                            name: other[..colon_index].parse()?,
                            port: Some(other[(colon_index + 1)..].parse().map_err(Error::map)?),
                        }),
                        None => Ok(Self::DnsNameAndPort {
                            name: other.parse()?,
                            port: None,
                        }),
                    }
                }
            }
        }
    }
}

/// Convert glob pattern to regular expression.
fn glob_to_regex(glob: &str) -> Result<Regex, regex::Error> {
    let mut regex = String::with_capacity(glob.len() * 6);
    regex.push('^');
    for ch in glob.chars() {
        match ch {
            '*' => regex.push_str(".*"),
            ch => write!(regex, "\\u{{{:x}}}", ch as u32).unwrap(),
        }
    }
    regex.push('$');
    Regex::new(regex.as_str())
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
    use rand::Rng;

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
        fn arbitrary(_: &mut quickcheck::Gen) -> Self {
            let mut g3 = quickcheck::Gen::new(3);
            let dns_name_patterns: Vec<ArbitraryRegex> = Arbitrary::arbitrary(&mut g3);
            Self {
                socketaddrs: Arbitrary::arbitrary(&mut g3),
                other_socketaddrs: Default::default(), // TODO
                dns_names: Arbitrary::arbitrary(&mut g3),
                dns_name_patterns: dns_name_patterns.into_iter().map(|x| x.0).collect(),
                uris: Arbitrary::arbitrary(&mut g3),
            }
        }
    }

    #[derive(Clone)]
    struct ArbitraryRegex(Regex);

    impl Arbitrary for ArbitraryRegex {
        fn arbitrary(_: &mut quickcheck::Gen) -> Self {
            let mut g3 = quickcheck::Gen::new(3);
            let dns_name: DnsName = Arbitrary::arbitrary(&mut g3);
            let mut labels: Vec<String> = dns_name
                .as_str()
                .split('.')
                .map(ToString::to_string)
                .collect();
            let mut prng = rand::thread_rng();
            let i = prng.gen_range(0..labels.len());
            labels[i] = "*".to_string();
            Self(Regex::new(glob_to_regex(labels.join(".").as_str()).unwrap().as_str()).unwrap())
        }
    }

    #[test]
    fn glob_to_regex_test() {
        assert!(glob_to_regex("*.staex.io")
            .unwrap()
            .is_match("cas.staex.io"));
        assert!(!glob_to_regex("*.staex.io").unwrap().is_match("staex.io"));
        assert!(glob_to_regex("*staex.io").unwrap().is_match("cas.staex.io"));
        assert!(glob_to_regex("*staex.io").unwrap().is_match("staex.io"));
    }
}
