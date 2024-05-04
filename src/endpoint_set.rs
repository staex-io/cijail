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
use hyper::Uri;
use regex::Regex;

use crate::DnsName;
use crate::Error;

#[derive(Default)]
#[cfg_attr(test, derive(Clone, Debug))]
pub struct EndpointSet {
    socketaddrs: HashMap<SocketAddr, Option<DnsName>>,
    dns_names: HashSet<DnsName>,
    dns_name_patterns: Vec<Regex>,
    uris: Vec<Uri>,
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
            for pattern in self.dns_name_patterns.iter() {
                if pattern.is_match(name.as_str()) {
                    return true;
                }
            }
        }
        false
    }

    pub fn contains_uri(&self, other: &Uri) -> bool {
        for uri in self.uris.iter() {
            if uri == other {
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

    pub fn allow_socketaddr(&mut self, socketaddr: SocketAddr) {
        self.socketaddrs.insert(socketaddr, None);
    }

    fn parse(other: &str) -> Result<Self, Error> {
        let mut socketaddrs: HashMap<SocketAddr, Option<DnsName>> = HashMap::new();
        let mut dns_names: HashSet<DnsName> = HashSet::new();
        let mut dns_name_patterns: Vec<Regex> = Vec::new();
        let mut uris: Vec<Uri> = Vec::new();
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
                Endpoint::DnsNamePattern(regex) => {
                    dns_name_patterns.push(regex);
                }
                Endpoint::Uri(uri) => {
                    uris.push(uri);
                }
            }
        }
        Ok(Self {
            socketaddrs,
            dns_names,
            dns_name_patterns,
            uris,
        })
    }
}

impl Encode for EndpointSet {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        Encode::encode(&self.socketaddrs, encoder)?;
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
        let dns_names = Decode::decode(decoder)?;
        let dns_name_patterns: Vec<String> = Decode::decode(decoder)?;
        let uris: Vec<String> = Decode::decode(decoder)?;
        Ok(Self {
            socketaddrs,
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
        let dns_names = BorrowDecode::borrow_decode(decoder)?;
        let dns_name_patterns: Vec<String> = BorrowDecode::borrow_decode(decoder)?;
        let uris: Vec<String> = BorrowDecode::borrow_decode(decoder)?;
        Ok(Self {
            socketaddrs,
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
        print_space_separated(f, self.dns_names.iter())?;
        Ok(())
    }
}

enum Endpoint {
    SocketAddr(SocketAddr),
    DnsNameAndPort { name: DnsName, port: Option<u16> },
    DnsNamePattern(Regex),
    Uri(Uri),
}

impl FromStr for Endpoint {
    type Err = Error;
    fn from_str(other: &str) -> Result<Self, Self::Err> {
        match other.parse::<SocketAddr>() {
            Ok(socketaddr) => Ok(Self::SocketAddr(socketaddr)),
            Err(_) => {
                if let Ok(uri) = other.parse::<Uri>() {
                    if uri.scheme_str().is_some() && uri.host().is_some() {
                        return Ok(Self::Uri(uri));
                    }
                }
                if other.contains('*') {
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
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let dns_name_patterns: Vec<ArbitraryRegex> = Arbitrary::arbitrary(g);
            let uris: Vec<ArbitraryUri> = Arbitrary::arbitrary(g);
            Self {
                socketaddrs: Arbitrary::arbitrary(g),
                dns_names: Arbitrary::arbitrary(g),
                dns_name_patterns: dns_name_patterns.into_iter().map(|x| x.0).collect(),
                uris: uris.into_iter().map(|x| x.0).collect(),
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

    #[derive(Clone)]
    struct ArbitraryUri(Uri);

    impl Arbitrary for ArbitraryUri {
        fn arbitrary(_: &mut quickcheck::Gen) -> Self {
            let uri: Uri =
                "abc://username:password@example.com:123/path/data?key=value&key2=value2#fragid1"
                    .parse()
                    .unwrap();
            Self(uri)
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
