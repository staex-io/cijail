use std::fmt::Debug;
use std::fmt::Display;
use std::hash::Hash;
use std::hash::Hasher;
use std::str::FromStr;

use crate::DnsName;
use crate::Error;

/// URI with every component as a separate field.
/// Suitable for pattern matching.
/// Host and scheme are mandatory.
#[derive(Clone)]
pub struct Uri {
    pub scheme: String,
    pub credentials: Option<UriCredentials>,
    pub host: DnsName,
    pub port: u16,
    pub path: String,
    pub query: String,
    pub fragment: String,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct UriCredentials {
    pub username: String,
    pub password: String,
}

impl FromStr for Uri {
    type Err = Error;

    fn from_str(other: &str) -> Result<Uri, Error> {
        let mut other = other.trim();
        let scheme_end = other
            .find("://")
            .ok_or_else(|| Error::map(format!("invalid uri: `{}`", other)))?;
        let scheme = other[..scheme_end].to_string();
        other = &other[(scheme_end + 3)..];
        let fragment_start = other.rfind('#');
        let fragment = match fragment_start {
            Some(fragment_start) => {
                let s = &other[(fragment_start + 1)..];
                other = &other[..fragment_start];
                s
            }
            None => "",
        }
        .to_string();
        let query_start = other.rfind('?');
        let query = match query_start {
            Some(query_start) => {
                let s = &other[(query_start + 1)..];
                other = &other[..query_start];
                s
            }
            None => "",
        }
        .to_string();
        let path_start = other.find('/');
        let path = match path_start {
            Some(path_start) => {
                let s = &other[path_start..];
                other = &other[..path_start];
                s
            }
            None => {
                if !query.is_empty() || !fragment.is_empty() {
                    return Err(Error::map(format!("invalid uri: {}", other)));
                }
                ""
            }
        }
        .to_string();
        let credentials_end = other.find('@');
        let credentials = match credentials_end {
            Some(credentials_end) => {
                let other2 = &other[..credentials_end];
                let username_end = other2.find(':');
                let (username, password) = match username_end {
                    Some(username_end) => (
                        other2[..username_end].to_string(),
                        other2[(username_end + 1)..].to_string(),
                    ),
                    None => (other2.to_string(), String::new()),
                };
                other = &other[(credentials_end + 1)..];
                Some(UriCredentials { username, password })
            }
            None => None,
        };
        let host_end = other.find(':');
        let (host, port) = match host_end {
            Some(host_end) => (
                other[..host_end].to_string(),
                other[(host_end + 1)..].parse::<u16>().map_err(Error::map)?,
            ),
            None => (
                other.to_string(),
                if scheme.as_str().eq_ignore_ascii_case("http") {
                    HTTP_PORT
                } else if scheme.as_str().eq_ignore_ascii_case("https") {
                    HTTPS_PORT
                } else {
                    return Err(Error::map(format!("invalid uri: {}", other)));
                },
            ),
        };
        if port == 0 || host.is_empty() {
            return Err(Error::map(format!("invalid uri: {}", other)));
        }
        let host = DnsName::parse_with_punycode(host.as_str())?;
        Ok(Self {
            scheme,
            credentials,
            host,
            port,
            path,
            query,
            fragment,
        })
    }
}

impl PartialEq for Uri {
    fn eq(&self, other: &Self) -> bool {
        self.scheme.eq_ignore_ascii_case(other.scheme.as_str())
            && self.credentials == other.credentials
            && self.host == other.host
            && self.port == other.port
            && self.path == other.path
            && self.query == other.query
            && self.fragment == other.fragment
    }
}

impl Eq for Uri {}

impl Hash for Uri {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.scheme.to_lowercase().hash(state);
        self.credentials.hash(state);
        self.host.hash(state);
        self.port.hash(state);
        self.path.hash(state);
        self.query.hash(state);
        self.fragment.hash(state);
    }
}

impl Display for Uri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://", self.scheme)?;
        if let Some(credentials) = self.credentials.as_ref() {
            write!(f, "{}:{}@", credentials.username, credentials.password)?;
        }
        write!(f, "{}:{}{}", self.host, self.port, self.path)?;
        if !self.query.is_empty() {
            write!(f, "?{}", self.query)?;
        }
        if !self.fragment.is_empty() {
            write!(f, "#{}", self.fragment)?;
        }
        Ok(())
    }
}

impl Debug for Uri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl TryFrom<hyper::Uri> for Uri {
    type Error = Error;
    fn try_from(other: hyper::Uri) -> Result<Self, Self::Error> {
        other.to_string().parse()
    }
}

const HTTP_PORT: u16 = 80;
const HTTPS_PORT: u16 = 443;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use quickcheck::Arbitrary;
    use rand::Rng;

    use super::*;
    use crate::DnsName;

    #[test]
    fn edge_cases() {
        assert_eq!(
            "https://staex.io/".parse::<Uri>().unwrap(),
            "HTTPS://staex.io/".parse::<Uri>().unwrap()
        );
        assert_eq!(
            "https://staex.io/".parse::<Uri>().unwrap(),
            "HTTPS://STAEX.IO/".parse::<Uri>().unwrap()
        );
    }

    #[quickcheck_macros::quickcheck]
    fn uris(uri: Uri) {
        let string = uri.to_string();
        let actual = string.as_str().parse::<Uri>().unwrap();
        assert_eq!(uri, actual);
    }

    impl Arbitrary for Uri {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let mut prng = rand::thread_rng();
            Self {
                scheme: ArbitraryScheme::arbitrary(g).0,
                credentials: Some(UriCredentials {
                    username: random_string(USERNAME_ALPHABET, 0, 10),
                    password: random_string(USERNAME_ALPHABET, 0, 10),
                }),
                host: DnsName::arbitrary(g),
                port: prng.gen_range(1_u16..u16::MAX),
                path: format!("/{}", random_string(PATH_ALPHABET, 0, 10)),
                query: random_string(PATH_ALPHABET, 0, 10),
                fragment: random_string(PATH_ALPHABET, 0, 10),
            }
        }
    }

    #[derive(Clone, Debug)]
    struct ArbitraryScheme(String);

    impl Arbitrary for ArbitraryScheme {
        fn arbitrary(_: &mut quickcheck::Gen) -> Self {
            Self(random_string(SCHEME_ALPHABET, 1, 10))
        }
    }

    fn random_string(alphabet: &[u8], min_length: usize, max_length: usize) -> String {
        let mut prng = rand::thread_rng();
        let len = prng.gen_range(min_length..max_length);
        let mut string = String::with_capacity(len);
        for _ in 0..len {
            string.push(alphabet[prng.gen_range(0..alphabet.len())] as char);
        }
        string
    }

    const SCHEME_ALPHABET: &[u8; 63] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-";
    const USERNAME_ALPHABET: &[u8; 63] = SCHEME_ALPHABET;
    const PATH_ALPHABET: &[u8; 64] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-/";
}
