use std::fmt::Debug;
use std::fmt::Display;
use std::str::FromStr;

// https://datatracker.ietf.org/doc/html/rfc1035
#[cfg_attr(test, derive(Debug, PartialEq))]
pub(crate) struct DnsName(pub(crate) String);

impl DnsName {
    #[allow(dead_code)]
    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl FromStr for DnsName {
    type Err = DnsNameError;

    fn from_str(other: &str) -> Result<Self, Self::Err> {
        let other = other.trim();
        validate_dns_name(other)?;
        Ok(Self(other.to_string()))
    }
}

impl TryFrom<String> for DnsName {
    type Error = DnsNameError;
    fn try_from(other: String) -> Result<Self, Self::Error> {
        validate_dns_name(other.as_str())?;
        Ok(Self(other))
    }
}

impl From<DnsName> for String {
    fn from(other: DnsName) -> String {
        other.0
    }
}

impl AsRef<str> for DnsName {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

fn validate_dns_name(other: &str) -> Result<(), DnsNameError> {
    if other.is_empty() || other.len() > MAX_NAME_LEN {
        return Err(DnsNameError);
    }
    let mut label_len = 0;
    let bytes = other.as_bytes();
    for i in 0..bytes.len() {
        let ch = bytes[i];
        let ch_prev = if i == 0 { None } else { Some(bytes[i - 1]) };
        let ch_next = bytes.get(i + 1);
        if ch == b'.' {
            if matches!(ch_prev, None | Some(b'.')) || label_len == 0 {
                return Err(DnsNameError);
            }
            label_len = 0;
        } else {
            if label_len == 0 {
                // first character
                if !is_alphabetic(ch) {
                    return Err(DnsNameError);
                }
            } else if matches!(ch_next, None | Some(b'.')) {
                // last character
                if !is_alphabetic(ch) && !is_numeric(ch) {
                    return Err(DnsNameError);
                }
            } else {
                // interior character
                if !is_alphabetic(ch) && !is_numeric(ch) && ch != b'-' {
                    return Err(DnsNameError);
                }
            }
            label_len += 1;
            if label_len > MAX_LABEL_LEN {
                return Err(DnsNameError);
            }
        }
    }
    Ok(())
}

fn is_alphabetic(ch: u8) -> bool {
    ch.is_ascii_lowercase() || ch.is_ascii_uppercase()
}

fn is_numeric(ch: u8) -> bool {
    ch.is_ascii_digit()
}

#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct DnsNameError;

impl std::error::Error for DnsNameError {}

impl Display for DnsNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid DNS name")
    }
}

impl Debug for DnsNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

const MAX_LABEL_LEN: usize = 63;
const MAX_NAME_LEN: usize = 255;

#[cfg(test)]
mod tests {

    #![allow(clippy::unwrap_used)]

    use quickcheck::Arbitrary;
    use rand::Rng;

    use super::*;

    #[test]
    fn invalid_dns_names() {
        assert_eq!(Err(DnsNameError), "".parse::<DnsName>());
        assert_eq!(Err(DnsNameError), ".".parse::<DnsName>());
        assert_eq!(Err(DnsNameError), "..".parse::<DnsName>());
        assert_eq!(Err(DnsNameError), "0".parse::<DnsName>());
        assert_eq!(Err(DnsNameError), "-".parse::<DnsName>());
    }

    fn validate_label(label: &str) -> bool {
        label.len() <= MAX_LABEL_LEN
            && !label.is_empty()
            && label.chars().next().unwrap().is_alphabetic()
            && label.chars().last().unwrap().is_alphanumeric()
            && !label.contains('.')
    }

    fn validate_name(name: &str) -> bool {
        name.split('.').all(validate_label)
            && name.len() <= MAX_NAME_LEN
            && !name.is_empty()
            && name != "."
    }

    #[quickcheck_macros::quickcheck]
    fn dns_labels(ArbitraryDnsLabel(name): ArbitraryDnsLabel) {
        match name.clone().try_into() {
            Ok(DnsName(name)) => {
                assert!(
                    validate_label(name.as_str()),
                    "should be valid: dns label = `{}`",
                    name
                );
            }
            Err(_) => {
                assert!(
                    !validate_label(name.as_str()),
                    "should be invalid: dns label = `{}`",
                    name
                );
            }
        }
    }

    #[quickcheck_macros::quickcheck]
    fn dns_names(ArbitraryDnsName(name): ArbitraryDnsName) {
        match name.clone().try_into() {
            Ok(DnsName(name)) => {
                assert!(
                    validate_name(name.as_str()),
                    "should be valid: dns name = `{}`",
                    name
                );
            }
            Err(_) => {
                assert!(
                    !validate_name(name.as_str()),
                    "should be invalid: dns name = `{}`",
                    name
                );
            }
        }
    }

    #[derive(Debug, Clone)]
    struct ArbitraryDnsLabel(String);

    impl Arbitrary for ArbitraryDnsLabel {
        fn arbitrary(_: &mut quickcheck::Gen) -> Self {
            const LABEL_ALPHABET: &[u8; 63] =
                b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-";
            let mut prng = rand::thread_rng();
            let label_len: usize = prng.gen_range(1..(2 * MAX_LABEL_LEN));
            let mut name = String::with_capacity(label_len);
            for _ in 0..label_len {
                let i: usize = prng.gen_range(0..LABEL_ALPHABET.len());
                name.push(LABEL_ALPHABET[i] as char);
            }
            Self(name)
        }
    }

    #[derive(Debug, Clone)]
    struct ArbitraryDnsName(String);

    impl Arbitrary for ArbitraryDnsName {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let mut prng = rand::thread_rng();
            let num_labels: usize = prng.gen_range(0..3);
            let mut labels: Vec<String> = Vec::with_capacity(num_labels);
            for _ in 0..num_labels {
                labels.push(ArbitraryDnsLabel::arbitrary(g).0);
            }
            Self(labels.join("."))
        }
    }
}
