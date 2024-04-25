use std::collections::HashSet;
use std::fmt::Display;
use std::fmt::Formatter;

use log::error;

use crate::DnsName;
use crate::DnsNameError;

pub(crate) struct AllowedDnsNames {
    names: HashSet<DnsName>,
}

impl AllowedDnsNames {
    pub(crate) fn new() -> Self {
        Self {
            names: Default::default(),
        }
    }

    pub(crate) fn contain(&self, name: &DnsName) -> bool {
        self.names.contains(name)
    }

    pub(crate) fn contain_any(&self, names: &[DnsName]) -> bool {
        for name in names {
            if self.contain(name) {
                return true;
            }
        }
        false
    }
}

impl Default for AllowedDnsNames {
    fn default() -> Self {
        Self::new()
    }
}

impl TryFrom<&str> for AllowedDnsNames {
    type Error = DnsNameError;
    fn try_from(other: &str) -> Result<Self, Self::Error> {
        let mut allowed_dns_names = AllowedDnsNames::new();
        for word in other.split_whitespace() {
            match word.parse::<DnsName>() {
                Ok(name) => {
                    allowed_dns_names.names.insert(name);
                }
                Err(e) => {
                    error!("failed to parse `{}` as DNS name: {}", word, e);
                }
            }
        }
        Ok(allowed_dns_names)
    }
}

impl Display for AllowedDnsNames {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(name) = self.names.iter().next() {
            write!(f, "{}", name)?;
        }
        for name in self.names.iter().skip(1) {
            write!(f, " {}", name)?;
        }
        Ok(())
    }
}
