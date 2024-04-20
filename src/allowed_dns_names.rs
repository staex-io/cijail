use std::collections::HashSet;
use std::fmt::Display;
use std::fmt::Formatter;

pub(crate) struct AllowedDnsNames {
    names: HashSet<String>,
}

impl AllowedDnsNames {
    pub(crate) fn new() -> Self {
        Self {
            names: Default::default(),
        }
    }

    pub(crate) fn contain(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    pub(crate) fn contain_any(&self, names: &[String]) -> bool {
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

impl From<&str> for AllowedDnsNames {
    fn from(other: &str) -> Self {
        let mut allowed_dns_names = AllowedDnsNames::new();
        for word in other.split_whitespace() {
            allowed_dns_names.names.insert(word.to_string());
        }
        allowed_dns_names
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
