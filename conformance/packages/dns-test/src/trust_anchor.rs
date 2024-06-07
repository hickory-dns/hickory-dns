use core::fmt;

use crate::record::DNSKEY;

pub struct TrustAnchor {
    keys: Vec<DNSKEY>,
}

impl TrustAnchor {
    pub fn empty() -> Self {
        Self { keys: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn add(&mut self, key: DNSKEY) -> &mut Self {
        self.keys.push(key);
        self
    }

    pub(crate) fn keys(&self) -> &[DNSKEY] {
        &self.keys
    }

    /// formats the `TrustAnchor` in the format `delv` expects
    pub(super) fn delv(&self) -> String {
        let mut buf = "trust-anchors {".to_string();

        for key in &self.keys {
            buf.push_str(&key.delv());
        }

        buf.push_str("};");
        buf
    }
}

impl fmt::Display for TrustAnchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for key in &self.keys {
            writeln!(f, "{key}")?;
        }
        Ok(())
    }
}

impl FromIterator<DNSKEY> for TrustAnchor {
    fn from_iter<T: IntoIterator<Item = DNSKEY>>(iter: T) -> Self {
        Self {
            keys: iter.into_iter().collect(),
        }
    }
}
