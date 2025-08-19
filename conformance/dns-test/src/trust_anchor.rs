use core::fmt;

use crate::{
    DEFAULT_TTL, FQDN,
    record::{DNSKEY, DNSKEYRData},
};

pub struct TrustAnchor {
    keys: Vec<DNSKEY>,
}

impl TrustAnchor {
    pub fn empty() -> Self {
        Self { keys: Vec::new() }
    }

    pub fn public_dns() -> Self {
        let mut anchors = Self::empty();
        anchors.add(DNSKEY {
            zone: FQDN::ROOT,
            ttl: DEFAULT_TTL,
            rdata: DNSKEYRData {
                flags: 256,
                protocol: 3,
                algorithm: 8,
                public_key: "AwEAAbPwrxwtOMENWvblQbUFwBllR7ZtXsu9rg/LdyklKs9gU2GQTeOc59XjhuAPZ4WrT09z6YPL+vzIIJqnG3Hiru7hFUQ4pH0qsLNxrsuZrZYmXAKoVa9SXL1Ap0LygwrIugEk1G4v7Rk/Alt1jLUIE+ZymGtSEhIuGQdXrEmj3ffzXY13H42X4Ja3vJTn/WIQOXY7vwHXGDypSh9j0Tt0hknF1yVJCrIpfkhFWihMKNdMzMprD4bV+PDLRA5YSn3OPIeUnRn9qBUCN11LXQKb+W3Jg+m/5xQRQJzJ/qXgDh1+aN+Mc9AstP29Y/ZLFmF6cKtL2zoUMN5I5QymeSkJJzc=".to_string(),
            }
        });
        anchors.add(DNSKEY {
            zone: FQDN::ROOT,
            ttl: DEFAULT_TTL,
            rdata: DNSKEYRData {
                flags: 257,
                protocol: 3,
                algorithm: 8,
                public_key: "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=".to_string(),
            }
        });
        anchors
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
