// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[cfg(feature = "dnssec")]
use std::sync::Arc;
use std::{
    borrow::Cow,
    fs::File,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use crate::error::ConfigError;
use crate::proto::{
    rr::{RData, Record, RecordSet},
    serialize::txt::Parser,
};
use crate::resolver::Name;
#[cfg(feature = "dnssec")]
use crate::{proto::rr::dnssec::TrustAnchor, recursor::DnssecPolicy};

/// Configuration for file based zones
#[derive(Clone, Deserialize, Eq, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub struct RecursiveConfig {
    /// File with roots, aka hints
    pub roots: PathBuf,

    /// Maximum nameserver cache size
    #[serde(default = "ns_cache_size_default")]
    pub ns_cache_size: usize,

    /// Maximum DNS record cache size
    #[serde(default = "record_cache_size_default")]
    pub record_cache_size: usize,

    /// DNSSEC policy
    #[cfg(feature = "dnssec")]
    #[serde(default)]
    pub dnssec_policy: DnssecPolicyConfig,
}

impl RecursiveConfig {
    pub(crate) fn read_roots(
        &self,
        root_dir: Option<&Path>,
    ) -> Result<Vec<SocketAddr>, ConfigError> {
        let path = if let Some(root_dir) = root_dir {
            Cow::Owned(root_dir.join(&self.roots))
        } else {
            Cow::Borrowed(&self.roots)
        };

        let mut roots = File::open(path.as_ref())?;
        let mut roots_str = String::new();
        roots.read_to_string(&mut roots_str)?;

        let (_zone, roots_zone) =
            Parser::new(roots_str, Some(path.into_owned()), Some(Name::root())).parse()?;

        // TODO: we may want to deny some of the root nameservers, for reasons...
        Ok(roots_zone
            .values()
            .flat_map(RecordSet::records_without_rrsigs)
            .map(Record::data)
            .filter_map(RData::ip_addr) // we only want IPs
            .map(|ip| SocketAddr::from((ip, 53))) // all the roots only have tradition DNS ports
            .collect())
    }
}

fn ns_cache_size_default() -> usize {
    1024
}
fn record_cache_size_default() -> usize {
    1048576
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub enum DnssecPolicyConfig {
    /// security unaware; DNSSEC records will not be requested nor processed
    #[default]
    SecurityUnaware,

    /// DNSSEC validation is disabled; DNSSEC records will be requested and processed
    #[cfg(feature = "dnssec")]
    ValidationDisabled,

    /// DNSSEC validation is enabled and will use the chosen `trust_anchor` set of keys
    #[cfg(feature = "dnssec")]
    ValidateWithStaticKey {
        /// set to `None` to use built-in trust anchor
        path: Option<PathBuf>,
    },
}

impl DnssecPolicyConfig {
    pub(crate) fn load(&self) -> Result<DnssecPolicy, String> {
        Ok(match self {
            Self::SecurityUnaware => DnssecPolicy::SecurityUnaware,
            #[cfg(feature = "dnssec")]
            Self::ValidationDisabled => DnssecPolicy::ValidationDisabled,
            #[cfg(feature = "dnssec")]
            Self::ValidateWithStaticKey { path } => DnssecPolicy::ValidateWithStaticKey {
                trust_anchor: path
                    .as_ref()
                    .map(|path| read_trust_anchor(path))
                    .transpose()?
                    .map(Arc::new),
            },
        })
    }
}

#[cfg(feature = "dnssec")]
fn read_trust_anchor(path: &Path) -> Result<TrustAnchor, String> {
    use std::fs;

    let contents = fs::read_to_string(path).map_err(|e| e.to_string())?;

    parse_trust_anchor(&contents)
}

#[cfg(feature = "dnssec")]
fn parse_trust_anchor(input: &str) -> Result<TrustAnchor, String> {
    use crate::proto::{
        rr::dnssec::PublicKeyEnum,
        serialize::txt::trust_anchor::{self, Entry},
    };

    let parser = trust_anchor::Parser::new(input);
    let entries = parser.parse().map_err(|e| e.to_string())?;

    let mut trust_anchor = TrustAnchor::new();
    for entry in entries {
        if let Entry::DNSKEY(record) = entry {
            let dnskey = record.data();
            // XXX should we filter based on `dnskey.flags()`?
            let key = PublicKeyEnum::from_public_bytes(dnskey.public_key(), dnskey.algorithm())
                .map_err(|e| e.to_string())?;
            trust_anchor.insert_trust_anchor(&key);
        }
    }

    Ok(trust_anchor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "dnssec")]
    #[test]
    fn can_load_trust_anchor_file() {
        let input = include_str!("../../../../proto/tests/test-data/root.key");

        let trust_anchor = parse_trust_anchor(input).unwrap();
        assert_eq!(3, trust_anchor.len());
    }

    #[cfg(all(feature = "dnssec", feature = "toml"))]
    #[test]
    fn can_parse_recursive_config() {
        let input = r#"roots = "/etc/root.hints"
dnssec_policy.ValidateWithStaticKey.path = "/etc/trusted-key.key""#;

        let config: RecursiveConfig = toml::from_str(input).unwrap();

        if let DnssecPolicyConfig::ValidateWithStaticKey { path } = config.dnssec_policy {
            assert_eq!(Some(Path::new("/etc/trusted-key.key")), path.as_deref());
        } else {
            unreachable!()
        }
    }
}
