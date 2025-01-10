// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[cfg(feature = "__dnssec")]
use std::sync::Arc;
use std::{
    borrow::Cow,
    collections::HashSet,
    fs::File,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use ipnet::IpNet;
use serde::Deserialize;

use crate::error::ConfigError;
#[cfg(feature = "__dnssec")]
use crate::proto::{
    dnssec::{TrustAnchor, Verifier},
    serialize::txt::trust_anchor::{self, Entry},
};
use crate::proto::{
    rr::{Name, RData, Record, RecordSet},
    serialize::txt::Parser,
};
use crate::recursor::DnssecPolicy;
use crate::resolver::dns_lru::TtlConfig;

/// Configuration for file based zones
#[derive(Clone, Deserialize, Eq, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub struct RecursiveConfig {
    /// File with roots, aka hints
    pub roots: PathBuf,

    /// Maximum nameserver cache size
    pub ns_cache_size: Option<usize>,

    /// Maximum DNS record cache size
    pub record_cache_size: Option<usize>,

    /// Maximum recursion depth for queries. Set to 0 for unlimited recursion depth.
    #[serde(default = "recursion_limit_default")]
    pub recursion_limit: u8,

    /// Maximum recursion depth for building NS pools. Set to 0 for unlimited recursion depth.
    #[serde(default = "ns_recursion_limit_default")]
    pub ns_recursion_limit: u8,

    /// DNSSEC policy
    #[serde(default)]
    pub dnssec_policy: DnssecPolicyConfig,

    /// Networks that will be queried during resolution
    #[serde(default)]
    pub allow_server: Vec<IpNet>,

    /// Networks that will not be queried during resolution
    #[serde(default)]
    pub deny_server: Vec<IpNet>,

    /// Local UDP ports to avoid when making outgoing queries
    #[serde(default)]
    pub avoid_local_udp_ports: HashSet<u16>,

    /// Caching policy, setting minimum and maximum TTLs
    #[serde(default)]
    pub cache_policy: TtlConfig,

    /// Enable case randomization.
    ///
    /// Randomize the case of letters in query names, and require that responses preserve the case
    /// of the query name, in order to mitigate spoofing attacks. This is only applied over UDP.
    ///
    /// This implements the mechanism described in
    /// [draft-vixie-dnsext-dns0x20-00](https://datatracker.ietf.org/doc/html/draft-vixie-dnsext-dns0x20-00).
    #[serde(default)]
    pub case_randomization: bool,
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

fn recursion_limit_default() -> u8 {
    12
}

fn ns_recursion_limit_default() -> u8 {
    16
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[allow(missing_copy_implementations)]
pub enum DnssecPolicyConfig {
    /// security unaware; DNSSEC records will not be requested nor processed
    #[default]
    SecurityUnaware,

    /// DNSSEC validation is disabled; DNSSEC records will be requested and processed
    #[cfg(feature = "__dnssec")]
    ValidationDisabled,

    /// DNSSEC validation is enabled and will use the chosen `trust_anchor` set of keys
    #[cfg(feature = "__dnssec")]
    ValidateWithStaticKey {
        /// set to `None` to use built-in trust anchor
        path: Option<PathBuf>,
    },
}

impl DnssecPolicyConfig {
    pub(crate) fn load(&self) -> Result<DnssecPolicy, String> {
        Ok(match self {
            Self::SecurityUnaware => DnssecPolicy::SecurityUnaware,
            #[cfg(feature = "__dnssec")]
            Self::ValidationDisabled => DnssecPolicy::ValidationDisabled,
            #[cfg(feature = "__dnssec")]
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

#[cfg(feature = "__dnssec")]
fn read_trust_anchor(path: &Path) -> Result<TrustAnchor, String> {
    use std::fs;

    let contents = fs::read_to_string(path).map_err(|e| e.to_string())?;

    parse_trust_anchor(&contents)
}

#[cfg(feature = "__dnssec")]
fn parse_trust_anchor(input: &str) -> Result<TrustAnchor, String> {
    let parser = trust_anchor::Parser::new(input);
    let entries = parser.parse().map_err(|e| e.to_string())?;

    let mut trust_anchor = TrustAnchor::new();
    for entry in entries {
        if let Entry::DNSKEY(record) = entry {
            let dnskey = record.data();
            // XXX should we filter based on `dnskey.flags()`?
            let key = dnskey.key().map_err(|e| e.to_string())?;
            trust_anchor.insert_trust_anchor(&*key);
        }
    }

    Ok(trust_anchor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "__dnssec")]
    #[test]
    fn can_load_trust_anchor_file() {
        let input = include_str!("../../../../proto/tests/test-data/root.key");

        let trust_anchor = parse_trust_anchor(input).unwrap();
        assert_eq!(3, trust_anchor.len());
    }

    #[cfg(all(feature = "__dnssec", feature = "toml"))]
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

    #[cfg(all(feature = "recursor", feature = "toml"))]
    #[test]
    fn can_parse_recursor_cache_policy() {
        use std::time::Duration;

        use hickory_proto::rr::RecordType;

        let input = r#"roots = "/etc/root.hints"

[cache_policy.default]
positive_max_ttl = 14400

[cache_policy.A]
positive_max_ttl = 3600"#;

        let config: RecursiveConfig = toml::from_str(input).unwrap();

        assert_eq!(
            *config
                .cache_policy
                .positive_response_ttl_bounds(RecordType::MX)
                .end(),
            Duration::from_secs(14400)
        );

        assert_eq!(
            *config
                .cache_policy
                .positive_response_ttl_bounds(RecordType::A)
                .end(),
            Duration::from_secs(3600)
        )
    }
}
