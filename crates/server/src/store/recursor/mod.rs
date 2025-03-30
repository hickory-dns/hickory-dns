// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(feature = "recursor")]

//! Recursive resolver related types

#[cfg(feature = "__dnssec")]
use std::sync::Arc;
use std::{
    borrow::Cow,
    collections::HashSet,
    fs::File,
    io::{self, Read},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Instant,
};

use ipnet::IpNet;
use serde::Deserialize;
use tracing::{debug, info};

#[cfg(feature = "__dnssec")]
use crate::{authority::Nsec3QueryInfo, dnssec::NxProofKind, proto::dnssec::TrustAnchors};
use crate::{
    authority::{
        Authority, LookupControlFlow, LookupError, LookupObject, LookupOptions, MessageRequest,
        UpdateResult, ZoneType,
    },
    error::ConfigError,
    proto::{
        op::{Query, ResponseCode},
        rr::{LowerName, Name, RData, Record, RecordSet, RecordType},
        serialize::txt::{ParseError, Parser},
        xfer::Protocol,
    },
    recursor::{DnssecPolicy, Recursor},
    resolver::{
        config::{NameServerConfig, NameServerConfigGroup},
        dns_lru::TtlConfig,
        lookup::Lookup,
    },
    server::RequestInfo,
};

/// An authority that performs recursive resolutions.
///
/// This uses the hickory-recursor crate for resolving requests.
pub struct RecursiveAuthority {
    origin: LowerName,
    recursor: Recursor,
}

impl RecursiveAuthority {
    /// Read the Authority for the origin from the specified configuration
    pub async fn try_from_config(
        origin: Name,
        _zone_type: ZoneType,
        config: &RecursiveConfig,
        root_dir: Option<&Path>,
    ) -> Result<Self, String> {
        info!("loading recursor config: {}", origin);

        // read the roots
        let root_addrs = config
            .read_roots(root_dir)
            .map_err(|e| format!("failed to read roots {}: {}", config.roots.display(), e))?;

        // Configure all the name servers
        let mut roots = NameServerConfigGroup::new();
        for socket_addr in root_addrs {
            roots.push(NameServerConfig {
                socket_addr,
                protocol: Protocol::Tcp,
                tls_dns_name: None,
                http_endpoint: None,
                trust_negative_responses: false,
                bind_addr: None, // TODO: need to support bind addresses
            });

            roots.push(NameServerConfig {
                socket_addr,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                http_endpoint: None,
                trust_negative_responses: false,
                bind_addr: None,
            });
        }

        let mut builder = Recursor::builder();
        if let Some(ns_cache_size) = config.ns_cache_size {
            builder = builder.ns_cache_size(ns_cache_size);
        }
        if let Some(record_cache_size) = config.record_cache_size {
            builder = builder.record_cache_size(record_cache_size);
        }

        let recursor = builder
            .dnssec_policy(config.dnssec_policy.load().map_err(|e| e.to_string())?)
            .nameserver_filter(config.allow_server.iter(), config.deny_server.iter())
            .recursion_limit(match config.recursion_limit {
                0 => None,
                limit => Some(limit),
            })
            .ns_recursion_limit(match config.ns_recursion_limit {
                0 => None,
                limit => Some(limit),
            })
            .avoid_local_udp_ports(config.avoid_local_udp_ports.clone())
            .ttl_config(config.cache_policy.clone())
            .case_randomization(config.case_randomization)
            .build(roots)
            .map_err(|e| format!("failed to initialize recursor: {e}"))?;

        Ok(Self {
            origin: origin.into(),
            recursor,
        })
    }
}

#[async_trait::async_trait]
impl Authority for RecursiveAuthority {
    type Lookup = RecursiveLookup;

    /// Always External
    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    /// Always false for Forward zones
    fn is_axfr_allowed(&self) -> bool {
        false
    }

    fn can_validate_dnssec(&self) -> bool {
        self.recursor.is_validating()
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    ///
    /// In the context of a forwarder, this is either a zone which this forwarder is associated,
    ///   or `.`, the root zone for all zones. If this is not the root zone, then it will only forward
    ///   for lookups which match the given zone name.
    fn origin(&self) -> &LowerName {
        &self.origin
    }

    /// Forwards a lookup given the resolver configuration for this Forwarded zone
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        debug!("recursive lookup: {} {}", name, rtype);

        let query = Query::query(name.into(), rtype);
        let now = Instant::now();

        let result = self
            .recursor
            .resolve(query, now, lookup_options.dnssec_ok())
            .await;

        use LookupControlFlow::*;
        match result {
            Ok(lookup) => Continue(Ok(RecursiveLookup(lookup))),
            Err(error) => Continue(Err(LookupError::from(error))),
        }
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        self.lookup(
            request_info.query.name(),
            request_info.query.query_type(),
            lookup_options,
        )
        .await
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        LookupControlFlow::Continue(Err(LookupError::from(io::Error::new(
            io::ErrorKind::Other,
            "Getting NSEC records is unimplemented for the recursor",
        ))))
    }

    #[cfg(feature = "__dnssec")]
    async fn get_nsec3_records(
        &self,
        _info: Nsec3QueryInfo<'_>,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        LookupControlFlow::Continue(Err(LookupError::from(io::Error::new(
            io::ErrorKind::Other,
            "getting NSEC3 records is unimplemented for the recursor",
        ))))
    }

    #[cfg(feature = "__dnssec")]
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        None
    }
}

/// A Lookup object for the recursive resolver
pub struct RecursiveLookup(Lookup);

impl LookupObject for RecursiveLookup {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a> {
        Box::new(self.0.record_iter())
    }

    fn take_additionals(&mut self) -> Option<Box<dyn LookupObject>> {
        None
    }
}

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

/// DNSSEC policy configuration
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
    pub(crate) fn load(&self) -> Result<DnssecPolicy, ParseError> {
        Ok(match self {
            Self::SecurityUnaware => DnssecPolicy::SecurityUnaware,
            #[cfg(feature = "__dnssec")]
            Self::ValidationDisabled => DnssecPolicy::ValidationDisabled,
            #[cfg(feature = "__dnssec")]
            Self::ValidateWithStaticKey { path } => DnssecPolicy::ValidateWithStaticKey {
                trust_anchor: path
                    .as_ref()
                    .map(|path| TrustAnchors::from_file(path))
                    .transpose()?
                    .map(Arc::new),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "__dnssec", feature = "toml"))]
    use super::*;

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
