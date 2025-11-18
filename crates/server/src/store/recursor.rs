// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(feature = "recursor")]

//! Recursive resolver related types

use std::{
    borrow::Cow,
    collections::HashSet,
    fs, io,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use ipnet::IpNet;
use serde::Deserialize;
use tracing::{debug, info};

#[cfg(all(feature = "toml", any(feature = "__tls", feature = "__quic")))]
use crate::resolver::{
    NameServerTransportState, OpportunisticEncryptionStatePersistTask,
    config::OpportunisticEncryptionConfig,
};
#[cfg(feature = "__dnssec")]
use crate::{dnssec::NxProofKind, proto::dnssec::TrustAnchors, zone_handler::Nsec3QueryInfo};
use crate::{
    error::ConfigError,
    proto::{
        op::Query,
        op::ResponseSigner,
        rr::{LowerName, Name, RData, Record, RecordSet, RecordType},
        runtime::RuntimeProvider,
        serialize::txt::{ParseError, Parser},
    },
    recursor::{DnssecPolicy, Recursor, RecursorBuilder},
    resolver::{TtlConfig, config::OpportunisticEncryption},
    server::{Request, RequestInfo},
    zone_handler::{
        AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, ZoneHandler,
        ZoneType,
    },
};

/// A zone handler that performs recursive resolutions.
///
/// This uses the hickory-recursor crate for resolving requests.
pub struct RecursiveZoneHandler<P: RuntimeProvider> {
    origin: LowerName,
    recursor: Recursor<P>,
    #[allow(dead_code)] // Handle is retained to Drop along with RecursiveZoneHandler.
    opportunistic_encryption_persistence_task: Option<P::Handle>,
}

impl<P: RuntimeProvider> RecursiveZoneHandler<P> {
    /// Read the ZoneHandler for the origin from the specified configuration
    pub async fn try_from_config(
        origin: Name,
        _zone_type: ZoneType,
        config: &RecursiveConfig,
        root_dir: Option<&Path>,
        conn_provider: P,
    ) -> Result<Self, String> {
        info!("loading recursor config: {}", origin);

        // read the roots
        let root_addrs = config
            .read_roots(root_dir)
            .map_err(|e| format!("failed to read roots {}: {}", config.roots.display(), e))?;

        let mut builder = Recursor::builder_with_provider(conn_provider.clone());
        if let Some(ns_cache_size) = config.ns_cache_size {
            builder = builder.ns_cache_size(ns_cache_size);
        }
        if let Some(response_cache_size) = config.response_cache_size {
            builder = builder.response_cache_size(response_cache_size);
        }
        if !config.allow_answers.is_empty() {
            builder = builder.clear_answer_address_filter_allow();
            builder = builder.answer_address_filter_allow(config.allow_answers.iter());
        }
        if !config.deny_answers.is_empty() {
            builder = builder.clear_answer_address_filter_deny();
            builder = builder.answer_address_filter_deny(config.deny_answers.iter());
        }

        let mut builder = builder
            .dnssec_policy(config.dnssec_policy.load().map_err(|e| e.to_string())?)
            .deny_servers(config.deny_server.iter())
            .allow_servers(config.allow_server.iter())
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
            .opportunistic_encryption(config.opportunistic_encryption.clone());

        #[cfg(all(feature = "toml", any(feature = "__tls", feature = "__quic")))]
        {
            // Before building the recursor, potentially load some pre-existing opportunistic encrypted
            // nameserver state to configure on the builder.
            builder =
                opportunistic_encryption_persistence::configure_opp_enc_state(config, builder)?;
        }

        let recursor = builder
            .build(&root_addrs)
            .map_err(|e| format!("failed to initialize recursor: {e}"))?;

        Ok(Self {
            origin: origin.into(),
            // Once the recursor is built, potentially use the recursor's pool context to spawn a
            // background save task, holding the task handle (if created) so it drops with the zone handler.
            #[cfg(all(feature = "toml", any(feature = "__tls", feature = "__quic")))]
            opportunistic_encryption_persistence_task: match &config.opportunistic_encryption {
                OpportunisticEncryption::Enabled { config } => {
                    OpportunisticEncryptionStatePersistTask::<P::Timer>::start(
                        config,
                        recursor.pool_context(),
                        conn_provider.clone(),
                    )
                    .await?
                }
                _ => None,
            },
            #[cfg(not(all(feature = "toml", any(feature = "__tls", feature = "__quic"))))]
            opportunistic_encryption_persistence_task: None,
            recursor,
        })
    }
}

#[async_trait::async_trait]
impl<P: RuntimeProvider> ZoneHandler for RecursiveZoneHandler<P> {
    /// Always External
    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    /// Always deny for Forward zones
    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::Deny
    }

    fn can_validate_dnssec(&self) -> bool {
        self.recursor.is_validating()
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
        _request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        debug!("recursive lookup: {} {}", name, rtype);

        let query = Query::query(name.into(), rtype);
        let now = Instant::now();

        let result = self
            .recursor
            .resolve(query.clone(), now, lookup_options.dnssec_ok)
            .await;

        let response = match result {
            Ok(response) => response,
            Err(error) => return LookupControlFlow::Continue(Err(LookupError::from(error))),
        };
        LookupControlFlow::Continue(Ok(AuthLookup::Response(response)))
    }

    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (
        LookupControlFlow<AuthLookup>,
        Option<Box<dyn ResponseSigner>>,
    ) {
        let request_info = match request.request_info() {
            Ok(info) => info,
            Err(e) => return (LookupControlFlow::Break(Err(e)), None),
        };
        (
            self.lookup(
                request_info.query.name(),
                request_info.query.query_type(),
                Some(&request_info),
                lookup_options,
            )
            .await,
            None,
        )
    }

    async fn nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
            "Getting NSEC records is unimplemented for the recursor",
        ))))
    }

    #[cfg(feature = "__dnssec")]
    async fn nsec3_records(
        &self,
        _info: Nsec3QueryInfo<'_>,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
            "getting NSEC3 records is unimplemented for the recursor",
        ))))
    }

    #[cfg(feature = "__dnssec")]
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        None
    }

    #[cfg(feature = "metrics")]
    fn metrics_label(&self) -> &'static str {
        "recursive"
    }
}

/// Configuration for recursive resolver zones
#[derive(Clone, Deserialize, Eq, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub struct RecursiveConfig {
    /// File with roots, aka hints
    pub roots: PathBuf,

    /// Maximum nameserver cache size
    pub ns_cache_size: Option<usize>,

    /// Maximum DNS response cache size
    #[serde(alias = "record_cache_size")]
    pub response_cache_size: Option<u64>,

    /// Maximum recursion depth for queries. Set to 0 for unlimited recursion depth.
    #[serde(default = "recursion_limit_default")]
    pub recursion_limit: u8,

    /// Maximum recursion depth for building NS pools. Set to 0 for unlimited recursion depth.
    #[serde(default = "ns_recursion_limit_default")]
    pub ns_recursion_limit: u8,

    /// DNSSEC policy
    #[serde(default)]
    pub dnssec_policy: DnssecPolicyConfig,

    /// Networks that will not be filtered from responses.  This overrides anything present in
    /// deny_answers
    #[serde(default)]
    pub allow_answers: Vec<IpNet>,

    /// Networks that will be filtered from responses
    #[serde(default)]
    pub deny_answers: Vec<IpNet>,

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

    /// Configure RFC 9539 opportunistic encryption.
    #[serde(default)]
    pub opportunistic_encryption: OpportunisticEncryption,
}

impl RecursiveConfig {
    pub(crate) fn read_roots(&self, root_dir: Option<&Path>) -> Result<Vec<IpAddr>, ConfigError> {
        let path = if let Some(root_dir) = root_dir {
            Cow::Owned(root_dir.join(&self.roots))
        } else {
            Cow::Borrowed(&self.roots)
        };

        let roots_str = fs::read_to_string(path.as_ref())?;

        let (_zone, roots_zone) =
            Parser::new(roots_str, Some(path.into_owned()), Some(Name::root())).parse()?;

        // TODO: we may want to deny some of the root nameservers, for reasons...
        Ok(roots_zone
            .values()
            .flat_map(RecordSet::records_without_rrsigs)
            .map(Record::data)
            .filter_map(RData::ip_addr) // we only want IPs
            .collect())
    }
}

fn recursion_limit_default() -> u8 {
    24
}

fn ns_recursion_limit_default() -> u8 {
    24
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
        /// set to control the 'soft' NSEC3 iteration limit. Responses where valid NSEC3 records are
        /// returned having an iteration count above this limit, but below the hard limit, will
        /// be considered insecure (answered without the AD bit set.)
        nsec3_soft_iteration_limit: Option<u16>,
        /// set to control the 'hard' NSEC3 iteration limit. Responses where valid NSEC3 records are
        /// returned having an iteration count above this limit will be considered Bogus and will
        /// result in a SERVFAIL response being returned to the requester.
        nsec3_hard_iteration_limit: Option<u16>,
        /// set to control the size of the DNSSEC validation cache.  Set to none to use the default
        validation_cache_size: Option<usize>,
    },
}

impl DnssecPolicyConfig {
    pub(crate) fn load(&self) -> Result<DnssecPolicy, ParseError> {
        Ok(match self {
            Self::SecurityUnaware => DnssecPolicy::SecurityUnaware,
            #[cfg(feature = "__dnssec")]
            Self::ValidationDisabled => DnssecPolicy::ValidationDisabled,
            #[cfg(feature = "__dnssec")]
            Self::ValidateWithStaticKey {
                path,
                nsec3_soft_iteration_limit,
                nsec3_hard_iteration_limit,
                validation_cache_size,
            } => DnssecPolicy::ValidateWithStaticKey {
                trust_anchor: path
                    .as_ref()
                    .map(|path| TrustAnchors::from_file(path))
                    .transpose()?
                    .map(Arc::new),
                nsec3_soft_iteration_limit: *nsec3_soft_iteration_limit,
                nsec3_hard_iteration_limit: *nsec3_hard_iteration_limit,
                validation_cache_size: *validation_cache_size,
            },
        })
    }
}

#[cfg(all(feature = "toml", any(feature = "__tls", feature = "__quic")))]
mod opportunistic_encryption_persistence {
    use crate::resolver::config::OpportunisticEncryptionPersistence;

    use super::*;

    pub(super) fn configure_opp_enc_state<P: RuntimeProvider>(
        config: &RecursiveConfig,
        builder: RecursorBuilder<P>,
    ) -> Result<RecursorBuilder<P>, String> {
        let OpportunisticEncryption::Enabled {
            config:
                OpportunisticEncryptionConfig {
                    persistence: Some(OpportunisticEncryptionPersistence { path, .. }),
                    ..
                },
        } = &config.opportunistic_encryption
        else {
            return Ok(builder);
        };

        let state = match fs::read_to_string(path) {
            Ok(toml_content) => toml::from_str(&toml_content).map_err(|e| {
                format!(
                    "failed to parse opportunistic encryption state TOML file: {file_path}: {e}",
                    file_path = path.display()
                )
            })?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                info!(
                    state_file = %path.display(),
                    "no pre-existing opportunistic encryption state TOML file, starting with default state",
                );
                NameServerTransportState::default()
            }
            Err(e) => {
                return Err(format!(
                    "failed to read opportunistic encryption state TOML file: {file_path}: {e}",
                    file_path = path.display()
                ));
            }
        };

        debug!(
            path = %path.display(),
            nameserver_count = state.nameserver_count(),
            "loaded opportunistic encryption state"
        );

        Ok(builder.encrypted_transport_state(state))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(
        feature = "recursor",
        feature = "toml",
        any(feature = "__tls", feature = "__quic")
    ))]
    use hickory_resolver::config::OpportunisticEncryptionConfig;

    #[cfg(all(feature = "__dnssec", feature = "toml"))]
    use super::*;

    #[cfg(all(feature = "__dnssec", feature = "toml"))]
    #[test]
    fn can_parse_recursive_config() {
        let input = r#"roots = "/etc/root.hints"
dnssec_policy.ValidateWithStaticKey.path = "/etc/trusted-key.key""#;

        let config: RecursiveConfig = toml::from_str(input).unwrap();

        if let DnssecPolicyConfig::ValidateWithStaticKey { path, .. } = config.dnssec_policy {
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

    #[cfg(all(
        feature = "recursor",
        feature = "toml",
        any(feature = "__tls", feature = "__quic")
    ))]
    #[test]
    fn can_parse_recursor_opportunistic_enc_policy() {
        let input = r#"roots = "/etc/root.hints"
[opportunistic_encryption]
enabled = {}
"#;

        let config: RecursiveConfig = toml::from_str(input).unwrap();
        assert_eq!(
            config.opportunistic_encryption,
            OpportunisticEncryption::Enabled {
                config: OpportunisticEncryptionConfig::default()
            }
        );
    }
}
