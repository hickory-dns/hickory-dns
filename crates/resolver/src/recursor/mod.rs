// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! A recursive DNS resolver based on the Hickory DNS (stub) resolver

#[cfg(feature = "serde")]
use std::{
    borrow::Cow,
    fs,
    path::{Path, PathBuf},
};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, atomic::AtomicU8},
    time::Instant,
};

use ipnet::IpNet;
#[cfg(feature = "serde")]
use serde::Deserialize;
use tracing::warn;

#[cfg(feature = "tokio")]
use crate::net::runtime::TokioRuntimeProvider;
#[cfg(feature = "serde")]
use crate::proto::{
    rr::{RData, Record, RecordSet},
    serialize::txt::{ParseError, Parser},
};
use crate::{
    ConnectionProvider, NameServerTransportState, PoolContext, TlsConfig, TtlConfig,
    config::OpportunisticEncryption,
    proto::{
        op::{Message, Query},
        rr::Name,
    },
};
#[cfg(feature = "__dnssec")]
use crate::{
    ResponseCache,
    net::{
        DnsError, NetError, NoRecords,
        dnssec::DnssecDnsHandle,
        xfer::{DnsHandle as _, FirstAnswer as _},
    },
    proto::{
        dnssec::TrustAnchors,
        op::{DnsRequestOptions, ResponseCode},
        rr::RecordType,
    },
};

mod error;
pub use error::{AuthorityData, RecursorError};

mod handle;
use handle::RecursorDnsHandle;
#[cfg(all(feature = "__dnssec", feature = "metrics"))]
use handle::RecursorMetrics;

#[cfg(test)]
mod tests;

/// A top down recursive resolver which operates off a list of roots for initial recursive requests.
///
/// This is the well known root nodes, referred to as hints in RFCs. See the IANA [Root Servers](https://www.iana.org/domains/root/servers) list.
pub struct Recursor<P: ConnectionProvider> {
    pub(super) mode: RecursorMode<P>,
}

#[cfg(feature = "tokio")]
impl Recursor<TokioRuntimeProvider> {}

impl<P: ConnectionProvider> Recursor<P> {
    /// Build a new [`Recursor`] from the specified configuration
    #[cfg(feature = "serde")]
    pub fn from_config(
        config: &RecursiveConfig,
        root_dir: Option<&Path>,
        conn_provider: P,
    ) -> Result<Self, RecursorError> {
        let dnssec_policy =
            DnssecPolicy::from_config(&config.dnssec_policy).map_err(|e| e.to_string())?;

        #[allow(unused_mut, unused_assignments)]
        let mut encrypted_transport_state = None;
        #[cfg(all(feature = "toml", any(feature = "__tls", feature = "__quic")))]
        {
            // Before building the recursor, potentially load some pre-existing opportunistic encrypted
            // nameserver state to configure on the builder.
            encrypted_transport_state =
                config.options.opportunistic_encryption.persisted_state()?;
        }

        let path = match root_dir {
            Some(root_dir) => Cow::Owned(root_dir.join(&config.roots)),
            None => Cow::Borrowed(&config.roots),
        };

        let roots_str = fs::read_to_string(path.as_ref())?;
        let (_zone, roots_zone) =
            Parser::new(roots_str, Some(path.into_owned()), Some(Name::root()))
                .parse()
                .map_err(|e| format!("failed to read roots {}: {e}", config.roots.display()))?;

        let root_addrs = roots_zone
            .values()
            .flat_map(RecordSet::records_without_rrsigs)
            .map(Record::data)
            .filter_map(RData::ip_addr) // we only want IPs
            .collect::<Vec<_>>();

        Self::new(
            &root_addrs,
            dnssec_policy,
            encrypted_transport_state,
            config.options.clone(),
            conn_provider,
        )
    }

    /// Build a DNSSEC-unaware [`Recursor`] without any name server transport state
    pub fn with_options(
        roots: &[IpAddr],
        options: RecursorOptions,
        conn_provider: P,
    ) -> Result<Self, RecursorError> {
        Self::new(roots, DnssecPolicy::default(), None, options, conn_provider)
    }

    /// Build a new [`Recursor`]
    pub fn new(
        roots: &[IpAddr],
        dnssec_policy: DnssecPolicy,
        encrypted_transport_state: Option<NameServerTransportState>,
        options: RecursorOptions,
        conn_provider: P,
    ) -> Result<Self, RecursorError> {
        let mut tls_config = TlsConfig::new()?;
        if options.opportunistic_encryption.is_enabled() {
            warn!("disabling TLS peer verification for opportunistic encryption mode");
            tls_config.insecure_skip_verify();
        }

        #[cfg(feature = "__dnssec")]
        let response_cache_size = options.response_cache_size;
        #[cfg(feature = "__dnssec")]
        let ttl_config = options.cache_policy.clone();
        let handle = RecursorDnsHandle::new(
            roots,
            dnssec_policy.clone(),
            encrypted_transport_state,
            options,
            tls_config,
            conn_provider,
        )?;

        Ok(Self {
            mode: match dnssec_policy {
                DnssecPolicy::SecurityUnaware => RecursorMode::NonValidating { handle },
                #[cfg(feature = "__dnssec")]
                DnssecPolicy::ValidationDisabled => RecursorMode::NonValidating { handle },
                #[cfg(feature = "__dnssec")]
                DnssecPolicy::ValidateWithStaticKey(config) => RecursorMode::Validating(
                    ValidatingRecursor::new(handle, config, response_cache_size, ttl_config)?,
                ),
            },
        })
    }

    /// Perform a recursive resolution
    ///
    /// [RFC 1034](https://datatracker.ietf.org/doc/html/rfc1034#section-5.3.3), Domain Concepts and Facilities, November 1987
    ///
    /// ```text
    /// 5.3.3. Algorithm
    ///
    /// The top level algorithm has four steps:
    ///
    ///    1. See if the answer is in local information, and if so return
    ///       it to the client.
    ///
    ///    2. Find the best servers to ask.
    ///
    ///    3. Send them queries until one returns a response.
    ///
    ///    4. Analyze the response, either:
    ///
    ///          a. if the response answers the question or contains a name
    ///             error, cache the data as well as returning it back to
    ///             the client.
    ///
    ///          b. if the response contains a better delegation to other
    ///             servers, cache the delegation information, and go to
    ///             step 2.
    ///
    ///          c. if the response shows a CNAME and that is not the
    ///             answer itself, cache the CNAME, change the SNAME to the
    ///             canonical name in the CNAME RR and go to step 1.
    ///
    ///          d. if the response shows a servers failure or other
    ///             bizarre contents, delete the server from the SLIST and
    ///             go back to step 3.
    ///
    /// Step 1 searches the cache for the desired data. If the data is in the
    /// cache, it is assumed to be good enough for normal use.  Some resolvers
    /// have an option at the user interface which will force the resolver to
    /// ignore the cached data and consult with an authoritative server.  This
    /// is not recommended as the default.  If the resolver has direct access to
    /// a name server's zones, it should check to see if the desired data is
    /// present in authoritative form, and if so, use the authoritative data in
    /// preference to cached data.
    ///
    /// Step 2 looks for a name server to ask for the required data.  The
    /// general strategy is to look for locally-available name server RRs,
    /// starting at SNAME, then the parent domain name of SNAME, the
    /// grandparent, and so on toward the root.  Thus if SNAME were
    /// Mockapetris.ISI.EDU, this step would look for NS RRs for
    /// Mockapetris.ISI.EDU, then ISI.EDU, then EDU, and then . (the root).
    /// These NS RRs list the names of hosts for a zone at or above SNAME.  Copy
    /// the names into SLIST.  Set up their addresses using local data.  It may
    /// be the case that the addresses are not available.  The resolver has many
    /// choices here; the best is to start parallel resolver processes looking
    /// for the addresses while continuing onward with the addresses which are
    /// available.  Obviously, the design choices and options are complicated
    /// and a function of the local host's capabilities.  The recommended
    /// priorities for the resolver designer are:
    ///
    ///    1. Bound the amount of work (packets sent, parallel processes
    ///       started) so that a request can't get into an infinite loop or
    ///       start off a chain reaction of requests or queries with other
    ///       implementations EVEN IF SOMEONE HAS INCORRECTLY CONFIGURED
    ///       SOME DATA.
    ///
    ///    2. Get back an answer if at all possible.
    ///
    ///    3. Avoid unnecessary transmissions.
    ///
    ///    4. Get the answer as quickly as possible.
    ///
    /// If the search for NS RRs fails, then the resolver initializes SLIST from
    /// the safety belt SBELT.  The basic idea is that when the resolver has no
    /// idea what servers to ask, it should use information from a configuration
    /// file that lists several servers which are expected to be helpful.
    /// Although there are special situations, the usual choice is two of the
    /// root servers and two of the servers for the host's domain.  The reason
    /// for two of each is for redundancy.  The root servers will provide
    /// eventual access to all of the domain space.  The two local servers will
    /// allow the resolver to continue to resolve local names if the local
    /// network becomes isolated from the internet due to gateway or link
    /// failure.
    ///
    /// In addition to the names and addresses of the servers, the SLIST data
    /// structure can be sorted to use the best servers first, and to insure
    /// that all addresses of all servers are used in a round-robin manner.  The
    /// sorting can be a simple function of preferring addresses on the local
    /// network over others, or may involve statistics from past events, such as
    /// previous response times and batting averages.
    ///
    /// Step 3 sends out queries until a response is received.  The strategy is
    /// to cycle around all of the addresses for all of the servers with a
    /// timeout between each transmission.  In practice it is important to use
    /// all addresses of a multihomed host, and too aggressive a retransmission
    /// policy actually slows response when used by multiple resolvers
    /// contending for the same name server and even occasionally for a single
    /// resolver.  SLIST typically contains data values to control the timeouts
    /// and keep track of previous transmissions.
    ///
    /// Step 4 involves analyzing responses.  The resolver should be highly
    /// paranoid in its parsing of responses.  It should also check that the
    /// response matches the query it sent using the ID field in the response.
    ///
    /// The ideal answer is one from a server authoritative for the query which
    /// either gives the required data or a name error.  The data is passed back
    /// to the user and entered in the cache for future use if its TTL is
    /// greater than zero.
    ///
    /// If the response shows a delegation, the resolver should check to see
    /// that the delegation is "closer" to the answer than the servers in SLIST
    /// are.  This can be done by comparing the match count in SLIST with that
    /// computed from SNAME and the NS RRs in the delegation.  If not, the reply
    /// is bogus and should be ignored.  If the delegation is valid the NS
    /// delegation RRs and any address RRs for the servers should be cached.
    /// The name servers are entered in the SLIST, and the search is restarted.
    ///
    /// If the response contains a CNAME, the search is restarted at the CNAME
    /// unless the response has the data for the canonical name or if the CNAME
    /// is the answer itself.
    ///
    /// Details and implementation hints can be found in [RFC-1035].
    ///
    /// 6. A SCENARIO
    ///
    /// In our sample domain space, suppose we wanted separate administrative
    /// control for the root, MIL, EDU, MIT.EDU and ISI.EDU zones.  We might
    /// allocate name servers as follows:
    ///
    ///
    ///                                    |(C.ISI.EDU,SRI-NIC.ARPA
    ///                                    | A.ISI.EDU)
    ///              +---------------------+------------------+
    ///              |                     |                  |
    ///             MIL                   EDU                ARPA
    ///              |(SRI-NIC.ARPA,       |(SRI-NIC.ARPA,    |
    ///              | A.ISI.EDU           | C.ISI.EDU)       |
    ///        +-----+-----+               |     +------+-----+-----+
    ///        |     |     |               |     |      |           |
    ///       BRL  NOSC  DARPA             |  IN-ADDR  SRI-NIC     ACC
    ///                                    |
    ///        +--------+------------------+---------------+--------+
    ///        |        |                  |               |        |
    ///       UCI      MIT                 |              UDEL     YALE
    ///                 |(XX.LCS.MIT.EDU, ISI
    ///                 |ACHILLES.MIT.EDU) |(VAXA.ISI.EDU,VENERA.ISI.EDU,
    ///             +---+---+              | A.ISI.EDU)
    ///             |       |              |
    ///            LCS   ACHILLES +--+-----+-----+--------+
    ///             |             |  |     |     |        |
    ///             XX            A  C   VAXA  VENERA Mockapetris
    ///
    /// In this example, the authoritative name server is shown in parentheses
    /// at the point in the domain tree at which is assumes control.
    ///
    /// Thus the root name servers are on C.ISI.EDU, SRI-NIC.ARPA, and
    /// A.ISI.EDU.  The MIL domain is served by SRI-NIC.ARPA and A.ISI.EDU.  The
    /// EDU domain is served by SRI-NIC.ARPA. and C.ISI.EDU.  Note that servers
    /// may have zones which are contiguous or disjoint.  In this scenario,
    /// C.ISI.EDU has contiguous zones at the root and EDU domains.  A.ISI.EDU
    /// has contiguous zones at the root and MIL domains, but also has a non-
    /// contiguous zone at ISI.EDU.
    /// ```
    pub async fn resolve(
        &self,
        query: Query,
        request_time: Instant,
        query_has_dnssec_ok: bool,
    ) -> Result<Message, RecursorError> {
        if !query.name().is_fqdn() {
            return Err(RecursorError::from(
                "query's domain name must be fully qualified",
            ));
        }

        match &self.mode {
            RecursorMode::NonValidating { handle } => {
                handle
                    .resolve(
                        query,
                        request_time,
                        query_has_dnssec_ok,
                        0,
                        Arc::new(AtomicU8::new(0)),
                    )
                    .await
            }

            #[cfg(feature = "__dnssec")]
            RecursorMode::Validating(validating) => {
                validating
                    .resolve(query, request_time, query_has_dnssec_ok)
                    .await
            }
        }
    }

    /// Get the recursor's [`PoolContext`].
    pub fn pool_context(&self) -> &Arc<PoolContext> {
        match &self.mode {
            RecursorMode::NonValidating { handle, .. } => handle.pool_context(),
            #[cfg(feature = "__dnssec")]
            RecursorMode::Validating(validating) => validating.handle.inner().pool_context(),
        }
    }

    /// Whether the recursive resolver is a validating resolver
    pub fn is_validating(&self) -> bool {
        // matching on `NonValidating` to avoid conditional compilation (`#[cfg]`)
        !matches!(self.mode, RecursorMode::NonValidating { .. })
    }
}

#[allow(clippy::large_enum_variant)]
pub(super) enum RecursorMode<P: ConnectionProvider> {
    NonValidating {
        handle: RecursorDnsHandle<P>,
    },

    #[cfg(feature = "__dnssec")]
    Validating(ValidatingRecursor<P>),
}

#[cfg(feature = "__dnssec")]
pub(crate) struct ValidatingRecursor<P: ConnectionProvider> {
    pub(crate) handle: DnssecDnsHandle<RecursorDnsHandle<P>>,
    // This is a separate response cache from that inside `RecursorDnsHandle`.
    pub(crate) validated_response_cache: ResponseCache,
    #[cfg(feature = "metrics")]
    metrics: RecursorMetrics,
}

#[cfg(feature = "__dnssec")]
impl<P: ConnectionProvider> ValidatingRecursor<P> {
    pub(crate) fn new(
        handle: RecursorDnsHandle<P>,
        config: DnssecConfig,
        response_cache_size: u64,
        ttl_config: TtlConfig,
    ) -> Result<Self, RecursorError> {
        let validated_response_cache = ResponseCache::new(response_cache_size, ttl_config.clone());
        let trust_anchor = match config.trust_anchor {
            Some(anchor) if anchor.is_empty() => {
                return Err(RecursorError::from("trust anchor must not be empty"));
            }
            Some(anchor) => anchor,
            None => Arc::new(TrustAnchors::default()),
        };

        #[cfg(feature = "metrics")]
        let metrics = handle.metrics.clone();

        let mut handle = DnssecDnsHandle::with_trust_anchor(handle, trust_anchor)
            .nsec3_iteration_limits(
                config.nsec3_soft_iteration_limit,
                config.nsec3_hard_iteration_limit,
            )
            .negative_validation_ttl(ttl_config.negative_response_ttl_bounds(RecordType::RRSIG))
            .positive_validation_ttl(ttl_config.positive_response_ttl_bounds(RecordType::RRSIG));

        if let Some(validation_cache_size) = config.validation_cache_size {
            handle = handle.validation_cache_size(validation_cache_size);
        }

        Ok(Self {
            validated_response_cache,
            #[cfg(feature = "metrics")]
            metrics,
            handle,
        })
    }

    async fn resolve(
        &self,
        query: Query,
        request_time: Instant,
        query_has_dnssec_ok: bool,
    ) -> Result<Message, RecursorError> {
        if let Some(Ok(response)) = self.validated_response_cache.get(&query, request_time) {
            // Increment metrics on cache hits only. We will check the cache a second time
            // inside resolve(), thus we only track cache misses there.
            #[cfg(feature = "metrics")]
            self.metrics.cache_hit_counter.increment(1);

            let none_indeterminate = response
                .all_sections()
                .all(|record| !record.proof().is_indeterminate());

            // if the cached response is a referral, or if any record is indeterminate, fall
            // through and perform DNSSEC validation
            if response.authoritative() && none_indeterminate {
                return Ok(response.maybe_strip_dnssec_records(query_has_dnssec_ok));
            }
        }

        let mut options = DnsRequestOptions::default();
        // a validating recursor must be security aware
        options.use_edns = true;
        options.edns_set_dnssec_ok = true;

        let response = self
            .handle
            .lookup(query.clone(), options)
            .first_answer()
            .await?;

        // Return NXDomain and NoData responses in error form
        // These need to bypass the cache lookup (and casting to a Lookup object in general)
        // to preserve SOA and DNSSEC records, and to keep those records in the authorities
        // section of the response.
        if response.response_code() == ResponseCode::NXDomain {
            use crate::recursor::RecursorError;

            let Err(dns_error) = DnsError::from_response(response) else {
                return Err(RecursorError::from(
                    "unable to build ProtoError from response {response:?}",
                ));
            };

            Err(RecursorError::Net(NetError::from(dns_error)))
        } else if response.answers().is_empty()
            && !response.authorities().is_empty()
            && response.response_code() == ResponseCode::NoError
        {
            let mut no_records = NoRecords::new(query.clone(), ResponseCode::NoError);
            no_records.soa = response
                .soa()
                .as_ref()
                .map(|record| Box::new(record.to_owned()));
            no_records.authorities = Some(
                response
                    .authorities()
                    .iter()
                    .filter_map(|x| match x.record_type() {
                        RecordType::SOA => None,
                        _ => Some(x.clone()),
                    })
                    .collect(),
            );

            Err(RecursorError::from(NetError::from(no_records)))
        } else {
            let message = response.into_message();
            self.validated_response_cache
                .insert(query.clone(), Ok(message.clone()), request_time);
            Ok(message.maybe_strip_dnssec_records(query_has_dnssec_ok))
        }
    }
}

/// Configuration for recursive resolver zones
#[cfg(feature = "serde")]
#[derive(Clone, Deserialize, Eq, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub struct RecursiveConfig {
    /// File with roots, aka hints
    pub roots: PathBuf,
    /// DNSSEC policy
    #[serde(default)]
    pub dnssec_policy: DnssecPolicyConfig,
    /// Options for the recursor
    #[serde(flatten)]
    pub options: RecursorOptions,
}

/// Options for the [`Recursor`]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct RecursorOptions {
    /// Maximum nameserver cache size
    #[cfg_attr(feature = "serde", serde(default = "default_ns_cache_size"))]
    pub ns_cache_size: usize,

    /// Maximum DNS response cache size
    #[cfg_attr(
        feature = "serde",
        serde(default = "default_response_cache_size", alias = "record_cache_size")
    )]
    pub response_cache_size: u64,

    /// Maximum recursion depth for queries
    ///
    /// Setting to 0 will fail all requests requiring recursion.
    #[cfg_attr(feature = "serde", serde(default = "recursion_limit_default"))]
    pub recursion_limit: u8,

    /// Maximum recursion depth for building NS pools
    ///
    /// Setting to 0 will fail all requests requiring recursion.
    #[cfg_attr(feature = "serde", serde(default = "ns_recursion_limit_default"))]
    pub ns_recursion_limit: u8,

    /// Networks that will not be filtered from responses.  This overrides anything present in
    /// deny_answers
    #[cfg_attr(feature = "serde", serde(default))]
    pub allow_answers: Vec<IpNet>,

    /// Networks that will be filtered from responses
    #[cfg_attr(feature = "serde", serde(default))]
    pub deny_answers: Vec<IpNet>,

    /// Networks that will be queried during resolution
    #[cfg_attr(feature = "serde", serde(default))]
    pub allow_server: Vec<IpNet>,

    /// Networks that will not be queried during resolution
    #[cfg_attr(feature = "serde", serde(default = "deny_server_default"))]
    pub deny_server: Vec<IpNet>,

    /// Local UDP ports to avoid when making outgoing queries
    #[cfg_attr(feature = "serde", serde(default))]
    pub avoid_local_udp_ports: HashSet<u16>,

    /// Caching policy, setting minimum and maximum TTLs
    #[cfg_attr(feature = "serde", serde(default))]
    pub cache_policy: TtlConfig,

    /// Enable case randomization.
    ///
    /// Randomize the case of letters in query names, and require that responses preserve the case
    /// of the query name, in order to mitigate spoofing attacks. This is only applied over UDP.
    ///
    /// This implements the mechanism described in
    /// [draft-vixie-dnsext-dns0x20-00](https://datatracker.ietf.org/doc/html/draft-vixie-dnsext-dns0x20-00).
    #[cfg_attr(feature = "serde", serde(default))]
    pub case_randomization: bool,

    /// Configure RFC 9539 opportunistic encryption.
    #[cfg_attr(feature = "serde", serde(default))]
    pub opportunistic_encryption: OpportunisticEncryption,
}

impl Default for RecursorOptions {
    fn default() -> Self {
        Self {
            ns_cache_size: 1_024,
            response_cache_size: 1_048_576,
            recursion_limit: 24,
            ns_recursion_limit: 24,
            allow_answers: Vec::new(),
            deny_answers: Vec::new(),
            allow_server: Vec::new(),
            deny_server: RECOMMENDED_SERVER_FILTERS.to_vec(),
            avoid_local_udp_ports: HashSet::new(),
            cache_policy: TtlConfig::default(),
            case_randomization: false,
            opportunistic_encryption: OpportunisticEncryption::default(),
        }
    }
}

#[cfg(feature = "serde")]
fn default_ns_cache_size() -> usize {
    1_024
}

#[cfg(feature = "serde")]
fn default_response_cache_size() -> u64 {
    1_048_576
}

#[cfg(feature = "serde")]
fn recursion_limit_default() -> u8 {
    24
}

#[cfg(feature = "serde")]
fn ns_recursion_limit_default() -> u8 {
    24
}

#[cfg(feature = "serde")]
fn deny_server_default() -> Vec<IpNet> {
    RECOMMENDED_SERVER_FILTERS.to_vec()
}

/// `Recursor`'s DNSSEC policy
// `Copy` can only be implemented when `dnssec` is disabled we don't want to remove a trait
// implementation when a feature is enabled as features are meant to be additive
#[derive(Clone, Default)]
pub enum DnssecPolicy {
    /// security unaware; DNSSEC records will not be requested nor processed
    #[default]
    SecurityUnaware,

    /// DNSSEC validation is disabled; DNSSEC records will be requested and processed
    #[cfg(feature = "__dnssec")]
    ValidationDisabled,

    /// DNSSEC validation is enabled and will use the chosen `trust_anchor` set of keys
    #[cfg(feature = "__dnssec")]
    ValidateWithStaticKey(DnssecConfig),
    // TODO RFC5011
    // ValidateWithInitialKey { ..  },}
}

impl DnssecPolicy {
    #[cfg(feature = "serde")]
    fn from_config(config: &DnssecPolicyConfig) -> Result<Self, ParseError> {
        Ok(match config {
            DnssecPolicyConfig::SecurityUnaware => Self::SecurityUnaware,
            #[cfg(feature = "__dnssec")]
            DnssecPolicyConfig::ValidationDisabled => Self::ValidationDisabled,
            #[cfg(feature = "__dnssec")]
            DnssecPolicyConfig::ValidateWithStaticKey {
                path,
                nsec3_soft_iteration_limit,
                nsec3_hard_iteration_limit,
                validation_cache_size,
            } => Self::ValidateWithStaticKey(DnssecConfig {
                trust_anchor: path
                    .as_ref()
                    .map(|path| TrustAnchors::from_file(path))
                    .transpose()?
                    .map(Arc::new),
                nsec3_soft_iteration_limit: *nsec3_soft_iteration_limit,
                nsec3_hard_iteration_limit: *nsec3_hard_iteration_limit,
                validation_cache_size: *validation_cache_size,
            }),
        })
    }

    pub(crate) fn is_security_aware(&self) -> bool {
        !matches!(self, Self::SecurityUnaware)
    }
}

/// DNSSEC configuration options for use in [`DnssecPolicy`]
#[cfg(feature = "__dnssec")]
#[non_exhaustive]
#[derive(Clone, Default)]
pub struct DnssecConfig {
    /// set to `None` to use built-in trust anchor
    pub trust_anchor: Option<Arc<TrustAnchors>>,
    /// NSEC3 soft iteration limit.  Responses with NSEC3 records having an iteration count
    /// exceeding this value, but less than the hard limit, will return Proof::Insecure
    pub nsec3_soft_iteration_limit: Option<u16>,
    /// NSEC3 hard iteration limit.  Responses with NSEC3 responses having an iteration count
    /// exceeding this value will return Proof::Bogus
    pub nsec3_hard_iteration_limit: Option<u16>,
    /// Validation cache size.  Controls how many DNSSEC validations are cached for future
    /// use.
    pub validation_cache_size: Option<usize>,
}

/// DNSSEC policy configuration
#[cfg(feature = "serde")]
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
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

/// Bailiwick/sub zone checking.
///
/// # Overview
///
/// This function checks that two host names have a parent/child relationship, but does so more strictly than elsewhere in the libraries
/// (see implementation notes.)
///
/// A resolver should not return answers outside of its delegated authority -- if we receive a delegation from the root servers for
/// "example.com", that server should only return answers related to example.com or a sub-domain thereof.  Note that record data may point
/// to out-of-bailwick records (e.g., example.com could return a CNAME record for www.example.com that points to example.cdnprovider.net,)
/// but it should not return a record name that is out-of-bailiwick (e.g., we ask for www.example.com and it returns www.otherdomain.com.)
///
/// Out-of-bailiwick responses have been used in cache poisoning attacks.
///
/// ## Examples
///
/// | Parent       | Child                | Expected Result                                                  |
/// |--------------|----------------------|------------------------------------------------------------------|
/// | .            | com.                 | In-bailiwick (true)                                              |
/// | com.         | example.net.         | Out-of-bailiwick (false)                                         |
/// | example.com. | www.example.com.     | In-bailiwick (true)                                              |
/// | example.com. | www.otherdomain.com. | Out-of-bailiwick (false)                                         |
/// | example.com  | www.example.com.     | Out-of-bailiwick (false, note the parent is not fully qualified) |
///
/// # Implementation Notes
///
/// * This function is nominally a wrapper around Name::zone_of, with two additional checks:
/// * If the caller doesn't provide a parent at all, we'll return false.
/// * If the domains have mixed qualification -- that is, if one is fully-qualified and the other partially-qualified, we'll return
///   false.
///
/// # References
///
/// * [RFC 8499](https://datatracker.ietf.org/doc/html/rfc8499) -- DNS Terminology (see page 25)
/// * [The Hitchiker's Guide to DNS Cache Poisoning](https://www.cs.utexas.edu/%7Eshmat/shmat_securecomm10.pdf) -- for a more in-depth
///   discussion of DNS cache poisoning attacks, see section 4, specifically, for a discussion of the Bailiwick rule.
fn is_subzone(parent: &Name, child: &Name) -> bool {
    if parent.is_empty() {
        return false;
    }

    if (parent.is_fqdn() && !child.is_fqdn()) || (!parent.is_fqdn() && child.is_fqdn()) {
        return false;
    }

    parent.zone_of(child)
}

const RECOMMENDED_SERVER_FILTERS: [IpNet; 22] = [
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8), // Loopback range
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8),       // Unspecified range
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::BROADCAST), 32),        // Directed Broadcast
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),  // RFC 1918 space
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12), // RFC 1918 space
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16), // RFC 1918 space
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10), // CG NAT
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), 16), // Link-local space
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 0)), 24), // IETF Reserved
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24), // TEST-NET-1
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)), 24), // TEST-NET-2
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)), 24), // TEST-NET-3
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 0)), 4), // Class E Reserved
    IpNet::new_assert(IpAddr::V6(Ipv6Addr::LOCALHOST), 128),       // v6 loopback
    IpNet::new_assert(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 128),     // v6 unspecified
    IpNet::new_assert(IpAddr::V6(Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0)), 64), // v6 discard prefix
    IpNet::new_assert(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
        32,
    ), // v6 documentation prefix
    IpNet::new_assert(IpAddr::V6(Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0)), 20), // v6 documentation prefix
    IpNet::new_assert(IpAddr::V6(Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0)), 16), // v6 segment routing prefix
    IpNet::new_assert(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)), 7), // v6 private address,
    IpNet::new_assert(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), 64), // v6 link local
    IpNet::new_assert(IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0)), 8), // v6 multicast
];
