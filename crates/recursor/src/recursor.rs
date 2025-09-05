// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, atomic::AtomicU8},
    time::Instant,
};

use ipnet::IpNet;

#[cfg(all(feature = "__dnssec", feature = "metrics"))]
use crate::recursor_dns_handle::RecursorCacheMetrics;
use crate::{
    DnssecPolicy, Error,
    proto::{
        op::{Message, Query},
        runtime::TokioRuntimeProvider,
    },
    recursor_dns_handle::RecursorDnsHandle,
    resolver::{
        TtlConfig,
        name_server::{ConnectionProvider, TlsConfig},
    },
};
#[cfg(feature = "__dnssec")]
use crate::{
    ErrorKind,
    proto::{
        DnsError, NoRecords, ProtoError,
        dnssec::{DnssecDnsHandle, TrustAnchors},
        op::{DnsRequestOptions, ResponseCode},
        rr::RecordType,
        xfer::{DnsHandle as _, FirstAnswer as _},
    },
    resolver::ResponseCache,
};

/// A `Recursor` builder
#[derive(Clone)]
pub struct RecursorBuilder<P: ConnectionProvider> {
    ns_cache_size: usize,
    response_cache_size: u64,
    /// This controls how many nested lookups will be attempted to resolve a CNAME chain. Setting it
    /// to None will disable the recursion limit check, and is not recommended.
    recursion_limit: Option<u8>,
    /// This controls how many nested lookups will be attempted when trying to build an NS pool.
    /// Setting it to None will disable the recursion limit check, and is not recommended.
    ns_recursion_limit: Option<u8>,
    dnssec_policy: DnssecPolicy,
    allow_servers: Vec<IpNet>,
    deny_servers: Vec<IpNet>,
    avoid_local_udp_ports: HashSet<u16>,
    ttl_config: TtlConfig,
    case_randomization: bool,
    conn_provider: P,
}

impl<P: ConnectionProvider> RecursorBuilder<P> {
    /// Sets the size of the list of cached name servers
    pub fn ns_cache_size(mut self, size: usize) -> Self {
        self.ns_cache_size = size;
        self
    }

    /// Sets the size of the list of cached responses
    pub fn response_cache_size(mut self, size: u64) -> Self {
        self.response_cache_size = size;
        self
    }

    /// Sets the maximum recursion depth for queries; set to None for unlimited
    /// recursion.
    pub fn recursion_limit(mut self, limit: Option<u8>) -> Self {
        self.recursion_limit = limit;
        self
    }

    /// Sets the maximum recursion depth for building NS pools; set to None for unlimited
    /// recursion.
    pub fn ns_recursion_limit(mut self, limit: Option<u8>) -> Self {
        self.ns_recursion_limit = limit;
        self
    }

    /// Sets the DNSSEC policy
    pub fn dnssec_policy(mut self, dnssec_policy: DnssecPolicy) -> Self {
        self.dnssec_policy = dnssec_policy;
        self
    }

    /// Clear the networks that should not be queried during recursive resolution.
    ///
    /// This will remove the default recommended filters and should be used with care.
    pub fn clear_nameserver_filter(mut self) -> Self {
        self.allow_servers.clear();
        self.deny_servers.clear();
        self
    }

    /// Add additional networks that should not be queried during recursive resolution
    pub fn nameserver_filter<'a>(
        mut self,
        allow: impl Iterator<Item = &'a IpNet>,
        deny: impl Iterator<Item = &'a IpNet>,
    ) -> Self {
        self.allow_servers.extend(allow);
        self.deny_servers.extend(deny);
        self
    }

    /// Sets local UDP ports that should be avoided when making outgoing queries
    pub fn avoid_local_udp_ports(mut self, ports: HashSet<u16>) -> Self {
        self.avoid_local_udp_ports = ports;
        self
    }

    /// Sets the minimum and maximum TTL values for cached responses
    pub fn ttl_config(mut self, ttl_config: TtlConfig) -> Self {
        self.ttl_config = ttl_config;
        self
    }

    /// Enable case randomization.
    ///
    /// Sets whether to randomize the case of letters in query names, and require that responses
    /// preserve the case.
    pub fn case_randomization(mut self, case_randomization: bool) -> Self {
        self.case_randomization = case_randomization;
        self
    }

    /// Construct a new recursor using the list of root zone name server addresses
    ///
    /// # Panics
    ///
    /// This will panic if the roots are empty.
    pub fn build(self, roots: &[IpAddr]) -> Result<Recursor<P>, Error> {
        Recursor::build(roots, self)
    }
}

/// A top down recursive resolver which operates off a list of roots for initial recursive requests.
///
/// This is the well known root nodes, referred to as hints in RFCs. See the IANA [Root Servers](https://www.iana.org/domains/root/servers) list.
pub struct Recursor<P: ConnectionProvider> {
    mode: RecursorMode<P>,
}

impl Recursor<TokioRuntimeProvider> {
    /// Construct a new [`Recursor`] via the [`RecursorBuilder`].
    ///
    /// This uses the Tokio async runtime. To use a different runtime provider, see
    /// [`Recursor::builder_with_provider`].
    pub fn builder() -> RecursorBuilder<TokioRuntimeProvider> {
        Self::builder_with_provider(TokioRuntimeProvider::default())
    }
}

impl<P: ConnectionProvider> Recursor<P> {
    /// Construct a new [`Recursor`] via the [`RecursorBuilder`].
    pub fn builder_with_provider(conn_provider: P) -> RecursorBuilder<P> {
        RecursorBuilder {
            ns_cache_size: 1_024,
            response_cache_size: 1_048_576,
            recursion_limit: Some(24),
            ns_recursion_limit: Some(24),
            dnssec_policy: DnssecPolicy::SecurityUnaware,
            allow_servers: vec![],
            deny_servers: RECOMMENDED_SERVER_FILTERS.to_vec(),
            avoid_local_udp_ports: HashSet::new(),
            ttl_config: TtlConfig::default(),
            case_randomization: false,
            conn_provider,
        }
    }

    /// Whether the recursive resolver is a validating resolver
    pub fn is_validating(&self) -> bool {
        // matching on `NonValidating` to avoid conditional compilation (`#[cfg]`)
        !matches!(self.mode, RecursorMode::NonValidating { .. })
    }

    fn build(roots: &[IpAddr], builder: RecursorBuilder<P>) -> Result<Self, Error> {
        let RecursorBuilder {
            ns_cache_size,
            response_cache_size,
            recursion_limit,
            ns_recursion_limit,
            dnssec_policy,
            allow_servers,
            deny_servers,
            avoid_local_udp_ports,
            ttl_config,
            case_randomization,
            conn_provider,
        } = builder;

        let handle = RecursorDnsHandle::new(
            roots,
            ns_cache_size,
            response_cache_size,
            recursion_limit,
            ns_recursion_limit,
            dnssec_policy.is_security_aware(),
            allow_servers,
            deny_servers,
            Arc::new(avoid_local_udp_ports),
            ttl_config.clone(),
            case_randomization,
            Arc::new(TlsConfig::new()?),
            conn_provider,
        );

        let mode = match dnssec_policy {
            DnssecPolicy::SecurityUnaware => RecursorMode::NonValidating { handle },

            #[cfg(feature = "__dnssec")]
            DnssecPolicy::ValidationDisabled => RecursorMode::NonValidating { handle },

            #[cfg(feature = "__dnssec")]
            DnssecPolicy::ValidateWithStaticKey {
                trust_anchor,
                nsec3_soft_iteration_limit,
                nsec3_hard_iteration_limit,
            } => {
                let validated_response_cache = ResponseCache::new(response_cache_size, ttl_config);
                let trust_anchor = match trust_anchor {
                    Some(anchor) if anchor.is_empty() => {
                        return Err(Error::from("trust anchor must not be empty"));
                    }
                    Some(anchor) => anchor,
                    None => Arc::new(TrustAnchors::default()),
                };

                RecursorMode::Validating {
                    validated_response_cache,
                    #[cfg(feature = "metrics")]
                    cache_metrics: handle.cache_metrics().clone(),
                    handle: DnssecDnsHandle::with_trust_anchor(handle, trust_anchor)
                        .nsec3_iteration_limits(
                            nsec3_soft_iteration_limit,
                            nsec3_hard_iteration_limit,
                        ),
                }
            }
        };

        Ok(Self { mode })
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
    ) -> Result<Message, Error> {
        if !query.name().is_fqdn() {
            return Err(Error::from("query's domain name must be fully qualified"));
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
            RecursorMode::Validating {
                handle,
                validated_response_cache,
                #[cfg(feature = "metrics")]
                cache_metrics,
            } => {
                if let Some(Ok(response)) = validated_response_cache.get(&query, request_time) {
                    // Increment metrics on cache hits only. We will check the cache a second time
                    // inside resolve(), thus we only track cache misses there.
                    #[cfg(feature = "metrics")]
                    cache_metrics.cache_hit_counter.increment(1);

                    let none_indeterminate = response
                        .all_sections()
                        .all(|record| !record.proof().is_indeterminate());

                    // if the cached response is a referral, or if any record is indeterminate, fall
                    // through and perform DNSSEC validation
                    if response.authoritative() && none_indeterminate {
                        return Ok(super::maybe_strip_dnssec_records(
                            query_has_dnssec_ok,
                            response,
                            query,
                        ));
                    }
                }

                let mut options = DnsRequestOptions::default();
                // a validating recursor must be security aware
                options.use_edns = true;
                options.edns_set_dnssec_ok = true;

                let response = handle.lookup(query.clone(), options).first_answer().await?;

                // Return NXDomain and NoData responses in error form
                // These need to bypass the cache lookup (and casting to a Lookup object in general)
                // to preserve SOA and DNSSEC records, and to keep those records in the authorities
                // section of the response.
                if response.response_code() == ResponseCode::NXDomain {
                    let Err(dns_error) = DnsError::from_response(response) else {
                        return Err(Error::from(
                            "unable to build ProtoError from response {response:?}",
                        ));
                    };

                    Err(Error {
                        kind: ErrorKind::Proto(ProtoError::from(dns_error)),
                        #[cfg(feature = "backtrace")]
                        backtrack: None,
                    })
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

                    Err(Error::from(ProtoError::from(no_records)))
                } else {
                    let message = response.into_message();
                    validated_response_cache.insert(
                        query.clone(),
                        Ok(message.clone()),
                        request_time,
                    );
                    Ok(super::maybe_strip_dnssec_records(
                        query_has_dnssec_ok,
                        message,
                        query,
                    ))
                }
            }
        }
    }
}

enum RecursorMode<P: ConnectionProvider> {
    NonValidating {
        handle: RecursorDnsHandle<P>,
    },

    #[cfg(feature = "__dnssec")]
    Validating {
        handle: DnssecDnsHandle<RecursorDnsHandle<P>>,
        // This is a separate response cache from that inside `RecursorDnsHandle`.
        validated_response_cache: ResponseCache,
        #[cfg(feature = "metrics")]
        cache_metrics: RecursorCacheMetrics,
    },
}

#[cfg(feature = "__dnssec")]
mod for_dnssec {
    use std::{
        sync::{Arc, atomic::AtomicU8},
        time::Instant,
    };

    use futures_util::{
        StreamExt as _, future,
        stream::{self, BoxStream},
    };

    use crate::ErrorKind;
    use crate::proto::{
        ProtoError,
        op::{DnsRequest, DnsResponse, Message, OpCode},
        xfer::DnsHandle,
    };
    use crate::recursor_dns_handle::RecursorDnsHandle;
    use crate::resolver::name_server::ConnectionProvider;

    impl<P: ConnectionProvider> DnsHandle for RecursorDnsHandle<P> {
        type Response = BoxStream<'static, Result<DnsResponse, ProtoError>>;
        type Runtime = P::RuntimeProvider;

        fn send(&self, request: DnsRequest) -> Self::Response {
            let query = if let OpCode::Query = request.op_code() {
                if let Some(query) = request.queries().first().cloned() {
                    query
                } else {
                    return Box::pin(stream::once(future::err(ProtoError::from(
                        "no query in request",
                    ))));
                }
            } else {
                return Box::pin(stream::once(future::err(ProtoError::from(
                    "request is not a query",
                ))));
            };

            let this = self.clone();
            stream::once(async move {
                // request the DNSSEC records; we'll strip them if not needed on the caller side
                let do_bit = true;

                let future =
                    this.resolve(query, Instant::now(), do_bit, 0, Arc::new(AtomicU8::new(0)));
                let response = match future.await {
                    Ok(response) => response,
                    Err(e) => {
                        return Err(match e.kind() {
                            // Translate back into a ProtoError::NoRecordsFound
                            ErrorKind::Negative(_fwd) => e.into(),
                            _ => ProtoError::from(e.to_string()),
                        });
                    }
                };

                // `DnssecDnsHandle` will only look at the answer section of the message so
                // we can put "stubs" in the other fields
                let mut msg = Message::query();

                msg.add_answers(response.answers().iter().cloned());
                msg.add_authorities(response.authorities().iter().cloned());
                msg.add_additionals(response.additionals().iter().cloned());

                DnsResponse::from_message(msg)
            })
            .boxed()
        }
    }
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

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, time::Instant};

    use test_support::subscribe;

    use crate::{
        Error, Recursor,
        proto::{op::Query, rr::RecordType},
        resolver::Name,
    };

    #[tokio::test]
    async fn not_fully_qualified_domain_name_in_query() -> Result<(), Error> {
        subscribe();

        let j_root_servers_net_ip = IpAddr::from([192, 58, 128, 30]);
        let recursor = Recursor::builder().build(&[j_root_servers_net_ip])?;
        let name = Name::from_ascii("example.com")?;
        assert!(!name.is_fqdn());
        let query = Query::query(name, RecordType::A);
        let res = recursor
            .resolve(query, Instant::now(), false)
            .await
            .unwrap_err();
        assert!(res.to_string().contains("fully qualified"));

        Ok(())
    }
}
