// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{collections::HashSet, sync::Arc, time::Instant};

use ipnet::IpNet;

#[cfg(feature = "dnssec")]
use crate::{
    proto::{
        error::ProtoError,
        op::ResponseCode,
        rr::{resource::RecordRef, Record, RecordType},
        xfer::{DnsHandle as _, DnsRequestOptions, DnssecDnsHandle, FirstAnswer as _},
    },
    resolver::dns_lru::DnsLru,
    resolver::error::ResolveErrorKind,
    ErrorKind,
};

use crate::{
    proto::op::Query,
    recursor_dns_handle::RecursorDnsHandle,
    resolver::{config::NameServerConfigGroup, error::ResolveError, lookup::Lookup},
    DnssecPolicy, Error,
};

/// A `Recursor` builder
#[derive(Clone)]
pub struct RecursorBuilder {
    ns_cache_size: usize,
    record_cache_size: usize,
    /// This controls how many nested lookups will be attempted to resolve a CNAME chain. Setting it
    /// to None will disable the recursion limit check, and is not recommended.
    recursion_limit: Option<u8>,
    /// This controls how many nested lookups will be attempted when trying to build an NS pool.
    /// Setting it to None will disable the recursion limit check, and is not recommended.
    ns_recursion_limit: Option<u8>,
    dnssec_policy: DnssecPolicy,
    do_not_query: Vec<IpNet>,
    avoid_local_udp_ports: HashSet<u16>,
}

impl RecursorBuilder {
    /// Sets the size of the list of cached name servers
    pub fn ns_cache_size(&mut self, size: usize) -> &mut Self {
        self.ns_cache_size = size;
        self
    }

    /// Sets the size of the list of cached records
    pub fn record_cache_size(&mut self, size: usize) -> &mut Self {
        self.record_cache_size = size;
        self
    }

    /// Sets the maximum recursion depth for queries; set to 0 for unlimited
    /// recursion.
    pub fn recursion_limit(&mut self, limit: Option<u8>) -> &mut Self {
        self.recursion_limit = limit;
        self
    }

    /// Sets the maximum recursion depth for building NS pools; set to 0 for unlimited
    /// recursion.
    pub fn ns_recursion_limit(&mut self, limit: Option<u8>) -> &mut Self {
        self.ns_recursion_limit = limit;
        self
    }

    /// Sets the DNSSEC policy
    pub fn dnssec_policy(&mut self, dnssec_policy: DnssecPolicy) -> &mut Self {
        self.dnssec_policy = dnssec_policy;
        self
    }

    /// Add networks that should not be queried during recursive resolution
    pub fn do_not_query(&mut self, networks: &[IpNet]) -> &mut Self {
        self.do_not_query.extend(networks.iter().copied());
        self
    }

    /// Sets local UDP ports that should be avoided when making outgoing queries
    pub fn avoid_local_udp_ports(&mut self, ports: HashSet<u16>) -> &mut Self {
        self.avoid_local_udp_ports = ports;
        self
    }

    /// Construct a new recursor using the list of NameServerConfigs for the root node list
    ///
    /// # Panics
    ///
    /// This will panic if the roots are empty.
    pub fn build(&self, roots: impl Into<NameServerConfigGroup>) -> Result<Recursor, ResolveError> {
        Recursor::build(
            roots,
            self.ns_cache_size,
            self.record_cache_size,
            self.recursion_limit,
            self.ns_recursion_limit,
            self.dnssec_policy.clone(),
            self.do_not_query.clone(),
            self.avoid_local_udp_ports.clone(),
        )
    }
}

/// A top down recursive resolver which operates off a list of roots for initial recursive requests.
///
/// This is the well known root nodes, referred to as hints in RFCs. See the IANA [Root Servers](https://www.iana.org/domains/root/servers) list.
pub struct Recursor {
    mode: RecursorMode,
}

impl Recursor {
    /// Construct the new [`Recursor`] via the [`RecursorBuilder`]
    pub fn builder() -> RecursorBuilder {
        RecursorBuilder::default()
    }

    /// Whether the recursive resolver is a validating resolver
    pub fn is_validating(&self) -> bool {
        // matching on `NonValidating` to avoid conditional compilation (`#[cfg]`)
        !matches!(self.mode, RecursorMode::NonValidating { .. })
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        roots: impl Into<NameServerConfigGroup>,
        ns_cache_size: usize,
        record_cache_size: usize,
        recursion_limit: Option<u8>,
        ns_recursion_limit: Option<u8>,
        dnssec_policy: DnssecPolicy,
        do_not_query: Vec<IpNet>,
        avoid_local_udp_ports: HashSet<u16>,
    ) -> Result<Self, ResolveError> {
        let handle = RecursorDnsHandle::new(
            roots,
            ns_cache_size,
            record_cache_size,
            recursion_limit,
            ns_recursion_limit,
            dnssec_policy.is_security_aware(),
            do_not_query,
            Arc::new(avoid_local_udp_ports),
        )?;

        let mode = match dnssec_policy {
            DnssecPolicy::SecurityUnaware => RecursorMode::NonValidating { handle },

            #[cfg(feature = "dnssec")]
            DnssecPolicy::ValidationDisabled => RecursorMode::NonValidating { handle },

            #[cfg(feature = "dnssec")]
            DnssecPolicy::ValidateWithStaticKey { trust_anchor } => {
                let record_cache = handle.record_cache().clone();
                let handle = if let Some(trust_anchor) = trust_anchor {
                    if trust_anchor.is_empty() {
                        return Err(ResolveError::from(ResolveErrorKind::Message(
                            "trust anchor must not be empty",
                        )));
                    }

                    DnssecDnsHandle::with_trust_anchor(handle, trust_anchor.clone())
                } else {
                    DnssecDnsHandle::new(handle)
                };

                RecursorMode::Validating {
                    record_cache,
                    handle,
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
    ) -> Result<Lookup, Error> {
        if !query.name().is_fqdn() {
            return Err(Error::from("query's domain name must be fully qualified"));
        }

        match &self.mode {
            RecursorMode::NonValidating { handle } => {
                handle
                    .resolve(query, request_time, query_has_dnssec_ok, 0)
                    .await
            }

            #[cfg(feature = "dnssec")]
            RecursorMode::Validating {
                handle,
                record_cache,
            } => {
                if let Some(Ok(lookup)) = record_cache.get(&query, request_time) {
                    let none_indeterminate = lookup
                        .records()
                        .iter()
                        .all(|record| !record.proof().is_indeterminate());

                    // if any cached record is indeterminate, fall through and perform
                    // DNSSEC validation
                    if none_indeterminate {
                        return Ok(super::maybe_strip_dnssec_records(
                            query_has_dnssec_ok,
                            lookup,
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
                    let Err(proto_err) = ProtoError::from_response(response, true) else {
                        return Err(Error::from(
                            "unable to build ProtoError from response {response:?}",
                        ));
                    };

                    Err(Error {
                        kind: Box::new(ErrorKind::Proto(proto_err)),
                        #[cfg(feature = "backtrace")]
                        backtrack: None,
                    })
                } else if response.answers().is_empty()
                    && !response.name_servers().is_empty()
                    && response.response_code() == ResponseCode::NoError
                {
                    let authorities = response
                        .name_servers()
                        .iter()
                        .filter_map(|x| match x.record_type() {
                            RecordType::SOA => None,
                            _ => Some(x.clone()),
                        })
                        .collect::<Arc<[Record]>>();

                    let soa = response.soa().as_ref().map(RecordRef::to_owned);

                    Err(Error {
                        kind: Box::new(ErrorKind::Proto(ProtoError::nx_error(
                            Box::new(query),
                            soa.map(Box::new),
                            None,
                            None,
                            ResponseCode::NoError,
                            true,
                            Some(authorities),
                        ))),
                        #[cfg(feature = "backtrace")]
                        backtrack: None,
                    })
                } else {
                    // do not perform is_subzone filtering as it already happened in `handle.lookup`
                    let no_subzone_filtering = None;
                    let lookup = super::cache_response(
                        response,
                        no_subzone_filtering,
                        record_cache,
                        query.clone(),
                        request_time,
                    )?;
                    Ok(super::maybe_strip_dnssec_records(
                        query_has_dnssec_ok,
                        lookup,
                        query,
                    ))
                }
            }
        }
    }
}

impl Default for RecursorBuilder {
    fn default() -> Self {
        Self {
            ns_cache_size: 1_024,
            record_cache_size: 1_048_576,
            // This default is based on CNAME recursion failures of long (> 8 records) CNAME chains
            // that users of Unbound encountered (see https://github.com/NLnetLabs/unbound/issues/438)
            // with a small safety margin added.
            recursion_limit: Some(12),
            ns_recursion_limit: Some(16),
            dnssec_policy: DnssecPolicy::SecurityUnaware,
            do_not_query: vec![],
            avoid_local_udp_ports: HashSet::new(),
        }
    }
}

enum RecursorMode {
    NonValidating {
        handle: RecursorDnsHandle,
    },

    #[cfg(feature = "dnssec")]
    Validating {
        handle: DnssecDnsHandle<RecursorDnsHandle>,
        // this is a handle to the record cache in `RecursorDnsHandle`; not a whole separate cache
        record_cache: DnsLru,
    },
}

#[cfg(feature = "dnssec")]
mod for_dnssec {
    use std::time::Instant;

    use futures_util::{
        future,
        stream::{self, BoxStream},
        StreamExt as _, TryFutureExt as _,
    };

    use crate::proto::{
        error::ProtoError,
        op::{Message, OpCode},
        xfer::DnsHandle,
        xfer::DnsResponse,
    };
    use crate::recursor_dns_handle::RecursorDnsHandle;
    use crate::ErrorKind;

    impl DnsHandle for RecursorDnsHandle {
        type Response = BoxStream<'static, Result<DnsResponse, ProtoError>>;

        fn send<R: Into<hickory_proto::xfer::DnsRequest> + Unpin + Send + 'static>(
            &self,
            request: R,
        ) -> Self::Response {
            let request = request.into();

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

                this.resolve(query, Instant::now(), do_bit, 0)
                    .map_ok(|lookup| {
                        // `DnssecDnsHandle` will only look at the answer section of the message so
                        // we can put "stubs" in the other fields
                        let mut msg = Message::new();

                        // XXX this effectively merges the original nameservers and additional
                        // sections into the answers section
                        msg.add_answers(lookup.records().iter().cloned());

                        DnsResponse::new(msg, vec![])
                    })
                    .map_err(|e| match e.kind() {
                        // Translate back into a ProtoError::NoRecordsFound
                        ErrorKind::Forward(_fwd) => e.into(),
                        _ => ProtoError::from(e.to_string()),
                    })
                    .await
            })
            .boxed()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn not_fully_qualified_domain_name_in_query() -> Result<(), Error> {
        use crate::{proto::rr::RecordType, resolver::Name};

        let recursor = Recursor::builder().build(NameServerConfigGroup::cloudflare())?;
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
