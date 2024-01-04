// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{net::SocketAddr, time::Instant};

use async_recursion::async_recursion;
use futures_util::{future::select_all, FutureExt};
use hickory_resolver::name_server::TokioConnectionProvider;
use lru_cache::LruCache;
use parking_lot::Mutex;
use tracing::{debug, info, warn};

#[cfg(test)]
use std::str::FromStr;

use crate::{
    proto::{
        op::Query,
        rr::{RData, RecordType},
    },
    recursor_pool::RecursorPool,
    resolver::{
        config::{NameServerConfig, NameServerConfigGroup, Protocol, ResolverOpts},
        dns_lru::{DnsLru, TtlConfig},
        error::ResolveError,
        lookup::Lookup,
        name_server::{GenericNameServerPool, TokioRuntimeProvider},
        Name,
    },
    Error, ErrorKind,
};

/// Set of nameservers by the zone name
type NameServerCache<P> = LruCache<Name, RecursorPool<P>>;

/// A top down recursive resolver which operates off a list of roots for initial recursive requests.
///
/// This is the well known root nodes, referred to as hints in RFCs. See the IANA [Root Servers](https://www.iana.org/domains/root/servers) list.
pub struct Recursor {
    roots: RecursorPool<TokioRuntimeProvider>,
    name_server_cache: Mutex<NameServerCache<TokioRuntimeProvider>>,
    record_cache: DnsLru,
}

impl Recursor {
    /// Construct a new recursor using the list of NameServerConfigs for the root node list
    ///
    /// # Panics
    ///
    /// This will panic if the roots are empty.
    pub fn new(
        roots: impl Into<NameServerConfigGroup>,
        ns_cache_size: usize,
        record_cache_size: usize,
    ) -> Result<Self, ResolveError> {
        // configure the hickory-resolver
        let roots: NameServerConfigGroup = roots.into();

        assert!(!roots.is_empty(), "roots must not be empty");

        debug!("Using cache sizes {}/{}", ns_cache_size, record_cache_size);
        let opts = recursor_opts();
        let roots =
            GenericNameServerPool::from_config(roots, opts, TokioConnectionProvider::default());
        let roots = RecursorPool::from(Name::root(), roots);
        let name_server_cache = Mutex::new(NameServerCache::new(ns_cache_size));
        let record_cache = DnsLru::new(record_cache_size, TtlConfig::default());

        Ok(Self {
            roots,
            name_server_cache,
            record_cache,
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
    pub async fn resolve(&self, query: Query, request_time: Instant) -> Result<Lookup, Error> {
        if let Some(lookup) = self.record_cache.get(&query, request_time) {
            return lookup.map_err(Into::into);
        }

        // not in cache, let's look for an ns record for lookup
        let zone = match query.query_type() {
            RecordType::NS => query.name().base_name(),
            // look for the NS records "inside" the zone
            _ => query.name().clone(),
        };

        let mut zone = zone;
        let mut ns = None;

        // max number of forwarding processes
        'max_forward: for _ in 0..20 {
            match self.ns_pool_for_zone(zone.clone(), request_time).await {
                Ok(found) => {
                    // found the nameserver
                    ns = Some(found);
                    break 'max_forward;
                }
                Err(e) => match e.kind() {
                    ErrorKind::Forward(name) => {
                        // if we already had this name, don't try again
                        if &zone == name {
                            debug!("zone previously searched for {}", name);
                            break 'max_forward;
                        };

                        debug!("ns forwarded to {}", name);
                        zone = name.clone();
                    }
                    _ => return Err(e),
                },
            }
        }

        let ns = ns.ok_or_else(|| Error::from(format!("no nameserver found for {zone}")))?;
        debug!("found zone {} for {}", ns.zone(), query);

        let response = self.lookup(query, ns, request_time).await?;
        Ok(response)
    }

    async fn lookup(
        &self,
        query: Query,
        ns: RecursorPool<TokioRuntimeProvider>,
        now: Instant,
    ) -> Result<Lookup, Error> {
        if let Some(lookup) = self.record_cache.get(&query, now) {
            debug!("cached data {lookup:?}");
            return lookup.map_err(Into::into);
        }

        let response = ns.lookup(query.clone());

        // TODO: we are only expecting one response
        // TODO: should we change DnsHandle to always be a single response? And build a totally custom handler for other situations?
        // TODO: check if data is "authentic"
        match response.await {
            Ok(r) => {
                let mut r = r.into_message();
                info!("response: {}", r.header());
                let records = r
                    .take_answers()
                    .into_iter()
                    .chain(r.take_name_servers())
                    .chain(r.take_additionals())
                    .filter(|x| {
                        if !is_subzone(ns.zone().clone(), x.name().clone()) {
                            warn!(
                                "Dropping out of bailiwick record {x} for zone {}",
                                ns.zone().clone()
                            );
                            false
                        } else {
                            true
                        }
                    });

                let lookup = self.record_cache.insert_records(query, records, now);

                lookup.ok_or_else(|| Error::from("no records found"))
            }
            Err(e) => {
                warn!("lookup error: {e}");
                Err(Error::from(e))
            }
        }
    }

    #[async_recursion]
    async fn ns_pool_for_zone(
        &self,
        zone: Name,
        request_time: Instant,
    ) -> Result<RecursorPool<TokioRuntimeProvider>, Error> {
        // TODO: need to check TTLs here.
        if let Some(ns) = self.name_server_cache.lock().get_mut(&zone) {
            return Ok(ns.clone());
        };

        let parent_zone = zone.base_name();

        let nameserver_pool = if parent_zone.is_root() {
            debug!("using roots for {zone} nameservers");
            self.roots.clone()
        } else {
            self.ns_pool_for_zone(parent_zone, request_time).await?
        };

        // TODO: check for cached ns pool for this zone

        let lookup = Query::query(zone.clone(), RecordType::NS);
        let response = self
            .lookup(lookup.clone(), nameserver_pool.clone(), request_time)
            .await?;

        // let zone_nameservers = response.name_servers();
        // let glue = response.additionals();

        // TODO: grab TTL and use for cache
        // get all the NS records and glue
        let mut config_group = NameServerConfigGroup::new();
        let mut need_ips_for_names = Vec::new();

        // unpack all glued records
        for zns in response.record_iter() {
            if let Some(ns_data) = zns.data().and_then(RData::as_ns) {
                // let glue_ips = glue
                //     .iter()
                //     .filter(|g| g.name() == ns_data)
                //     .filter_map(Record::data)
                //     .filter_map(RData::to_ip_addr);

                if !is_subzone(zone.base_name().clone(), zns.name().clone()) {
                    warn!(
                        "Dropping out of bailiwick record for {:?} with parent {:?}",
                        zns.name().clone(),
                        zone.base_name().clone()
                    );
                    continue;
                }

                let cached_a = self.record_cache.get(
                    &Query::query(ns_data.0.clone(), RecordType::A),
                    request_time,
                );
                let cached_aaaa = self.record_cache.get(
                    &Query::query(ns_data.0.clone(), RecordType::AAAA),
                    request_time,
                );

                let cached_a = cached_a.and_then(Result::ok).map(Lookup::into_iter);
                let cached_aaaa = cached_aaaa.and_then(Result::ok).map(Lookup::into_iter);

                let glue_ips = cached_a
                    .into_iter()
                    .flatten()
                    .chain(cached_aaaa.into_iter().flatten())
                    .filter_map(|r| RData::ip_addr(&r));

                let mut had_glue = false;
                for ip in glue_ips {
                    let mut udp = NameServerConfig::new(SocketAddr::from((ip, 53)), Protocol::Udp);
                    let mut tcp = NameServerConfig::new(SocketAddr::from((ip, 53)), Protocol::Tcp);

                    udp.trust_negative_responses = true;
                    tcp.trust_negative_responses = true;

                    config_group.push(udp);
                    config_group.push(tcp);
                    had_glue = true;
                }

                if !had_glue {
                    debug!("glue not found for {}", ns_data);
                    need_ips_for_names.push(ns_data);
                }
            }
        }

        // collect missing IP addresses, select over them all, get the addresses
        // make it configurable to query for all records?
        if config_group.is_empty() && !need_ips_for_names.is_empty() {
            debug!("need glue for {}", zone);
            let a_resolves = need_ips_for_names.iter().take(1).map(|name| {
                let a_query = Query::query(name.0.clone(), RecordType::A);
                self.resolve(a_query, request_time).boxed()
            });

            let aaaa_resolves = need_ips_for_names.iter().take(1).map(|name| {
                let aaaa_query = Query::query(name.0.clone(), RecordType::AAAA);
                self.resolve(aaaa_query, request_time).boxed()
            });

            let mut a_resolves: Vec<_> = a_resolves.chain(aaaa_resolves).collect();
            while !a_resolves.is_empty() {
                let (next, _, rest) = select_all(a_resolves).await;
                a_resolves = rest;

                match next {
                    Ok(response) => {
                        debug!("A or AAAA response: {:?}", response);
                        let ips = response.iter().filter_map(RData::ip_addr);

                        for ip in ips {
                            let udp =
                                NameServerConfig::new(SocketAddr::from((ip, 53)), Protocol::Udp);
                            let tcp =
                                NameServerConfig::new(SocketAddr::from((ip, 53)), Protocol::Tcp);

                            config_group.push(udp);
                            config_group.push(tcp);
                        }
                    }
                    Err(e) => {
                        warn!("resolve failed {}", e);
                    }
                }
            }
        }

        // now construct a namesever pool based off the NS and glue records
        let ns = GenericNameServerPool::from_config(
            config_group,
            recursor_opts(),
            TokioConnectionProvider::default(),
        );
        let ns = RecursorPool::from(zone.clone(), ns);

        // store in cache for future usage
        debug!("found nameservers for {}", zone);
        self.name_server_cache.lock().insert(zone, ns.clone());
        Ok(ns)
    }
}

fn recursor_opts() -> ResolverOpts {
    let mut options = ResolverOpts::default();
    options.ndots = 0;
    options.edns0 = true;
    options.validate = false; // we'll need to do any dnssec validation differently in a recursor (top-down rather than bottom-up)
    options.preserve_intermediates = true;
    options.recursion_desired = false;
    options.num_concurrent_reqs = 1;

    options
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
///    false.
///
/// # References
///
/// * [RFC 8499](https://datatracker.ietf.org/doc/html/rfc8499) -- DNS Terminology (see page 25)
/// * [The Hitchiker's Guide to DNS Cache Poisoning](https://www.cs.utexas.edu/%7Eshmat/shmat_securecomm10.pdf) -- for a more in-depth
/// discussion of DNS cache poisoning attacks, see section 4, specifically, for a discussion of the Bailiwick rule.
fn is_subzone(parent: Name, child: Name) -> bool {
    if parent.is_empty() {
        return false;
    }

    if (parent.is_fqdn() && !child.is_fqdn()) || (!parent.is_fqdn() && child.is_fqdn()) {
        return false;
    }

    parent.zone_of(&child)
}

#[test]
fn is_subzone_test() {
    assert!(is_subzone(
        Name::from_str(".").unwrap(),
        Name::from_str("com.").unwrap()
    ));
    assert!(is_subzone(
        Name::from_str("com.").unwrap(),
        Name::from_str("example.com.").unwrap()
    ));
    assert!(is_subzone(
        Name::from_str("example.com.").unwrap(),
        Name::from_str("host.example.com.").unwrap()
    ));
    assert!(is_subzone(
        Name::from_str("example.com.").unwrap(),
        Name::from_str("host.multilevel.example.com.").unwrap()
    ));
    assert!(!is_subzone(
        Name::from_str("").unwrap(),
        Name::from_str("example.com.").unwrap()
    ));
    assert!(!is_subzone(
        Name::from_str("com.").unwrap(),
        Name::from_str("example.net.").unwrap()
    ));
    assert!(!is_subzone(
        Name::from_str("example.com.").unwrap(),
        Name::from_str("otherdomain.com.").unwrap()
    ));
    assert!(!is_subzone(
        Name::from_str("com").unwrap(),
        Name::from_str("example.com.").unwrap()
    ));
}
