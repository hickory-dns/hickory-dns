use std::{sync::Arc, time::Instant};

use async_recursion::async_recursion;
use futures_util::{future::select_all, FutureExt};
use lru_cache::LruCache;
use parking_lot::Mutex;
use tracing::{debug, trace, warn};

use crate::{
    proto::{
        error::ForwardNSData,
        op::Query,
        rr::{RData, RecordType},
    },
    recursor_pool::RecursorPool,
    resolver::{
        config::{NameServerConfigGroup, ResolverOpts},
        dns_lru::{DnsLru, TtlConfig},
        error::ResolveError,
        lookup::Lookup,
        name_server::{GenericNameServerPool, TokioConnectionProvider, TokioRuntimeProvider},
        Name,
    },
    Error, ErrorKind,
};

/// Set of nameservers by the zone name
type NameServerCache<P> = LruCache<Name, RecursorPool<P>>;

#[derive(Clone)]
pub(crate) struct RecursorDnsHandle {
    roots: RecursorPool<TokioRuntimeProvider>,
    name_server_cache: Arc<Mutex<NameServerCache<TokioRuntimeProvider>>>,
    record_cache: DnsLru,
    security_aware: bool,
}

impl RecursorDnsHandle {
    pub(crate) fn new(
        roots: impl Into<NameServerConfigGroup>,
        ns_cache_size: usize,
        record_cache_size: usize,
        security_aware: bool,
    ) -> Result<Self, ResolveError> {
        // configure the hickory-resolver
        let roots: NameServerConfigGroup = roots.into();

        assert!(!roots.is_empty(), "roots must not be empty");

        debug!("Using cache sizes {}/{}", ns_cache_size, record_cache_size);
        let opts = recursor_opts();
        let roots =
            GenericNameServerPool::from_config(roots, opts, TokioConnectionProvider::default());
        let roots = RecursorPool::from(Name::root(), roots);
        let name_server_cache = Arc::new(Mutex::new(NameServerCache::new(ns_cache_size)));
        let record_cache = DnsLru::new(record_cache_size, TtlConfig::default());

        Ok(Self {
            roots,
            name_server_cache,
            record_cache,
            security_aware,
        })
    }

    pub(crate) async fn resolve(
        &self,
        query: Query,
        request_time: Instant,
        query_has_dnssec_ok: bool,
    ) -> Result<Lookup, Error> {
        if let Some(lookup) = self.record_cache.get(&query, request_time) {
            let lookup = super::maybe_strip_dnssec_records(query_has_dnssec_ok, lookup?, query);

            return Ok(lookup);
        }

        // Recursively search for authoritative name servers for the queried record to build an NS
        // pool to use for queries for a given zone. By searching for zone.base_name() (e.g.,
        // example.com if the query is 'www.example.com'), we should end up with the following set
        // of queries:
        //
        // query NS . for com. -> NS list + glue for com.
        // query NS com. for example.com. -> NS list + glue for example.com.
        //
        // ns_pool_for_zone would then return an NS pool based the results of the last query, plus
        // any additional glue records that needed to be resolved, and the authoritative name servers
        // for example.com can be queried directly for 'www.example.com'.
        //
        // If you query zone.name() using this algorithm, you get a superfluous NS query for
        // www.example.com directed to the nameservers for example.com, which will generally result in
        // those servers returning an SOA record, and an additional query being made for whatever
        // record is being queried.
        //
        // If the user is directly querying the second-level domain (e.g., an A query for example.com),
        // the following behavior will occur:
        //
        // query NS . for com. -> NS list + glue for com.
        //
        // ns_pool_for_zone would return that as the NS pool to use for the query 'example.com'.
        // The subsequent lookup request for then ask the com. servers to resolve A example.com, which
        // they are not authoritative for. In that case, those servers will return an empty answer
        // section and a list of authortative name servers, which will result in an ErrorKind::ForwardNS
        // error indicating a referral.  ns_pool_for_referral will build a new NS pool based on those
        // name servers, and an additional query can be made to them to resolve A example.com.
        //
        // Note that while the recursor code has to do some additional checks, no additional queries
        // are being sent to any nameservers in this case -- there are still a total of three queries
        // being made:
        //
        // query NS . for com. -> NS list + glue for com.
        // query A com. for example.com. -> Effectively an NS list + glue for example.com.
        // query A example.com. for example.com. -> authoritative record set.

        let mut zone = match query.query_type() {
            // For DNSSEC queries for NS records, if DO=1 then we need to send the `NS $ZONE`
            // query to `$ZONE` to get the RRSIG records associated to the NS record
            // if DO=0 then we can send the query to the parent zone. its response won't include
            // RRSIG records but that's fine
            RecordType::NS if query_has_dnssec_ok => query.name().clone(),

            // For all other records, we want to set the NS Pool based on the parent zone to
            // avoid extra NS queries as outlined above.  Note that for DS records
            // (RFC4035 section 3.1.4.1) this is an explicit requirement and not an optimization.
            _ => query.name().base_name(),
        };

        let mut ns = None;

        // The for _ in .. range controls maximum number of forwarding processes
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

                        debug!(
                            "ns for {} forwarded to {} via SOA record",
                            query.name(),
                            name
                        );
                        zone = name.clone();
                    }
                    _ => return Err(e),
                },
            }
        }

        let mut ns = ns.ok_or_else(|| Error::from(format!("no nameserver found for {zone}")))?;
        debug!("found zone {} for {}", ns.zone(), query);

        match self
            .lookup(query.clone(), ns, request_time, query_has_dnssec_ok)
            .await
        {
            Ok(response) => {
                // RFC 4035 section 3.2.1 if DO bit not set, strip DNSSEC records unless
                // explicitly requested
                Ok(super::maybe_strip_dnssec_records(
                    query_has_dnssec_ok,
                    response,
                    query,
                ))
            }
            Err(e) => {
                match e.kind() {
                    // ErrorKind::ForwardNS is mapped from ProtoError(NoRecordsFound) when an authoritative
                    // nameserver returns an empty answers sections (NoRecordsFound) and one or more
                    // nameserver records in the nameservers section.  We build a new NS Pool based on those
                    // records and call resolve against that NS pool.
                    ErrorKind::ForwardNS(referral_ns) => {
                        debug!("ns for {} forwarded via NS records", query.name());

                        ns = self
                            .ns_pool_for_referral(query.clone(), referral_ns.clone(), request_time)
                            .await?;

                        match self
                            .lookup(query.clone(), ns, request_time, query_has_dnssec_ok)
                            .await
                        {
                            Ok(response) => {
                                // RFC 4035 section 3.2.1 if DO bit not set, strip DNSSEC
                                // records unless explicitly requested
                                Ok(super::maybe_strip_dnssec_records(
                                    query_has_dnssec_ok,
                                    response,
                                    query.clone(),
                                ))
                            }
                            Err(e) => Err(e),
                        }
                    }
                    _ => Err(e),
                }
            }
        }
    }

    async fn lookup(
        &self,
        query: Query,
        ns: RecursorPool<TokioRuntimeProvider>,
        now: Instant,
        expect_dnssec_in_cached_response: bool,
    ) -> Result<Lookup, Error> {
        if let Some(lookup) = self.record_cache.get(&query, now) {
            let lookup = lookup?;

            // we may have cached a referral (NS+A record pair) from a parent zone while looking for
            // the nameserver to send the query to. that parent zone response won't include RRSIG
            // records. if DO=1 we want to fall through and send the query to the child zone to
            // retrieve the missing RRSIG record
            if expect_dnssec_in_cached_response
                && lookup
                    .records()
                    .iter()
                    .all(|rrset| !rrset.record_type().is_dnssec())
            {
                // fall through to send query to child zone
            } else {
                debug!("cached data {lookup:?}");
                return Ok(lookup);
            }
        }

        let response = ns.lookup(query.clone(), self.security_aware);

        // TODO: we are only expecting one response
        // TODO: should we change DnsHandle to always be a single response? And build a totally custom handler for other situations?
        // TODO: check if data is "authentic"
        match response.await {
            Ok(r) => super::cache_response(r, Some(ns.zone()), &self.record_cache, query, now),
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
            .lookup(lookup.clone(), nameserver_pool.clone(), request_time, false)
            .await?;

        // let zone_nameservers = response.name_servers();
        // let glue = response.additionals();

        // TODO: grab TTL and use for cache
        // get all the NS records and glue
        let mut config_group = NameServerConfigGroup::new();
        let mut need_ips_for_names = Vec::new();

        // unpack all glued records
        for zns in response.record_iter() {
            if let Some(ns_data) = zns.data().as_ns() {
                // let glue_ips = glue
                //     .iter()
                //     .filter(|g| g.name() == ns_data)
                //     .filter_map(Record::data)
                //     .filter_map(RData::to_ip_addr);

                if !super::is_subzone(&zone.base_name(), zns.name()) {
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

                let mut glue_ips = cached_a
                    .into_iter()
                    .flatten()
                    .chain(cached_aaaa.into_iter().flatten())
                    .filter_map(|r| r.ip_addr())
                    .peekable();

                if glue_ips.peek().is_none() {
                    debug!("glue not found for {ns_data}");
                    need_ips_for_names.push(ns_data);
                }

                config_group.append_ips(glue_ips, true);
            }
        }

        // collect missing IP addresses, select over them all, get the addresses
        // make it configurable to query for all records?
        if config_group.is_empty() && !need_ips_for_names.is_empty() {
            debug!("need glue for {}", zone);
            let a_resolves = need_ips_for_names.iter().take(1).map(|name| {
                let a_query = Query::query(name.0.clone(), RecordType::A);
                self.resolve(a_query, request_time, false).boxed()
            });

            let aaaa_resolves = need_ips_for_names.iter().take(1).map(|name| {
                let aaaa_query = Query::query(name.0.clone(), RecordType::AAAA);
                self.resolve(aaaa_query, request_time, false).boxed()
            });

            let mut a_resolves: Vec<_> = a_resolves.chain(aaaa_resolves).collect();
            while !a_resolves.is_empty() {
                let (next, _, rest) = select_all(a_resolves).await;
                a_resolves = rest;

                match next {
                    Ok(response) => {
                        debug!("A or AAAA response: {:?}", response);
                        let ips = response.iter().filter_map(RData::ip_addr);

                        config_group.append_ips(ips, true);
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

    /// Build an NS Pool based on an NS-record referral.
    ///
    /// Normally, when we build an NS Pool with ns_pool_for_zone, we search recursively, starting at
    /// the root, for authoritative name servers for a given domain.  Sometimes in the recursive
    /// resolution process, an upstream name server will return an empty answers section but one or
    /// more name servers in the name servers section (and possibly glue records in the additionals
    /// section.)  To continue the resolution process, we need to query those name servers.  This
    /// function builds a pool with those servers by:
    ///
    ///  1. Iterating over the list of referent name servers
    ///  2. Combining glue records and A/AAAA cache entries for the referent name servers to build the new
    ///     pool.
    ///  3. If there are no glue records and no relevant A/AAAA cache entries, attempt to recursively
    ///     resolve the referent NS records to produce an NS Pool.
    #[async_recursion]
    async fn ns_pool_for_referral(
        &self,
        query: Query,
        nameservers: Vec<ForwardNSData>,
        request_time: Instant,
    ) -> Result<RecursorPool<TokioRuntimeProvider>, Error> {
        let query_name = query.name().clone();

        // TODO: grab TTL and use for cache
        // get all the NS records and glue
        let mut config_group = NameServerConfigGroup::new();
        let mut need_ips_for_names = Vec::new();

        for nameserver in nameservers.into_iter() {
            let ns = nameserver.ns;

            let ns_name = if let Some(ns_name) = ns.data().as_ns() {
                ns_name.0.clone()
            } else {
                debug!("ns_pool_for_referral: non-NS name in NS referral list: {ns:?}");
                continue;
            };

            let glue = nameserver
                .glue
                .iter()
                .filter(|record| *record.name() == ns_name);

            trace!("ns_pool_for_referral: GLUE_A: {:?}", nameserver.glue);

            let cached_a = self
                .record_cache
                .get(&Query::query(ns_name.clone(), RecordType::A), request_time);
            let cached_aaaa = self.record_cache.get(
                &Query::query(ns_name.clone(), RecordType::AAAA),
                request_time,
            );

            trace!("ns_pool_for_referral: CACHED_A: {cached_a:?}");

            let cached_a = cached_a.and_then(Result::ok).map(Lookup::into_iter);
            let cached_aaaa = cached_aaaa.and_then(Result::ok).map(Lookup::into_iter);

            let mut glue_ips = cached_a
                .into_iter()
                .flatten()
                .chain(cached_aaaa.into_iter().flatten())
                .filter_map(|r| RData::ip_addr(&r))
                .chain(glue.filter_map(|r| RData::ip_addr(r.data())))
                .peekable();

            if glue_ips.peek().is_some() {
                config_group.append_ips(glue_ips, true);
            } else {
                debug!("ns_pool_for_referral glue not found for {}", ns);
                need_ips_for_names.push(ns);
            }
        }

        trace!("Pre glue config group: {config_group:?} Need IPs: {need_ips_for_names:?}");

        // collect missing IP addresses, select over them all, get the addresses
        // make it configurable to query for all records?
        if config_group.is_empty() && !need_ips_for_names.is_empty() {
            debug!("ns_pool_for_referral need glue for {}", query_name);
            let a_resolves = need_ips_for_names.iter().take(1).map(|name| {
                let a_query = Query::query(name.data().as_ns().unwrap().0.clone(), RecordType::A);
                self.resolve(a_query, request_time, false).boxed()
            });

            let aaaa_resolves = need_ips_for_names.iter().take(1).map(|name| {
                let aaaa_query =
                    Query::query(name.data().as_ns().unwrap().0.clone(), RecordType::AAAA);
                self.resolve(aaaa_query, request_time, false).boxed()
            });

            let mut a_resolves: Vec<_> = a_resolves.chain(aaaa_resolves).collect();
            while !a_resolves.is_empty() {
                let (next, _, rest) = select_all(a_resolves).await;
                a_resolves = rest;

                match next {
                    Ok(response) => {
                        debug!("ns_pool_for_referral A or AAAA response: {:?}", response);
                        let ips = response.iter().filter_map(RData::ip_addr);

                        config_group.append_ips(ips, true);
                    }
                    Err(e) => {
                        warn!("ns_pool_for_referral resolve failed {}", e);
                    }
                }
            }
        }

        debug!(
            "ns_pool_for_referral found nameservers for {}: {config_group:?}",
            query_name
        );

        // now construct a namesever pool based off the NS and glue records
        let ns = GenericNameServerPool::from_config(
            config_group,
            recursor_opts(),
            TokioConnectionProvider::default(),
        );
        let ns = RecursorPool::from(query_name.clone(), ns);

        // store in cache for future usage
        self.name_server_cache.lock().insert(query_name, ns.clone());

        Ok(ns)
    }

    #[cfg(feature = "dnssec")]
    pub(crate) fn record_cache(&self) -> &DnsLru {
        &self.record_cache
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
