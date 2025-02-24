use std::{
    collections::HashSet,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Instant,
};

use async_recursion::async_recursion;
use futures_util::{StreamExt, stream::FuturesUnordered};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use lru_cache::LruCache;
use parking_lot::Mutex;
use prefix_trie::PrefixSet;
use tracing::{debug, info, trace, warn};

use crate::{
    Error, ErrorKind,
    proto::{
        ForwardNSData, ProtoErrorKind,
        op::Query,
        rr::{RData, RData::CNAME, RecordType, rdata::NS},
        runtime::TokioRuntimeProvider,
    },
    recursor_pool::RecursorPool,
    resolver::{
        Name,
        config::{NameServerConfigGroup, ResolverOpts},
        dns_lru::{DnsLru, TtlConfig},
        lookup::Lookup,
        name_server::{GenericNameServerPool, TokioConnectionProvider},
    },
};

#[derive(Clone)]
pub(crate) struct RecursorDnsHandle {
    roots: RecursorPool<TokioRuntimeProvider>,
    name_server_cache: Arc<Mutex<LruCache<Name, RecursorPool<TokioRuntimeProvider>>>>,
    record_cache: DnsLru,
    recursion_limit: Option<u8>,
    ns_recursion_limit: Option<u8>,
    security_aware: bool,
    deny_server_v4: PrefixSet<Ipv4Net>,
    deny_server_v6: PrefixSet<Ipv6Net>,
    allow_server_v4: PrefixSet<Ipv4Net>,
    allow_server_v6: PrefixSet<Ipv6Net>,
    avoid_local_udp_ports: Arc<HashSet<u16>>,
    case_randomization: bool,
}

impl RecursorDnsHandle {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        roots: impl Into<NameServerConfigGroup>,
        ns_cache_size: usize,
        record_cache_size: usize,
        recursion_limit: Option<u8>,
        ns_recursion_limit: Option<u8>,
        security_aware: bool,
        allow_server: Vec<IpNet>,
        deny_server: Vec<IpNet>,
        avoid_local_udp_ports: Arc<HashSet<u16>>,
        ttl_config: TtlConfig,
        case_randomization: bool,
    ) -> Self {
        // configure the hickory-resolver
        let roots: NameServerConfigGroup = roots.into();

        assert!(!roots.is_empty(), "roots must not be empty");

        debug!("Using cache sizes {}/{}", ns_cache_size, record_cache_size);
        let opts = recursor_opts(avoid_local_udp_ports.clone(), case_randomization);
        let roots =
            GenericNameServerPool::from_config(roots, opts, TokioConnectionProvider::default());
        let roots = RecursorPool::from(Name::root(), roots);
        let name_server_cache = Arc::new(Mutex::new(LruCache::new(ns_cache_size)));
        let record_cache = DnsLru::new(record_cache_size, ttl_config);

        let mut deny_server_v4 = PrefixSet::new();
        let mut deny_server_v6 = PrefixSet::new();

        for network in deny_server {
            info!("adding {network} to the do not query list");
            match network {
                IpNet::V4(network) => {
                    deny_server_v4.insert(network);
                }
                IpNet::V6(network) => {
                    deny_server_v6.insert(network);
                }
            }
        }

        let mut allow_server_v4 = PrefixSet::new();
        let mut allow_server_v6 = PrefixSet::new();

        for network in allow_server {
            info!("adding {network} to the do not query override list");
            match network {
                IpNet::V4(network) => {
                    allow_server_v4.insert(network);
                }
                IpNet::V6(network) => {
                    allow_server_v6.insert(network);
                }
            }
        }

        Self {
            roots,
            name_server_cache,
            record_cache,
            recursion_limit,
            ns_recursion_limit,
            security_aware,
            deny_server_v4,
            deny_server_v6,
            allow_server_v4,
            allow_server_v6,
            avoid_local_udp_ports,
            case_randomization,
        }
    }

    pub(crate) async fn resolve(
        &self,
        query: Query,
        request_time: Instant,
        query_has_dnssec_ok: bool,
        depth: u8,
        cname_limit: Arc<AtomicU8>,
    ) -> Result<Lookup, Error> {
        if let Some(lookup) = self.record_cache.get(&query, request_time) {
            let response = self
                .resolve_cnames(
                    lookup?,
                    query.clone(),
                    request_time,
                    query_has_dnssec_ok,
                    depth,
                    cname_limit,
                )
                .await?;

            return Ok(super::maybe_strip_dnssec_records(
                query_has_dnssec_ok,
                response,
                query,
            ));
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

        let zone = match query.query_type() {
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

        let (mut depth, mut ns) = match self
            .ns_pool_for_zone(zone.clone(), request_time, depth)
            .await
        {
            Ok((depth, ns)) => (depth, ns),
            Err(e) => return Err(Error::from(format!("no nameserver found for {zone}: {e}"))),
        };

        debug!("found zone {} for {query}", ns.zone());

        match self
            .lookup(query.clone(), ns, request_time, query_has_dnssec_ok)
            .await
        {
            Ok(response) => {
                let response = self
                    .resolve_cnames(
                        response,
                        query.clone(),
                        request_time,
                        query_has_dnssec_ok,
                        depth,
                        cname_limit,
                    )
                    .await?;

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

                        (depth, ns) = self
                            .ns_pool_for_referral(
                                query.clone(),
                                referral_ns.clone(),
                                request_time,
                                depth,
                            )
                            .await?;

                        match self
                            .lookup(query.clone(), ns, request_time, query_has_dnssec_ok)
                            .await
                        {
                            Ok(response) => {
                                let response = self
                                    .resolve_cnames(
                                        response,
                                        query.clone(),
                                        request_time,
                                        query_has_dnssec_ok,
                                        depth,
                                        cname_limit,
                                    )
                                    .await?;

                                // RFC 4035 section 3.2.1 if DO bit not set, strip DNSSEC
                                // records unless explicitly requested
                                Ok(super::maybe_strip_dnssec_records(
                                    query_has_dnssec_ok,
                                    response,
                                    query,
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

    /// Handle CNAME expansion for the current query
    #[async_recursion]
    async fn resolve_cnames(
        &self,
        mut lookup: Lookup,
        query: Query,
        now: Instant,
        query_has_dnssec_ok: bool,
        mut depth: u8,
        cname_limit: Arc<AtomicU8>,
    ) -> Result<Lookup, Error> {
        let query_type = query.query_type();
        let query_name = query.name().clone();

        // Don't resolve CNAME lookups for a CNAME (or ANY) query
        if query_type == RecordType::CNAME || query_type == RecordType::ANY {
            return Ok(lookup);
        }

        depth += 1;
        Error::recursion_exceeded(self.recursion_limit, depth, &query_name)?;

        let mut cname_chain = vec![];

        for rec in lookup.records().iter() {
            let CNAME(name) = rec.data() else {
                continue;
            };

            let cname_query = Query::query(name.0.clone(), query_type);

            let count = cname_limit.fetch_add(1, Ordering::Relaxed) + 1;
            if count > MAX_CNAME_LOOKUPS {
                warn!("cname limit exceeded for query {query}");
                return Err(ErrorKind::Proto(
                    ProtoErrorKind::MaxRecordLimitExceeded {
                        count: count as usize,
                        record_type: RecordType::CNAME,
                    }
                    .into(),
                )
                .into());
            }

            // Note that we aren't worried about whether the intermediates are local or remote
            // to the original queried name, or included or not included in the original
            // response.  Resolve will either pull the intermediates out of the cache or query
            // the appropriate nameservers if necessary.
            let records = match self
                .resolve(
                    cname_query,
                    now,
                    query_has_dnssec_ok,
                    depth,
                    cname_limit.clone(),
                )
                .await
            {
                Ok(cname_r) => cname_r,
                Err(e) => {
                    return Err(e);
                }
            };

            // Here, we're looking for either the terminal record type (matching the
            // original query, or another CNAME.
            cname_chain.extend(records.records().iter().filter_map(|r| {
                if r.record_type() == query_type || r.record_type() == RecordType::CNAME {
                    Some(r.to_owned())
                } else {
                    None
                }
            }));
        }

        if !cname_chain.is_empty() {
            lookup.extend_records(cname_chain);
        }

        Ok(lookup)
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
        mut depth: u8,
    ) -> Result<(u8, RecursorPool<TokioRuntimeProvider>), Error> {
        // TODO: need to check TTLs here.
        if let Some(ns) = self.name_server_cache.lock().get_mut(&zone) {
            debug!("returning cached pool for {zone}");
            return Ok((depth, ns.clone()));
        };

        trace!("ns_pool_for_zone: depth {depth} for {zone}");

        depth += 1;
        Error::recursion_exceeded(self.ns_recursion_limit, depth, &zone)?;

        let parent_zone = zone.base_name();

        let (mut ns_depth, mut nameserver_pool) = if parent_zone.is_root() {
            debug!("using roots for {zone} nameservers");
            (depth, self.roots.clone())
        } else {
            self.ns_pool_for_zone(parent_zone, request_time, depth)
                .await?
        };

        let mut lookup = Query::query(zone.clone(), RecordType::NS);

        // Query for nameserver records via the pool for the parent zone, following SOA referrals up
        // to the nameserver recursion limit.
        let response = loop {
            ns_depth += 1;

            Error::recursion_exceeded(self.ns_recursion_limit, ns_depth, &zone)?;

            let error = match self
                .lookup(lookup.clone(), nameserver_pool.clone(), request_time, false)
                .await
            {
                Ok(response) => break response,
                Err(e) => e,
            };

            if let ErrorKind::Forward(name) = error.kind() {
                // if we already had this name, don't try again
                if zone == name.name {
                    debug!("zone previously searched for {}", name.name);
                    return Err(error);
                };

                debug!("ns for {zone} forwarded to {} via SOA record", name.name);

                (ns_depth, nameserver_pool) = self
                    .ns_pool_for_zone(name.name.clone(), request_time, ns_depth)
                    .await?;

                lookup = Query::query(name.name.clone(), RecordType::NS);
                continue;
            }

            return Err(error);
        };

        // TODO: grab TTL and use for cache
        // get all the NS records and glue
        let mut config_group = NameServerConfigGroup::new();
        let mut need_ips_for_names = Vec::new();

        // unpack all glued records
        for zns in response.record_iter() {
            let Some(ns_data) = zns.data().as_ns() else {
                debug!("response is not NS: {:?}; skipping", zns.data());
                continue;
            };

            if !super::is_subzone(&lookup.name().base_name(), zns.name()) {
                warn!(
                    "dropping out of bailiwick record for {:?} with parent {:?}",
                    zns.name(),
                    lookup.name().base_name(),
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
                .filter_map(|r| {
                    let ip = r.ip_addr()?;

                    if self.matches_nameserver_filter(ip) {
                        debug!(name = %ns_data, %ip, "ignoring address due to do_not_query");
                        None
                    } else {
                        Some(ip)
                    }
                })
                .peekable();

            if glue_ips.peek().is_none() {
                debug!("glue not found for {ns_data}");
                need_ips_for_names.push(ns_data.to_owned());
            }

            config_group.append_ips(glue_ips, true);
        }

        // If we have no glue, collect missing nameserver IP addresses.
        // For non-child name servers, get a new pool by calling ns_pool_for_zone recursively.
        // For child child name servers, we can use the existing pool, but we *must* use lookup
        // to avoid infinite recursion.
        if config_group.is_empty() && !need_ips_for_names.is_empty() {
            debug!("need glue for {zone}");

            depth = self
                .append_ips_from_lookup(
                    &zone,
                    depth,
                    request_time,
                    nameserver_pool,
                    need_ips_for_names.iter(),
                    &mut config_group,
                )
                .await?;
        }

        // now construct a namesever pool based off the NS and glue records
        let ns = GenericNameServerPool::from_config(
            config_group,
            self.recursor_opts(),
            TokioConnectionProvider::default(),
        );
        let ns = RecursorPool::from(zone.clone(), ns);

        // store in cache for future usage
        debug!("found nameservers for {zone}");
        self.name_server_cache.lock().insert(zone, ns.clone());
        Ok((depth, ns))
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
        nameservers: Arc<[ForwardNSData]>,
        request_time: Instant,
        mut depth: u8,
    ) -> Result<(u8, RecursorPool<TokioRuntimeProvider>), Error> {
        let query_name = query.name().clone();

        depth += 1;
        Error::recursion_exceeded(self.ns_recursion_limit, depth, &query_name)?;

        trace!("ns_pool_for_referral: depth {depth} for {query}");

        // TODO: grab TTL and use for cache
        // get all the NS records and glue
        let mut config_group = NameServerConfigGroup::new();
        let mut need_ips_for_names = Vec::new();

        for nameserver in nameservers.iter() {
            let ns = &nameserver.ns;

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
                .filter(|ip| {
                    let matches = self.matches_nameserver_filter(*ip);
                    if matches {
                        debug!(name = %ns_name, %ip, "ignoring address due to do_not_query");
                    }
                    !matches
                })
                .peekable();

            if glue_ips.peek().is_some() {
                config_group.append_ips(glue_ips, true);
            } else {
                debug!("ns_pool_for_referral glue not found for {ns}");
                need_ips_for_names.push(ns);
            }
        }

        trace!("pre glue config group: {config_group:?} Need IPs: {need_ips_for_names:?}");

        // collect missing IP addresses
        if config_group.is_empty() && !need_ips_for_names.is_empty() {
            debug!("ns_pool_for_referral need glue for {query_name}");

            let (new_depth, nameserver_pool) = self
                .ns_pool_for_zone(query_name.clone(), request_time, depth)
                .await?;

            depth = new_depth;

            depth = self
                .append_ips_from_lookup(
                    &query_name,
                    depth,
                    request_time,
                    nameserver_pool,
                    need_ips_for_names.iter().filter_map(|x| x.data().as_ns()),
                    &mut config_group,
                )
                .await?;
        }

        debug!("ns_pool_for_referral found nameservers for {query_name}: {config_group:?}");

        // now construct a namesever pool based off the NS and glue records
        let ns = GenericNameServerPool::from_config(
            config_group,
            self.recursor_opts(),
            TokioConnectionProvider::default(),
        );
        let ns = RecursorPool::from(query_name.clone(), ns);

        // store in cache for future usage
        self.name_server_cache.lock().insert(query_name, ns.clone());

        Ok((depth, ns))
    }

    /// Check if an IP address matches any networks listed in the configuration that should not be
    /// sent recursive queries.
    fn matches_nameserver_filter(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                self.allow_server_v4.get_spm(&ip.into()).is_none()
                    && self.deny_server_v4.get_spm(&ip.into()).is_some()
            }
            IpAddr::V6(ip) => {
                self.allow_server_v6.get_spm(&ip.into()).is_none()
                    && self.deny_server_v6.get_spm(&ip.into()).is_some()
            }
        }
    }

    #[cfg(feature = "__dnssec")]
    pub(crate) fn record_cache(&self) -> &DnsLru {
        &self.record_cache
    }

    async fn append_ips_from_lookup<'a, I: Iterator<Item = &'a NS>>(
        &self,
        zone: &Name,
        depth: u8,
        request_time: Instant,
        nameserver_pool: RecursorPool<TokioRuntimeProvider>,
        nameservers: I,
        config: &mut NameServerConfigGroup,
    ) -> Result<u8, Error> {
        let mut pool_queries = vec![];

        for ns in nameservers {
            let record_name = ns.0.clone();

            // For child nameservers of zone, we can reuse the pool that was passed in as
            // nameserver_pool, but for a non-child nameservers we need to get an appropriate pool.
            // To avoid incrementing the depth counter for each nameserver, we'll use the passed in
            // depth as a fixed base for the nameserver lookups
            let nameserver_pool = if !crate::is_subzone(zone, &record_name) {
                self.ns_pool_for_zone(record_name.clone(), request_time, depth)
                    .await?
                    .1 // discard the depth part of the tuple
            } else {
                nameserver_pool.clone()
            };

            pool_queries.push((nameserver_pool, record_name));
        }

        let mut futures = FuturesUnordered::new();

        for (pool, query) in pool_queries.iter() {
            for rec_type in [RecordType::A, RecordType::AAAA] {
                futures
                    .push(pool.lookup(Query::query(query.clone(), rec_type), self.security_aware));
            }
        }

        while let Some(next) = futures.next().await {
            match next {
                Ok(mut response) => {
                    debug!("append_ips_from_lookup: A or AAAA response: {response:?}");
                    let ip_iter = response
                        .take_answers()
                        .into_iter()
                        .filter_map(|answer| {
                            let ip = answer.data().ip_addr()?;

                            if self.matches_nameserver_filter(ip) {
                                debug!(%ip, "append_ips_from_lookup: ignoring address due to do_not_query");
                                None
                            } else {
                                Some(ip)
                            }
                        });
                    config.append_ips(ip_iter, true);
                }
                Err(e) => {
                    warn!("append_ips_from_lookup: resolution failed failed: {e}");
                }
            }
        }

        Ok(depth)
    }

    fn recursor_opts(&self) -> ResolverOpts {
        recursor_opts(self.avoid_local_udp_ports.clone(), self.case_randomization)
    }
}

fn recursor_opts(
    avoid_local_udp_ports: Arc<HashSet<u16>>,
    case_randomization: bool,
) -> ResolverOpts {
    let mut options = ResolverOpts::default();
    options.ndots = 0;
    options.edns0 = true;
    options.validate = false; // we'll need to do any dnssec validation differently in a recursor (top-down rather than bottom-up)
    options.preserve_intermediates = true;
    options.recursion_desired = false;
    options.num_concurrent_reqs = 1;
    options.avoid_local_udp_ports = avoid_local_udp_ports;
    options.case_randomization = case_randomization;

    options
}

#[cfg(test)]
#[test]
fn test_nameserver_filter() {
    use std::net::Ipv4Addr;

    let allow_server = vec![IpNet::new(IpAddr::from([192, 168, 0, 1]), 32).unwrap()];
    let deny_server = vec![
        IpNet::new(IpAddr::from(Ipv4Addr::LOCALHOST), 8).unwrap(),
        IpNet::new(IpAddr::from([192, 168, 0, 0]), 23).unwrap(),
        IpNet::new(IpAddr::from([172, 17, 0, 0]), 20).unwrap(),
    ];

    let recursor = RecursorDnsHandle::new(
        NameServerConfigGroup::from_ips_clear(&[IpAddr::from([192, 0, 2, 1])], 53, true),
        1,
        1,
        Some(1),
        Some(1),
        true,
        allow_server,
        deny_server,
        Arc::new(HashSet::new()),
        TtlConfig::default(),
        false,
    );

    for addr in [
        [127, 0, 0, 0],
        [127, 0, 0, 1],
        [192, 168, 1, 0],
        [192, 168, 1, 254],
        [172, 17, 0, 1],
    ] {
        assert!(recursor.matches_nameserver_filter(IpAddr::from(addr)));
    }

    for addr in [[128, 0, 0, 0], [192, 168, 2, 0], [192, 168, 0, 1]] {
        assert!(!recursor.matches_nameserver_filter(IpAddr::from(addr)));
    }
}

/// Maximum number of cname records to look up in a CNAME chain, regardless of the recursion
/// depth limit
const MAX_CNAME_LOOKUPS: u8 = 64;
