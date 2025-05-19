use std::{
    collections::{HashMap, HashSet},
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
        ProtoErrorKind,
        op::Query,
        rr::{
            RData,
            RData::CNAME,
            Record, RecordType,
            rdata::{A, AAAA, NS},
        },
        runtime::TokioRuntimeProvider,
        xfer::DnsResponse,
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
        roots: &[IpAddr],
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
        let roots = NameServerConfigGroup::from_ips_clear(roots, 53, true);

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
        // pool to use for queries for a given zone. By searching for the query name, (e.g.
        // 'www.example.com') we should end up with the following set of queries:
        //
        // query NS . for com. -> NS list + glue for com.
        // query NS com. for example.com. -> NS list + glue for example.com.
        // query NS example.com. for www.example.com. -> no data.
        //
        // ns_pool_for_zone would then return an NS pool based the results of the last NS RRset,
        // plus any additional glue records that needed to be resolved, and the authoritative name
        // servers for example.com can be queried directly for 'www.example.com'.
        //
        // When querying zone.name() using this algorithm, you make an NS query for www.example.com
        // directed to the nameservers for example.com, which will generally result in those servers
        // returning a no data response, and an additional query being made for whatever record is
        // being queried.
        //
        // If the user is directly querying the second-level domain (e.g., an A query for example.com),
        // the following behavior will occur:
        //
        // query NS . for com. -> NS list + glue for com.
        // query NS com. for example.com. -> NS list + glue for example.com.
        //
        // ns_pool_for_zone would return that as the NS pool to use for the query 'example.com'.
        // The subsequent lookup request for then ask the example.com. servers to resolve
        // A example.com.

        let zone = match query.query_type() {
            RecordType::DS => query.name().base_name(),
            _ => query.name().clone(),
        };

        let (depth, ns) = match self
            .ns_pool_for_zone(zone.clone(), request_time, depth)
            .await
        {
            Ok((depth, ns)) => (depth, ns),
            // Handle the short circuit case for when we receive NXDOMAIN on a parent name, per RFC
            // 8020.
            Err(e) if e.is_nx_domain() => return Err(e),
            Err(e) => return Err(Error::from(format!("no nameserver found for {zone}: {e}"))),
        };

        debug!("found zone {} for {query}", ns.zone());

        let (lookup, _) = self
            .lookup(query.clone(), ns, request_time, query_has_dnssec_ok)
            .await?;

        let response = self
            .resolve_cnames(
                lookup,
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
    ) -> Result<(Lookup, Option<DnsResponse>), Error> {
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
                return Ok((lookup, None));
            }
        }

        let response = ns.lookup(query.clone(), self.security_aware);

        // TODO: we are only expecting one response
        // TODO: should we change DnsHandle to always be a single response? And build a totally custom handler for other situations?
        // TODO: check if data is "authentic"
        match response.await {
            Ok(r) => Ok((
                super::cache_response(r.clone(), Some(ns.zone()), &self.record_cache, query, now)?,
                Some(r),
            )),
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

        let (mut ns_depth, nameserver_pool) = if parent_zone.is_root() {
            debug!("using roots for {zone} nameservers");
            (depth, self.roots.clone())
        } else {
            self.ns_pool_for_zone(parent_zone, request_time, depth)
                .await?
        };

        let query = Query::query(zone.clone(), RecordType::NS);

        ns_depth += 1;
        Error::recursion_exceeded(self.ns_recursion_limit, ns_depth, &zone)?;

        // Query for nameserver records via the pool for the parent zone.
        let lookup_res = self
            .lookup(query, nameserver_pool.clone(), request_time, false)
            .await;
        let (lookup, response_opt) = match lookup_res {
            Ok((lookup, response_opt)) => (lookup, response_opt),
            // Short-circuit on NXDOMAIN, per RFC 8020.
            Err(e) if e.is_nx_domain() => return Err(e),
            // Short-circuit on timeouts. Requesting a longer name from the same pool would likely
            // encounter them again.
            Err(e) if e.is_timeout() => return Err(e),
            // The name `zone` is not a zone cut. Return the same pool of name servers again, but do
            // not cache it. If this was recursively called by `ns_pool_for_zone()`, the outer call
            // will try again with one more label added to the iterative query name.
            Err(_) => return Ok((depth, nameserver_pool)),
        };

        let any_ns = lookup
            .record_iter()
            .any(|record| record.record_type() == RecordType::NS);
        if !any_ns {
            // Not a zone cut, but there is a CNAME or other record at this name. Return the
            // same pool of name servers as above in the error case, to try again with a
            // longer name.
            return Ok((depth, nameserver_pool));
        }

        // TODO: grab TTL and use for cache
        // get all the NS records and glue
        let mut config_group = NameServerConfigGroup::new();
        let mut need_ips_for_names = Vec::new();
        let mut glue_ips = HashMap::new();

        if let Some(response) = response_opt {
            for section in [
                response.answers(),
                response.name_servers(),
                response.additionals(),
            ] {
                self.add_glue_to_map(&mut glue_ips, section.iter());
            }
        }

        for zns in lookup.record_iter() {
            let Some(ns_data) = zns.data().as_ns() else {
                debug!("response is not NS: {:?}; skipping", zns.data());
                continue;
            };

            if !super::is_subzone(&zone.base_name(), zns.name()) {
                warn!(
                    "dropping out of bailiwick record for {:?} with parent {:?}",
                    zns.name(),
                    zone.base_name(),
                );
                continue;
            }

            for record_type in [RecordType::A, RecordType::AAAA] {
                if let Some(Ok(lookup)) = self
                    .record_cache
                    .get(&Query::query(ns_data.0.clone(), record_type), request_time)
                {
                    self.add_glue_to_map(&mut glue_ips, lookup.records().iter());
                }
            }

            match glue_ips.get(&ns_data.0) {
                Some(glue) if !glue.is_empty() => {
                    config_group.append_ips(glue.iter().cloned(), true)
                }
                _ => {
                    debug!("glue not found for {ns_data}");
                    need_ips_for_names.push(ns_data.to_owned());
                }
            }
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

    /// Helper function to add IP addresses from any A or AAAA records to a map indexed by record
    /// name.
    fn add_glue_to_map<'a>(
        &self,
        glue_map: &mut HashMap<Name, Vec<IpAddr>>,
        records: impl Iterator<Item = &'a Record>,
    ) {
        for record in records {
            let ip = match record.data() {
                RData::A(A(ipv4)) => (*ipv4).into(),
                RData::AAAA(AAAA(ipv6)) => (*ipv6).into(),
                _ => continue,
            };
            if self.matches_nameserver_filter(ip) {
                debug!(name = %record.name(), %ip, "ignoring address due to do_not_query");
                continue;
            }
            let ns_glue_ips = glue_map.entry(record.name().clone()).or_default();
            if !ns_glue_ips.contains(&ip) {
                ns_glue_ips.push(ip);
            }
        }
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
        &[IpAddr::from([192, 0, 2, 1])],
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
