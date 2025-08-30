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
use hickory_resolver::name_server::TlsConfig;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use lru_cache::LruCache;
#[cfg(feature = "metrics")]
use metrics::{Counter, Unit, counter, describe_counter};
use parking_lot::Mutex;
use prefix_trie::PrefixSet;
use tracing::{debug, info, trace, warn};

use crate::{
    Error, ErrorKind,
    proto::{
        ProtoErrorKind,
        op::{Message, Query},
        rr::{
            RData,
            RData::CNAME,
            Record, RecordType,
            rdata::{A, AAAA, NS},
        },
    },
    recursor_pool::RecursorPool,
    resolver::{
        Name, ResponseCache, TtlConfig,
        config::{NameServerConfig, ResolverOpts},
        name_server::{ConnectionProvider, NameServerPool},
    },
};

#[derive(Clone)]
pub(crate) struct RecursorDnsHandle<P: ConnectionProvider> {
    roots: RecursorPool<P>,
    name_server_cache: Arc<Mutex<LruCache<Name, RecursorPool<P>>>>,
    response_cache: ResponseCache,
    #[cfg(feature = "metrics")]
    cache_metrics: RecursorCacheMetrics,
    recursion_limit: Option<u8>,
    ns_recursion_limit: Option<u8>,
    security_aware: bool,
    deny_server_v4: PrefixSet<Ipv4Net>,
    deny_server_v6: PrefixSet<Ipv6Net>,
    allow_server_v4: PrefixSet<Ipv4Net>,
    allow_server_v6: PrefixSet<Ipv6Net>,
    avoid_local_udp_ports: Arc<HashSet<u16>>,
    case_randomization: bool,
    tls: Arc<TlsConfig>,
    conn_provider: P,
}

impl<P: ConnectionProvider> RecursorDnsHandle<P> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        roots: &[IpAddr],
        ns_cache_size: usize,
        response_cache_size: u64,
        recursion_limit: Option<u8>,
        ns_recursion_limit: Option<u8>,
        security_aware: bool,
        allow_server: Vec<IpNet>,
        deny_server: Vec<IpNet>,
        avoid_local_udp_ports: Arc<HashSet<u16>>,
        ttl_config: TtlConfig,
        case_randomization: bool,
        tls: Arc<TlsConfig>,
        conn_provider: P,
    ) -> Self {
        assert!(!roots.is_empty(), "roots must not be empty");
        let servers = roots
            .iter()
            .copied()
            .map(NameServerConfig::udp_and_tcp)
            .collect::<Vec<_>>();

        debug!(
            "Using cache sizes {}/{}",
            ns_cache_size, response_cache_size
        );
        let opts = recursor_opts(avoid_local_udp_ports.clone(), case_randomization);
        let roots = NameServerPool::from_config(
            servers,
            Arc::new(opts),
            tls.clone(),
            conn_provider.clone(),
        );

        let roots = RecursorPool::from(Name::root(), roots);
        let name_server_cache = Arc::new(Mutex::new(LruCache::new(ns_cache_size)));
        let response_cache = ResponseCache::new(response_cache_size, ttl_config);

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
            response_cache,
            #[cfg(feature = "metrics")]
            cache_metrics: RecursorCacheMetrics::new(),
            recursion_limit,
            ns_recursion_limit,
            security_aware,
            deny_server_v4,
            deny_server_v6,
            allow_server_v4,
            allow_server_v6,
            avoid_local_udp_ports,
            case_randomization,
            tls,
            conn_provider,
        }
    }

    pub(crate) async fn resolve(
        &self,
        query: Query,
        request_time: Instant,
        query_has_dnssec_ok: bool,
        depth: u8,
        cname_limit: Arc<AtomicU8>,
    ) -> Result<Message, Error> {
        if let Some(result) = self.response_cache.get(&query, request_time) {
            let response = result?;
            if response.authoritative() {
                #[cfg(feature = "metrics")]
                self.cache_metrics.cache_hit_counter.increment(1);

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

                return Ok(super::maybe_strip_dnssec_records(
                    query_has_dnssec_ok,
                    response,
                    query,
                ));
            }
        }

        #[cfg(feature = "metrics")]
        self.cache_metrics.cache_miss_counter.increment(1);

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

        let cached_response = self.filtered_cache_lookup(&query, request_time);
        let response = match cached_response {
            Some(result) => result?,
            None => self.lookup(query.clone(), ns, request_time).await?,
        };

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

    /// Handle CNAME expansion for the current query
    #[async_recursion]
    async fn resolve_cnames(
        &self,
        mut response: Message,
        query: Query,
        now: Instant,
        query_has_dnssec_ok: bool,
        mut depth: u8,
        cname_limit: Arc<AtomicU8>,
    ) -> Result<Message, Error> {
        let query_type = query.query_type();
        let query_name = query.name().clone();

        // Don't resolve CNAME lookups for a CNAME (or ANY) query
        if query_type == RecordType::CNAME || query_type == RecordType::ANY {
            return Ok(response);
        }

        depth += 1;
        Error::recursion_exceeded(self.recursion_limit, depth, &query_name)?;

        let mut cname_chain = vec![];

        for rec in response.all_sections() {
            let CNAME(name) = rec.data() else {
                continue;
            };

            // Check if the response has data for the canonical name.
            if response
                .answers()
                .iter()
                .any(|record| record.name() == &name.0)
            {
                continue;
            }

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
            let response = match self
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
            cname_chain.extend(response.answers().iter().filter_map(|r| {
                if r.record_type() == query_type || r.record_type() == RecordType::CNAME {
                    return Some(r.to_owned());
                }

                #[cfg(feature = "__dnssec")]
                if let Some(rrsig) = r.data().as_dnssec().and_then(|rdata| rdata.as_rrsig()) {
                    let type_covered = rrsig.input().type_covered;
                    if type_covered == query_type || type_covered == RecordType::CNAME {
                        return Some(r.to_owned());
                    }
                }

                None
            }));
        }

        if !cname_chain.is_empty() {
            response.answers_mut().extend(cname_chain);
        }

        Ok(response)
    }

    /// Retrieve a response from the cache, filtering out non-authoritative responses.
    fn filtered_cache_lookup(&self, query: &Query, now: Instant) -> Option<Result<Message, Error>> {
        let response = match self.response_cache.get(query, now) {
            Some(Ok(response)) => response,
            Some(Err(e)) => return Some(Err(e.into())),
            None => return None,
        };

        if !response.authoritative() {
            return None;
        }

        debug!(?response, "cached data");
        Some(Ok(response))
    }

    async fn lookup(
        &self,
        query: Query,
        ns: RecursorPool<P>,
        now: Instant,
    ) -> Result<Message, Error> {
        let response_future = ns.lookup(query.clone(), self.security_aware);

        // TODO: we are only expecting one response
        // TODO: should we change DnsHandle to always be a single response? And build a totally custom handler for other situations?
        // TODO: check if data is "authentic"
        match response_future.await {
            Ok(r) => {
                let message = r.into_message();
                self.response_cache.insert(query, Ok(message.clone()), now);
                Ok(message)
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
        mut depth: u8,
    ) -> Result<(u8, RecursorPool<P>), Error> {
        // TODO: need to check TTLs here.
        if let Some(ns) = self.name_server_cache.lock().get_mut(&zone) {
            debug!("returning cached pool for {zone}");
            return Ok((depth, ns.clone()));
        };

        trace!("ns_pool_for_zone: depth {depth} for {zone}");

        depth += 1;
        Error::recursion_exceeded(self.ns_recursion_limit, depth, &zone)?;

        let parent_zone = zone.base_name();

        let nameserver_pool = if parent_zone.is_root() {
            debug!("using roots for {zone} nameservers");
            self.roots.clone()
        } else {
            // Discard depth returned from recursive call.
            self.ns_pool_for_zone(parent_zone, request_time, depth)
                .await?
                .1
        };

        let query = Query::query(zone.clone(), RecordType::NS);

        // Query for nameserver records via the pool for the parent zone.
        let lookup_res = match self.response_cache.get(&query, request_time) {
            Some(Ok(response)) => {
                debug!(?response, "cached data");
                Ok(response)
            }
            Some(Err(e)) => Err(e.into()),
            None => {
                self.lookup(query, nameserver_pool.clone(), request_time)
                    .await
            }
        };
        let response = match lookup_res {
            Ok(response) => response,
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

        let any_ns = response
            .all_sections()
            .any(|record| record.record_type() == RecordType::NS);
        if !any_ns {
            // Not a zone cut, but there is a CNAME or other record at this name. Return the
            // same pool of name servers as above in the error case, to try again with a
            // longer name.
            return Ok((depth, nameserver_pool));
        }

        // TODO: grab TTL and use for cache
        // get all the NS records and glue
        let mut config_group = Vec::new();
        let mut need_ips_for_names = Vec::new();
        let mut glue_ips = HashMap::new();

        self.add_glue_to_map(&mut glue_ips, response.all_sections());

        for zns in response.all_sections() {
            let Some(ns_data) = zns.data().as_ns() else {
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
                if let Some(Ok(response)) = self
                    .response_cache
                    .get(&Query::query(ns_data.0.clone(), record_type), request_time)
                {
                    self.add_glue_to_map(&mut glue_ips, response.all_sections());
                }
            }

            match glue_ips.get(&ns_data.0) {
                Some(glue) if !glue.is_empty() => {
                    config_group.extend(glue.iter().copied().map(NameServerConfig::udp_and_tcp));
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
        let ns = NameServerPool::from_config(
            config_group,
            Arc::new(self.recursor_opts()),
            self.tls.clone(),
            self.conn_provider.clone(),
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

    #[cfg(all(feature = "__dnssec", feature = "metrics"))]
    pub(crate) fn cache_metrics(&self) -> &RecursorCacheMetrics {
        &self.cache_metrics
    }

    async fn append_ips_from_lookup<'a, I: Iterator<Item = &'a NS>>(
        &self,
        zone: &Name,
        depth: u8,
        request_time: Instant,
        nameserver_pool: RecursorPool<P>,
        nameservers: I,
        config: &mut Vec<NameServerConfig>,
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
                    config.extend(response
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
                        }).map(NameServerConfig::udp_and_tcp));
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
    #[cfg(feature = "__dnssec")]
    {
        options.validate = false; // we'll need to do any dnssec validation differently in a recursor (top-down rather than bottom-up)
    }
    options.preserve_intermediates = true;
    options.recursion_desired = false;
    options.num_concurrent_reqs = 1;
    options.avoid_local_udp_ports = avoid_local_udp_ports;
    options.case_randomization = case_randomization;

    options
}

#[cfg(feature = "metrics")]
#[derive(Clone)]
pub(super) struct RecursorCacheMetrics {
    pub(super) cache_hit_counter: Counter,
    pub(super) cache_miss_counter: Counter,
}

#[cfg(feature = "metrics")]
impl RecursorCacheMetrics {
    fn new() -> Self {
        let cache_hit_counter = counter!("hickory_recursor_cache_hit_total");
        describe_counter!(
            "hickory_recursor_cache_hit_total",
            Unit::Count,
            "Number of recursive requests answered from the cache."
        );
        let cache_miss_counter = counter!("hickory_recursor_cache_miss_total");
        describe_counter!(
            "hickory_recursor_cache_miss_total",
            Unit::Count,
            "Number of recursive requests that could not be answered from the cache."
        );
        Self {
            cache_hit_counter,
            cache_miss_counter,
        }
    }
}

/// Maximum number of cname records to look up in a CNAME chain, regardless of the recursion
/// depth limit
const MAX_CNAME_LOOKUPS: u8 = 64;

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
    };

    use ipnet::IpNet;

    use crate::{
        proto::runtime::TokioRuntimeProvider,
        recursor_dns_handle::RecursorDnsHandle,
        resolver::{TtlConfig, name_server::TlsConfig},
    };

    #[test]
    fn test_nameserver_filter() {
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
            Arc::new(TlsConfig::new().unwrap()),
            TokioRuntimeProvider::default(),
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
}
