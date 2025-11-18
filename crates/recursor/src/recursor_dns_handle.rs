use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

use async_recursion::async_recursion;
use futures_util::{FutureExt, StreamExt, stream::FuturesUnordered};
use lru_cache::LruCache;
#[cfg(feature = "metrics")]
use metrics::{Counter, Unit, counter, describe_counter};
use parking_lot::Mutex;
use tracing::{debug, error, trace, warn};

#[cfg(feature = "__dnssec")]
use crate::proto::dnssec::{DnssecDnsHandle, TrustAnchors};
use crate::{
    DnssecPolicy, Error, ErrorKind, RecursorBuilder,
    error::AuthorityData,
    is_subzone,
    proto::{
        DnsHandle,
        access_control::AccessControlSet,
        op::{DnsRequestOptions, Message, Query},
        rr::{
            RData,
            RData::CNAME,
            Record, RecordType,
            rdata::{A, AAAA, NS},
        },
    },
    recursor::RecursorMode,
    resolver::{
        ConnectionProvider, Name, NameServer, NameServerPool, PoolContext, ResponseCache,
        TlsConfig, TtlConfig,
        config::{NameServerConfig, OpportunisticEncryption, ResolverOpts},
    },
};

#[derive(Clone)]
pub(crate) struct RecursorDnsHandle<P: ConnectionProvider> {
    roots: NameServerPool<P>,
    name_server_cache: Arc<Mutex<LruCache<Name, NameServerPool<P>>>>,
    response_cache: ResponseCache,
    #[cfg(feature = "metrics")]
    metrics: RecursorMetrics,
    recursion_limit: Option<u8>,
    ns_recursion_limit: Option<u8>,
    name_server_filter: AccessControlSet,
    pool_context: Arc<PoolContext>,
    conn_provider: P,
    connection_cache: Arc<Mutex<LruCache<IpAddr, Arc<NameServer<P>>>>>,
    request_options: DnsRequestOptions,
    ttl_config: TtlConfig,
}

impl<P: ConnectionProvider> RecursorDnsHandle<P> {
    pub(super) fn build_recursor_mode(
        roots: &[IpAddr],
        tls: TlsConfig,
        builder: RecursorBuilder<P>,
    ) -> Result<RecursorMode<P>, Error> {
        assert!(!roots.is_empty(), "roots must not be empty");
        let servers = roots
            .iter()
            .copied()
            .map(|ip| name_server_config(ip, &builder.opportunistic_encryption))
            .collect::<Vec<_>>();

        let RecursorBuilder {
            ns_cache_size,
            response_cache_size,
            recursion_limit,
            ns_recursion_limit,
            dnssec_policy,
            answer_address_filter,
            name_server_filter,
            avoid_local_udp_ports,
            ttl_config,
            case_randomization,
            opportunistic_encryption,
            encrypted_transport_state,
            conn_provider,
        } = builder;

        let avoid_local_udp_ports = Arc::new(avoid_local_udp_ports);

        debug!(
            "Using cache sizes {}/{}",
            ns_cache_size, response_cache_size
        );

        let mut pool_context = PoolContext::new(
            recursor_opts(avoid_local_udp_ports.clone(), case_randomization),
            tls,
        )
        .with_probe_budget(
            opportunistic_encryption
                .max_concurrent_probes()
                .unwrap_or_default(),
        )
        .with_transport_state(encrypted_transport_state)
        .with_answer_filter(answer_address_filter);
        pool_context.opportunistic_encryption = opportunistic_encryption;
        let pool_context = Arc::new(pool_context);

        let roots =
            NameServerPool::from_config(servers, pool_context.clone(), conn_provider.clone());

        let name_server_cache = Arc::new(Mutex::new(LruCache::new(ns_cache_size)));
        let response_cache = ResponseCache::new(response_cache_size, ttl_config.clone());

        // DnsRequestOptions to use with outbound requests made by the recursor.
        let mut request_options = DnsRequestOptions::default();
        request_options.use_edns = dnssec_policy.is_security_aware();
        request_options.edns_set_dnssec_ok = dnssec_policy.is_security_aware();
        // Set RD=0 in queries made by the recursive resolver. See the last figure in
        // section 2.2 of RFC 1035, for example. Failure to do so may allow for loops
        // between recursive resolvers following referrals to each other.
        request_options.recursion_desired = false;

        let handle = Self {
            roots,
            name_server_cache,
            response_cache,
            #[cfg(feature = "metrics")]
            metrics: RecursorMetrics::new(),
            recursion_limit,
            ns_recursion_limit,
            name_server_filter,
            pool_context,
            conn_provider,
            connection_cache: Arc::new(Mutex::new(LruCache::new(ns_cache_size))),
            request_options,
            ttl_config: ttl_config.clone(),
        };

        Ok(match dnssec_policy {
            DnssecPolicy::SecurityUnaware => RecursorMode::NonValidating { handle },

            #[cfg(feature = "__dnssec")]
            DnssecPolicy::ValidationDisabled => RecursorMode::NonValidating { handle },

            #[cfg(feature = "__dnssec")]
            DnssecPolicy::ValidateWithStaticKey {
                trust_anchor,
                nsec3_soft_iteration_limit,
                nsec3_hard_iteration_limit,
                validation_cache_size,
            } => {
                let validated_response_cache =
                    ResponseCache::new(response_cache_size, ttl_config.clone());
                let trust_anchor = match trust_anchor {
                    Some(anchor) if anchor.is_empty() => {
                        return Err(Error::from("trust anchor must not be empty"));
                    }
                    Some(anchor) => anchor,
                    None => Arc::new(TrustAnchors::default()),
                };

                #[cfg(feature = "metrics")]
                let metrics = handle.metrics().clone();

                let mut dnssec_handle = DnssecDnsHandle::with_trust_anchor(handle, trust_anchor)
                    .nsec3_iteration_limits(nsec3_soft_iteration_limit, nsec3_hard_iteration_limit)
                    .negative_validation_ttl(
                        ttl_config.negative_response_ttl_bounds(RecordType::RRSIG),
                    )
                    .positive_validation_ttl(
                        ttl_config.positive_response_ttl_bounds(RecordType::RRSIG),
                    );

                if let Some(validation_cache_size) = validation_cache_size {
                    dnssec_handle = dnssec_handle.validation_cache_size(validation_cache_size);
                }

                RecursorMode::Validating {
                    validated_response_cache,
                    #[cfg(feature = "metrics")]
                    metrics,
                    handle: dnssec_handle,
                }
            }
        })
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
                self.metrics.cache_hit_counter.increment(1);

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
        self.metrics.cache_miss_counter.increment(1);

        // Recursively search for authoritative name servers for the queried record to build an NS
        // pool to use for queries for a given zone. By searching for the query name, (e.g.
        // 'www.example.com') we should end up with the following set of queries:
        //
        // query NS . for com. -> NS list + glue for com.
        // query NS com. for example.com. -> NS list + glue for example.com.
        // query NS example.com. for www.example.com. -> no data.
        //
        // ns_pool_for_name would then return an NS pool based the results of the last NS RRset,
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
        // ns_pool_for_name would return that as the NS pool to use for the query 'example.com'.
        // The subsequent lookup request for then ask the example.com. servers to resolve
        // A example.com.

        let zone = match query.query_type() {
            RecordType::DS => query.name().base_name(),
            _ => query.name().clone(),
        };

        let (depth, ns) = match self
            .ns_pool_for_name(zone.clone(), request_time, depth)
            .await
        {
            Ok((depth, ns)) => (depth, ns),
            // Handle the short circuit case for when we receive NXDOMAIN on a parent name, per RFC
            // 8020.
            Err(e) if e.is_nx_domain() => return Err(e),
            Err(e) => return Err(Error::from(format!("no nameserver found for {zone}: {e}"))),
        };

        // Set the zone based on the longest delegation found by ns_pool_for_name.  This will
        // affect bailiwick filtering.
        let Some(zone) = ns.zone() else {
            return Err("no zone information in name server pool".into());
        };

        debug!(%zone, %query, "found zone for query");

        let cached_response = self.filtered_cache_lookup(&query, request_time);
        let response = match cached_response {
            Some(result) => result?,
            None => {
                self.lookup(query.clone(), zone.clone(), ns, request_time)
                    .await?
            }
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

    pub(crate) fn pool_context(&self) -> &Arc<PoolContext> {
        &self.pool_context
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
                return Err(ErrorKind::MaxRecordLimitExceeded {
                    count: count as usize,
                    record_type: RecordType::CNAME,
                }
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
        zone: Name,
        ns: NameServerPool<P>,
        now: Instant,
    ) -> Result<Message, Error> {
        let mut response = ns.lookup(query.clone(), self.request_options);

        #[cfg(feature = "metrics")]
        self.metrics.outgoing_query_counter.increment(1);

        // TODO: we are only expecting one response
        // TODO: should we change DnsHandle to always be a single response? And build a totally custom handler for other situations?
        let mut response = match response.next().await {
            Some(Ok(r)) => r,
            Some(Err(e)) => {
                warn!("lookup error: {e}");
                return Err(Error::from(e));
            }
            None => {
                warn!("no response to lookup for {query}");
                return Err("no response to lookup".into());
            }
        };

        let answer_filter = |record: &Record| {
            if !is_subzone(&zone, record.name()) {
                error!(
                    %record, %zone,
                    "dropping out of bailiwick record",
                );
                return false;
            }

            true
        };

        let answers_len = response.answers().len();
        let authorities_len = response.authorities().len();

        response.additionals_mut().retain(answer_filter);
        response.answers_mut().retain(answer_filter);
        response.authorities_mut().retain(answer_filter);

        // If we stripped all of the answers out, or if we stripped all of the authorities
        // out and there are no answers, return an NXDomain response.
        if response.answers().is_empty() && answers_len != 0
            || (response.answers().is_empty()
                && response.authorities().is_empty()
                && authorities_len != 0)
        {
            return Err(ErrorKind::Negative(AuthorityData::new(
                Box::new(query),
                None,
                false,
                true,
                None,
            ))
            .into());
        }

        let message = response.into_message();
        self.response_cache.insert(query, Ok(message.clone()), now);
        Ok(message)
    }

    /// Identify the correct NameServerPool to use to answer queries for a given name.
    #[async_recursion]
    pub(crate) async fn ns_pool_for_name(
        &self,
        query_name: Name,
        request_time: Instant,
        mut depth: u8,
    ) -> Result<(u8, NameServerPool<P>), Error> {
        // Build a list of every zone between the root and the query name (but not including the root.)
        let mut zones = vec![];
        for i in 1..=query_name.num_labels() {
            zones.push(query_name.trim_to(i as usize));
        }
        trace!(?zones, "looking for zones");

        let mut nameserver_pool = self.roots.clone().with_zone(Name::root());

        for zone in zones {
            if let Some(ns) = self.name_server_cache.lock().get_mut(&zone) {
                match ns.ttl_expired() {
                    true => debug!(?zone, "cached name server pool expired"),
                    false => {
                        debug!(?zone, "already have cached name server pool for zone");
                        nameserver_pool = ns.clone();
                        continue;
                    }
                }
            };

            trace!(depth, ?zone, "ns_pool_for_name: depth {depth} for {zone}");
            depth += 1;
            Error::recursion_exceeded(self.ns_recursion_limit, depth, &zone)?;

            let parent_zone = zone.base_name();

            let query = Query::query(zone.clone(), RecordType::NS);

            // Query for nameserver records via the pool for the parent zone.
            let lookup_res = match self.response_cache.get(&query, request_time) {
                Some(Ok(response)) => {
                    debug!(?response, "cached data");
                    Ok(response)
                }
                Some(Err(e)) => Err(e.into()),
                None => {
                    self.lookup(query, parent_zone, nameserver_pool.clone(), request_time)
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
                // not cache it. If this was recursively called by `ns_pool_for_name()`, the outer call
                // will try again with one more label added to the iterative query name.
                Err(_) => {
                    trace!(?zone, "no zone cut at zone");
                    continue;
                }
            };

            let any_ns = response
                .all_sections()
                .any(|record| record.record_type() == RecordType::NS);
            if !any_ns {
                // Not a zone cut, but there is a CNAME or other record at this name. Return the
                // same pool of name servers as above in the error case, to try again with a
                // longer name.
                trace!(?zone, "no zone cut at zone");
                continue;
            }

            // get all the NS records and glue
            let mut config_group = Vec::new();
            let mut need_ips_for_names = Vec::new();
            let mut glue_ips = HashMap::new();
            let (positive_min_ttl, positive_max_ttl) = self
                .ttl_config
                .positive_response_ttl_bounds(RecordType::NS)
                .into_inner();
            let mut ns_pool_ttl = u32::MAX;

            let ttl = self.add_glue_to_map(&mut glue_ips, response.all_sections());

            if ttl < ns_pool_ttl {
                ns_pool_ttl = ttl;
            }

            for zns in response.all_sections() {
                let Some(ns_data) = zns.data().as_ns() else {
                    continue;
                };

                if !super::is_subzone(&zone.base_name(), zns.name()) {
                    warn!(
                        name = ?zns.name(),
                        parent = ?zone.base_name(),
                        "dropping out of bailiwick record",
                    );
                    continue;
                }

                if zns.ttl() < ns_pool_ttl {
                    ns_pool_ttl = zns.ttl();
                }

                for record_type in [RecordType::A, RecordType::AAAA] {
                    if let Some(Ok(response)) = self
                        .response_cache
                        .get(&Query::query(ns_data.0.clone(), record_type), request_time)
                    {
                        let ttl = self.add_glue_to_map(&mut glue_ips, response.all_sections());
                        if ttl < ns_pool_ttl {
                            ns_pool_ttl = ttl;
                        }
                    }
                }

                match glue_ips.get(&ns_data.0) {
                    Some(glue) if !glue.is_empty() => {
                        config_group.extend(glue.iter().copied().map(|ip| {
                            name_server_config(ip, &self.pool_context.opportunistic_encryption)
                        }));
                    }
                    _ => {
                        debug!(name_server = ?ns_data, "glue not found for name server");
                        need_ips_for_names.push(ns_data.to_owned());
                    }
                }
            }

            // If we have no glue, collect missing nameserver IP addresses.
            // For non-child name servers, get a new pool by calling ns_pool_for_name recursively.
            // For child child name servers, we can use the existing pool, but we *must* use lookup
            // to avoid infinite recursion.
            if config_group.is_empty() && !need_ips_for_names.is_empty() {
                debug!(?zone, "need glue for zone");

                let ttl;
                (ttl, depth) = self
                    .append_ips_from_lookup(
                        &zone,
                        depth,
                        request_time,
                        nameserver_pool.clone(),
                        need_ips_for_names.iter(),
                        &mut config_group,
                    )
                    .await?;

                if ttl < ns_pool_ttl {
                    ns_pool_ttl = ttl;
                }
            }

            let servers = {
                let mut cache = self.connection_cache.lock();
                config_group
                    .iter()
                    .map(|server| {
                        if let Some(ns) = cache.get_mut(&server.ip) {
                            return ns.clone();
                        }

                        debug!(?server, "adding new name server to cache");
                        let ns = Arc::new(NameServer::new(
                            [],
                            server.clone(),
                            &self.pool_context.clone().options,
                            self.conn_provider.clone(),
                        ));
                        cache.insert(server.ip, ns.clone());
                        ns
                    })
                    .collect()
            };

            let ns_pool_ttl =
                Duration::from_secs(ns_pool_ttl as u64).clamp(positive_min_ttl, positive_max_ttl);

            nameserver_pool = NameServerPool::from_nameservers(servers, self.pool_context.clone())
                .with_ttl(ns_pool_ttl)
                .with_zone(zone.clone());

            // store in cache for future usage
            debug!(?zone, "found nameservers for {zone}");
            self.name_server_cache
                .lock()
                .insert(zone.clone(), nameserver_pool.clone());
        }

        Ok((depth, nameserver_pool))
    }

    /// Helper function to add IP addresses from any A or AAAA records to a map indexed by record
    /// name.
    fn add_glue_to_map<'a>(
        &self,
        glue_map: &mut HashMap<Name, Vec<IpAddr>>,
        records: impl Iterator<Item = &'a Record>,
    ) -> u32 {
        let mut ttl = u32::MAX;

        for record in records {
            let ip = match record.data() {
                RData::A(A(ipv4)) => (*ipv4).into(),
                RData::AAAA(AAAA(ipv6)) => (*ipv6).into(),
                _ => continue,
            };
            if self.name_server_filter.denied(ip) {
                debug!(name = %record.name(), %ip, "ignoring address due to do_not_query");
                continue;
            }
            if record.ttl() < ttl {
                ttl = record.ttl();
            }
            let ns_glue_ips = glue_map.entry(record.name().clone()).or_default();
            if !ns_glue_ips.contains(&ip) {
                ns_glue_ips.push(ip);
            }
        }

        ttl
    }

    #[cfg(all(feature = "__dnssec", feature = "metrics"))]
    pub(crate) fn metrics(&self) -> &RecursorMetrics {
        &self.metrics
    }

    async fn append_ips_from_lookup<'a, I: Iterator<Item = &'a NS>>(
        &self,
        zone: &Name,
        depth: u8,
        request_time: Instant,
        nameserver_pool: NameServerPool<P>,
        nameservers: I,
        config: &mut Vec<NameServerConfig>,
    ) -> Result<(u32, u8), Error> {
        let mut pool_queries = vec![];

        for ns in nameservers {
            let record_name = ns.0.clone();

            // For child nameservers of zone, we can reuse the pool that was passed in as
            // nameserver_pool, but for a non-child nameservers we need to get an appropriate pool.
            // To avoid incrementing the depth counter for each nameserver, we'll use the passed in
            // depth as a fixed base for the nameserver lookups
            let nameserver_pool = if !crate::is_subzone(zone, &record_name) {
                self.ns_pool_for_name(record_name.clone(), request_time, depth)
                    .await?
                    .1 // discard the depth part of the tuple
                    .with_zone(zone.clone())
            } else {
                nameserver_pool.clone()
            };

            pool_queries.push((nameserver_pool, record_name));
        }

        let mut futures = FuturesUnordered::new();

        for (pool, query) in pool_queries.iter() {
            for rec_type in [RecordType::A, RecordType::AAAA] {
                futures.push(Box::pin(
                    pool.lookup(Query::query(query.clone(), rec_type), self.request_options)
                        .into_future()
                        .map(|(first, _rest)| first),
                ));
            }
        }

        let mut ttl = u32::MAX;

        while let Some(next) = futures.next().await {
            match next {
                Some(Ok(mut response)) => {
                    debug!("append_ips_from_lookup: A or AAAA response: {response:?}");
                    config.extend(response
                        .take_answers()
                        .into_iter()
                        .filter_map(|answer| {
                            let ip = answer.data().ip_addr()?;

                            if self.name_server_filter.denied(ip) {
                                debug!(%ip, "append_ips_from_lookup: ignoring address due to do_not_query");
                                None
                            } else {
                                if answer.ttl() < ttl {
                                    ttl = answer.ttl();
                                }
                                Some(ip)
                            }
                        }).map(|ip| name_server_config(ip, &self.pool_context.opportunistic_encryption)));
                }
                Some(Err(e)) => {
                    warn!("append_ips_from_lookup: resolution failed failed: {e}");
                }
                None => {
                    warn!("no response to lookup");
                }
            }
        }

        Ok((ttl, depth))
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

fn name_server_config(
    ip: IpAddr,
    opportunistic_encryption: &OpportunisticEncryption,
) -> NameServerConfig {
    match opportunistic_encryption {
        #[cfg(any(
            feature = "tls-aws-lc-rs",
            feature = "tls-ring",
            feature = "quic-aws-lc-rs",
            feature = "quic-ring"
        ))]
        OpportunisticEncryption::Enabled { .. } => NameServerConfig::opportunistic_encryption(ip),
        _ => NameServerConfig::udp_and_tcp(ip),
    }
}

#[cfg(feature = "metrics")]
#[derive(Clone)]
pub(super) struct RecursorMetrics {
    pub(super) cache_hit_counter: Counter,
    pub(super) cache_miss_counter: Counter,
    pub(super) outgoing_query_counter: Counter,
}

#[cfg(feature = "metrics")]
impl RecursorMetrics {
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
        let outgoing_query_counter = counter!("hickory_recursor_outgoing_queries_total");
        describe_counter!(
            "hickory_recursor_outgoing_queries_total",
            Unit::Count,
            "Number of outgoing queries made during resolution."
        );
        Self {
            cache_hit_counter,
            cache_miss_counter,
            outgoing_query_counter,
        }
    }
}

/// Maximum number of cname records to look up in a CNAME chain, regardless of the recursion
/// depth limit
const MAX_CNAME_LOOKUPS: u8 = 64;

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use ipnet::IpNet;

    use crate::Recursor;
    use crate::recursor::RecursorMode;

    #[test]
    fn test_nameserver_filter() {
        let allow_server = [IpNet::new(IpAddr::from([192, 168, 0, 1]), 32).unwrap()];
        let deny_server = [
            IpNet::new(IpAddr::from(Ipv4Addr::LOCALHOST), 8).unwrap(),
            IpNet::new(IpAddr::from([192, 168, 0, 0]), 23).unwrap(),
            IpNet::new(IpAddr::from([172, 17, 0, 0]), 20).unwrap(),
        ];

        let builder = Recursor::builder()
            .clear_deny_servers() // We use addresses in the default recommended deny list.
            .deny_servers(deny_server.iter())
            .allow_servers(allow_server.iter());

        #[cfg_attr(not(feature = "__dnssec"), allow(irrefutable_let_patterns))]
        let Recursor {
            mode: RecursorMode::NonValidating { handle },
        } = builder.build(&[IpAddr::from([192, 0, 2, 1])]).unwrap()
        else {
            panic!("unexpected DNSSEC validation mode");
        };

        for addr in [
            [127, 0, 0, 0],
            [127, 0, 0, 1],
            [192, 168, 1, 0],
            [192, 168, 1, 254],
            [172, 17, 0, 1],
        ] {
            assert!(handle.name_server_filter.denied(IpAddr::from(addr)));
        }

        for addr in [[128, 0, 0, 0], [192, 168, 2, 0], [192, 168, 0, 1]] {
            assert!(!handle.name_server_filter.denied(IpAddr::from(addr)));
        }
    }
}
