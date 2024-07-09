use std::{net::SocketAddr, sync::Arc, time::Instant};

use async_recursion::async_recursion;
use futures_util::{future::select_all, FutureExt};
use lru_cache::LruCache;
use parking_lot::Mutex;
use tracing::{debug, warn};

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

        // not in cache, let's look for an ns record for lookup
        let zone = match query.query_type() {
            // (RFC4035 section 3.1.4.1) the DS record needs to be queried in the parent zone
            RecordType::DS => query.name().base_name(),

            // if DO=1 then we need to send the `NS $ZONE` query to `$ZONE` to get the
            // RRSIG records associated to the NS record
            // if DO=0 then we can send the query to the parent zone. its response won't include
            // RRSIG records but that's fine
            RecordType::NS if !query_has_dnssec_ok => query.name().base_name(),

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

        let response = self
            .lookup(query.clone(), ns, request_time, query_has_dnssec_ok)
            .await?;

        // RFC 4035 section 3.2.1 if DO bit not set, strip DNSSEC records unless
        // explicitly requested
        let lookup = super::maybe_strip_dnssec_records(query_has_dnssec_ok, response, query);

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

                if !super::is_subzone(zone.base_name().clone(), zns.name().clone()) {
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
