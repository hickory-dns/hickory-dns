// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Structs for creating and using a Resolver
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use std::task::{Context, Poll};

use futures_util::{
    FutureExt, Stream,
    future::BoxFuture,
    lock::Mutex as AsyncMutex,
};
use once_cell::sync::Lazy;
use tracing::debug;

#[cfg(feature = "__tls")]
use crate::connection_provider::TlsConfig;
#[cfg(feature = "tokio")]
use crate::net::runtime::TokioRuntimeProvider;
use crate::{
    cache::{MAX_TTL, ResponseCache, TtlConfig},
    caching_client::CachingClient,
    config::{OpportunisticEncryption, ResolveHosts, ResolverConfig, ResolverOpts},
    connection_provider::ConnectionProvider,
    hosts::Hosts,
    lookup::Lookup,
    lookup_ip::{LookupIp, LookupIpFuture},
    name_server_pool::{NameServerPool, NameServerTransportState, PoolContext},
    net::{
        NetError,
        xfer::{DnsHandle, RetryDnsHandle},
    },
    proto::{
        op::{DnsRequest, DnsRequestOptions, DnsResponse, Query},
        rr::domain::usage::ONION,
        rr::{IntoName, Name, RData, Record, RecordType},
    },
};
#[cfg(feature = "__dnssec")]
use crate::{net::dnssec::DnssecDnsHandle, proto::dnssec::TrustAnchors};

macro_rules! lookup_fn {
    ($p:ident, $r:path) => {
        /// Performs a lookup for the associated type.
        ///
        /// *hint* queries that end with a '.' are fully qualified names and are cheaper lookups
        ///
        /// # Arguments
        ///
        /// * `query` - a string which parses to a domain name, failure to parse will return an error
        #[inline]
        pub async fn $p(&self, query: impl IntoName) -> Result<Lookup, NetError> {
            self.inner_lookup(query.into_name()?, $r, self.request_options())
                .await
        }
    };
}

/// A Resolver used with Tokio
#[cfg(feature = "tokio")]
pub type TokioResolver = Resolver<TokioRuntimeProvider>;

#[cfg(feature = "tokio")]
impl TokioResolver {
    /// Constructs a new Tokio based Resolver with the system configuration.
    ///
    /// This will use `/etc/resolv.conf` on Unix OSes and the registry on Windows.
    #[cfg(any(unix, target_os = "windows"))]
    #[cfg(feature = "system-config")]
    pub fn builder_tokio() -> Result<ResolverBuilder<TokioRuntimeProvider>, NetError> {
        Self::builder(TokioRuntimeProvider::default())
    }
}

/// An asynchronous resolver for DNS generic over async Runtimes.
///
/// The lookup methods on `Resolver` spawn background tasks to perform
/// queries. The futures returned by a `Resolver` and the corresponding
/// background tasks need not be spawned on the same executor, or be in the
/// same thread.
///
/// *NOTE* If lookup futures returned by a `Resolver` and the background
/// tasks are spawned on two separate `CurrentThread` executors, one thread
/// cannot run both executors simultaneously, so the `run` or `block_on`
/// functions will cause the thread to deadlock. If both the background work
/// and the lookup futures are intended to be run on the same thread, they
/// should be spawned on the same executor.
#[derive(Clone)]
pub struct Resolver<P: ConnectionProvider> {
    domain: Option<Name>,
    // Arc<[Name]> instead of Vec<Name>: Resolver::clone becomes a pointer increment
    // rather than a deep copy of the entire search list.
    search: Arc<[Name]>,
    context: Arc<PoolContext>,
    client_cache: CachingClient<LookupEither<P>>,
    hosts: Arc<Hosts>,
    // Precomputed once at build time; options are immutable after construction.
    request_opts: DnsRequestOptions,
}

impl<R: ConnectionProvider> Resolver<R> {
    /// Constructs a new [`Resolver`] via [`ResolverBuilder`] with the operating system's
    /// configuration.
    ///
    /// To use this with Tokio, see [TokioResolver::builder_tokio] instead.
    ///
    /// This will use `/etc/resolv.conf` on Unix OSes and the registry on Windows.
    #[cfg(any(unix, target_os = "windows"))]
    #[cfg(feature = "system-config")]
    pub fn builder(provider: R) -> Result<ResolverBuilder<R>, NetError> {
        let (config, options) = super::system_conf::read_system_conf()?;
        let mut builder = Self::builder_with_config(config, provider);
        *builder.options_mut() = options;
        Ok(builder)
    }

    /// Construct a new [`Resolver`] via [`ResolverBuilder`] with the provided configuration.
    pub fn builder_with_config(config: ResolverConfig, provider: R) -> ResolverBuilder<R> {
        ResolverBuilder {
            config,
            options: ResolverOpts::default(),
            provider,
            #[cfg(feature = "__tls")]
            tls: None,
            opportunistic_encryption: OpportunisticEncryption::default(),
            encrypted_transport_state: NameServerTransportState::default(),
            #[cfg(feature = "__dnssec")]
            trust_anchor: None,
            #[cfg(feature = "__dnssec")]
            nsec3_soft_iteration_limit: None,
            #[cfg(feature = "__dnssec")]
            nsec3_hard_iteration_limit: None,
        }
    }

    /// Customizes the static hosts used in this resolver.
    pub fn set_hosts(&mut self, hosts: Arc<Hosts>) {
        self.hosts = hosts;
    }

    /// Generic lookup for any RecordType
    ///
    /// *WARNING* this interface may change in the future, see if one of the specializations would be better.
    ///
    /// # Arguments
    ///
    /// * `name` - name of the record to lookup, if name is not a valid domain name, an error will be returned
    /// * `record_type` - type of record to lookup, all RecordData responses will be filtered to this type
    ///
    /// # Returns
    ///
    //  A future for the returned Lookup RData
    pub async fn lookup(
        &self,
        name: impl IntoName,
        record_type: RecordType,
    ) -> Result<Lookup, NetError> {
        self.inner_lookup(name.into_name()?, record_type, self.request_options())
            .await
    }

    pub(crate) async fn inner_lookup<L>(
        &self,
        name: Name,
        record_type: RecordType,
        options: DnsRequestOptions,
    ) -> Result<L, NetError>
    where
        L: From<Lookup> + Send + Sync + 'static,
    {
        // Fast path: no search expansion will occur — either the name is already
        // fully qualified, or there is no domain/search list to expand against.
        // In both cases we normalise to FQDN, bypass build_names and LookupFuture
        // entirely, and avoid their Vec + BoxFuture allocations.
        // This is the dominant production path (names ending with '.').
        if name.is_fqdn() || (self.search.is_empty() && self.domain.is_none()) {
            let mut fqdn = name;
            if !fqdn.is_fqdn() {
                fqdn.set_fqdn(true);
            }
            let query = Query::new(fqdn, record_type);
            let lookup = if let Some(hit) = self.hosts.lookup_static_host(&query) {
                hit
            } else {
                self.client_cache.clone().lookup(query, options).await?
            };
            return Ok(L::from(lookup));
        }

        let names = self.build_names(name);
        LookupFuture::lookup_with_hosts(
            names,
            record_type,
            options,
            self.client_cache.clone(),
            self.hosts.clone(),
        )
        .await
        .map(L::from)
    }

    /// Performs a dual-stack DNS lookup for the IP for the given hostname.
    ///
    /// See the configuration and options parameters for controlling the way in which A(Ipv4) and AAAA(Ipv6) lookups will be performed. For the least expensive query a fully-qualified-domain-name, FQDN, which ends in a final `.`, e.g. `www.example.com.`, will only issue one query. Anything else will always incur the cost of querying the `ResolverConfig::domain` and `ResolverConfig::search`.
    ///
    /// # Arguments
    /// * `host` - string hostname, if this is an invalid hostname, an error will be returned.
    pub async fn lookup_ip(&self, host: impl IntoName) -> Result<LookupIp, NetError> {
        let maybe_ip = host.to_ip().map(RData::from);
        let maybe_name = host.into_name().map_err(NetError::from);

        // If host is an IP address, return it directly — no DNS lookup needed
        // regardless of ndots. Search-list expansion on an IP literal is always
        // semantically meaningless (e.g. 198.51.100.35.example.com is not a
        // valid resolution of an IP address). Both ndots branches are now unified.
        if let Some(ip_addr) = maybe_ip {
            // Fall back to Name::default() when the IP string failed name-parsing
            // (e.g. bare IPv6 addresses that contain ':').
            let name = maybe_name.as_ref().ok().cloned().unwrap_or_default();
            let record_type = ip_addr.record_type();
            let record = Record::from_rdata(name, MAX_TTL, ip_addr);
            let query = Query::new(record.name.clone(), record_type);
            let lookup = Lookup::new_with_max_ttl(query, [record]);
            return Ok(lookup.into());
        }

        // Not an IP address — proceed with DNS name resolution.
        let name = maybe_name?;
        let names = self.build_names(name);

        LookupIpFuture::lookup(
            names,
            self.context.options.ip_strategy,
            self.client_cache.clone(),
            self.request_options(),
            self.hosts.clone(),
            None,  // no pre-resolved IP addr (always None after early return above)
        )
        .await
    }

    /// Clear the cache for a specific lookup
    ///
    /// # Arguments
    ///
    /// * `name` - name of the record to clear
    /// * `record_type` - type of record to clear
    ///
    pub fn clear_lookup_cache(&self, name: impl IntoName, record_type: RecordType) {
        let Ok(name) = name.into_name() else {
            return;
        };

        // Fast path: mirrors inner_lookup — if no search expansion is possible,
        // normalise to FQDN, clear the single cache key, and return early.
        if name.is_fqdn() || (self.search.is_empty() && self.domain.is_none()) {
            let mut fqdn = name;
            if !fqdn.is_fqdn() {
                fqdn.set_fqdn(true);
            }
            self.client_cache.clear_cache_query(&Query::new(fqdn, record_type));
            return;
        }

        for name in self.build_names(name) {
            let query = Query::new(name, record_type);
            self.client_cache.clear_cache_query(&query);
        }
    }

    fn build_names(&self, name: Name) -> Vec<Name> {
        // if it's fully qualified, we can short circuit the lookup logic
        if name.is_fqdn() || Self::is_onion_v3(&name) {
            // if already fully qualified, or if onion address, don't assume it might be a
            // sub-domain
            vec![name]
        } else {
            // Otherwise we have to build the search list
            // Note: the vec is built in reverse order of precedence, for stack semantics
            // +1 FQDN (either prepended or appended), +1 DOMAIN, +search entries.
            // Previous capacity was 2+search.len() which could be short by 1 in the
            // raw_name_first=true branch. Use 3 to avoid any reallocation.
            // Maximum entries: 1 FQDN + search.len() domain-appended names + 1 domain.
            let mut names = Vec::<Name>::with_capacity(self.search.len() + 2);

            // if not meeting ndots, we always do the raw name in the final lookup, or it's a localhost...
            let raw_name_first: bool =
                name.num_labels() as usize > self.context.options.ndots || name.is_localhost();

            // Hoist fqdn construction — used in both branches, built exactly once.
            let mut fqdn_name = name.clone();
            fqdn_name.set_fqdn(true);

            if !raw_name_first {
                names.push(fqdn_name.clone());
            }

            for search in self.search.iter().rev() {
                let name_search = name.clone().append_domain(search);

                match name_search {
                    Ok(name_search) => names.push(name_search),
                    Err(e) => debug!(
                        "Not adding {} to {} for search due to error: {}",
                        search, name, e
                    ),
                }
            }

            if let Some(domain) = &self.domain {
                let name_search = name.clone().append_domain(domain);

                match name_search {
                    Ok(name_search) => names.push(name_search),
                    Err(e) => debug!(
                        "Not adding {} to {} for search due to error: {}",
                        domain, name, e
                    ),
                }
            }

            // Consume the pre-built fqdn_name — no extra clone or set_fqdn needed.
            if raw_name_first {
                names.push(fqdn_name);
            }

            // Remove any duplicates that arise when `domain` matches one of the
            // `search` entries. Only runs when both `domain` and at least one
            // `search` entry are set — the only configuration where duplicates
            // are possible.
            //
            // Search lists are capped at 6 entries (RFC 1535), so a u16 bitmask
            // tracks which indices are already present, giving O(n) with zero
            // allocation and no Vec::remove memmove.
            if self.domain.is_some() && !self.search.is_empty() {
                let mut seen: u32 = 0;
                let mut out = 0usize;
                for i in 0..names.len() {
                    // Check whether an identical name appeared earlier.
                    let already_seen = names[..i]
                        .iter()
                        .enumerate()
                        .any(|(j, n)| seen & (1u32 << j) != 0 && n == &names[i]);
                    if !already_seen {
                        seen |= 1u32 << i;
                        if out != i {
                            names.swap(out, i);
                        }
                        out += 1;
                    }
                }
                names.truncate(out);
            }

            names
        }
    }

    /// Returns true if `name` is a valid Tor v3 .onion address.
    ///
    /// Avoids the expensive `ONION.zone_of()` call for non-.onion names by first
    /// checking whether the last label is literally `"onion"`. The vast majority
    /// of lookups short-circuit here at zero cost.
    #[inline]
    fn is_onion_v3(name: &Name) -> bool {
        // Quick rejection: last label must be exactly b"onion" (case-insensitive).
        if !name.iter().last().map(|l| l.eq_ignore_ascii_case(b"onion")).unwrap_or(false) {
            return false;
        }
        // Full check: must be within the .onion zone and the host label must be
        // 56 bytes (Tor v3 base32-encoded public key).
        //
        // rev().nth(1) skips the trailing "onion" label and peeks at the SLD
        // (second-to-last label = the v3 public key) with zero allocation,
        // replacing the previous trim_to(2) which constructed a new Name.
        ONION.zone_of(name)
            && name
                .iter()
                .rev()
                .nth(1)
                .map(|label| label.len() == 56)
                .unwrap_or(false)
    }

    lookup_fn!(reverse_lookup, RecordType::PTR);
    lookup_fn!(ipv4_lookup, RecordType::A);
    lookup_fn!(ipv6_lookup, RecordType::AAAA);
    lookup_fn!(mx_lookup, RecordType::MX);
    lookup_fn!(ns_lookup, RecordType::NS);
    lookup_fn!(smimea_lookup, RecordType::SMIMEA);
    lookup_fn!(soa_lookup, RecordType::SOA);
    lookup_fn!(srv_lookup, RecordType::SRV);
    lookup_fn!(tlsa_lookup, RecordType::TLSA);
    lookup_fn!(txt_lookup, RecordType::TXT);
    lookup_fn!(cert_lookup, RecordType::CERT);

    /// Flushes/Removes all entries from the cache
    pub fn clear_cache(&self) {
        self.client_cache.clear_cache();
    }

    /// Per request options based on the ResolverOpts
    pub(crate) fn request_options(&self) -> DnsRequestOptions {
        self.request_opts
    }

    /// Build request options from resolver opts (called once at construction).
    fn build_request_options(options: &ResolverOpts) -> DnsRequestOptions {
        let mut request_opts = DnsRequestOptions::default();
        request_opts.recursion_desired = options.recursion_desired;
        request_opts.use_edns = options.edns0;
        request_opts.edns_payload_len = options.edns_payload_len;
        request_opts.case_randomization = options.case_randomization;

        // Set DNSSEC OK bit when DNSSEC validation is enabled
        #[cfg(feature = "__dnssec")]
        {
            request_opts.edns_set_dnssec_ok = options.validate;
        }

        request_opts
    }

    /// Read the options for this resolver.
    pub fn options(&self) -> &ResolverOpts {
        &self.context.options
    }

    /// Returns a reference to the resolver options without cloning.
    ///
    /// Prefer this over [`options()`][Self::options] in hot paths to avoid
    /// any future regression if the return type is ever changed to an owned
    /// value. Currently both return a reference; this method makes the
    /// borrow intent explicit at the call site.
    #[inline]
    pub fn options_ref(&self) -> &ResolverOpts {
        &self.context.options
    }
}

impl<P: ConnectionProvider> fmt::Debug for Resolver<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resolver")
            .field("domain", &self.domain)
            .field("search_count", &self.search.len())
            .field("cache_size", &self.context.options.cache_size)
            .finish_non_exhaustive()
    }
}

/// Different lookup options for the lookup attempts and validation
#[derive(Clone)]
enum LookupEither<P: ConnectionProvider> {
    Retry(RetryDnsHandle<NameServerPool<P>>),
    #[cfg(feature = "__dnssec")]
    Secure(DnssecDnsHandle<RetryDnsHandle<NameServerPool<P>>>),
}

impl<P: ConnectionProvider> DnsHandle for LookupEither<P> {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, NetError>> + Send>>;
    type Runtime = P::RuntimeProvider;

    #[inline]
    fn is_verifying_dnssec(&self) -> bool {
        match self {
            Self::Retry(c) => c.is_verifying_dnssec(),
            #[cfg(feature = "__dnssec")]
            Self::Secure(c) => c.is_verifying_dnssec(),
        }
    }

    #[inline]
    fn send(&self, request: DnsRequest) -> Self::Response {
        match self {
            Self::Retry(c) => c.send(request),
            #[cfg(feature = "__dnssec")]
            Self::Secure(c) => c.send(request),
        }
    }
}

/// A builder to construct a [`Resolver`].
///
/// Created by [`Resolver::builder`].
pub struct ResolverBuilder<P> {
    config: ResolverConfig,
    options: ResolverOpts,
    provider: P,

    #[cfg(feature = "__tls")]
    tls: Option<rustls::ClientConfig>,
    opportunistic_encryption: OpportunisticEncryption,
    encrypted_transport_state: NameServerTransportState,
    #[cfg(feature = "__dnssec")]
    trust_anchor: Option<Arc<TrustAnchors>>,
    #[cfg(feature = "__dnssec")]
    nsec3_soft_iteration_limit: Option<u16>,
    #[cfg(feature = "__dnssec")]
    nsec3_hard_iteration_limit: Option<u16>,
}

impl<P: ConnectionProvider> ResolverBuilder<P> {
    /// Sets the [`ResolverOpts`] to be used by the resolver.
    ///
    /// NB: A [`ResolverBuilder<P>`] will use the system configuration e.g., `resolv.conf`, by
    /// default. Usage of this method will overwrite any options set by the system configuration.
    ///
    /// See [`system_conf`][crate::system_conf] for functions that can parse a [`ResolverOpts`]
    /// from the system configuration, or use [`options_mut()`][ResolverBuilder::with_options] to
    /// acquire a muitable reference to the existing [`ResolverOpts`].
    pub fn with_options(mut self, options: ResolverOpts) -> Self {
        self.options = options;
        self
    }

    /// Returns a mutable reference to the [`ResolverOpts`].
    pub fn options_mut(&mut self) -> &mut ResolverOpts {
        &mut self.options
    }

    /// Set the DNSSEC trust anchors to be used by the resolver.
    #[cfg(feature = "__dnssec")]
    pub fn with_trust_anchor(mut self, trust_anchor: Arc<TrustAnchors>) -> Self {
        self.trust_anchor = Some(trust_anchor);
        self
    }

    /// Set the TLS configuration to be used by the resolver.
    #[cfg(feature = "__tls")]
    pub fn with_tls_config(mut self, config: rustls::ClientConfig) -> Self {
        self.tls = Some(config);
        self
    }

    /// Set the opportunistic encryption configuration to be used by the resolver.
    pub fn with_opportunistic_encryption(
        mut self,
        opportunistic_encryption: OpportunisticEncryption,
    ) -> Self {
        self.opportunistic_encryption = opportunistic_encryption;
        self
    }

    /// Set pre-existing encrypted transport state for use with opportunistic encryption.
    pub fn with_encrypted_transport_state(
        mut self,
        encrypted_transport_state: NameServerTransportState,
    ) -> Self {
        self.encrypted_transport_state = encrypted_transport_state;
        self
    }

    /// Set maximum limits on NSEC3 additional iterations.
    ///
    /// See [RFC 9276](https://www.rfc-editor.org/rfc/rfc9276.html). Signed
    /// zones that exceed the soft limit will be treated as insecure, and signed
    /// zones that exceed the hard limit will be treated as bogus.
    #[cfg(feature = "__dnssec")]
    pub fn nsec3_iteration_limits(
        mut self,
        soft_limit: Option<u16>,
        hard_limit: Option<u16>,
    ) -> Self {
        self.nsec3_soft_iteration_limit = soft_limit;
        self.nsec3_hard_iteration_limit = hard_limit;
        self
    }

    /// Construct the resolver.
    pub fn build(self) -> Result<Resolver<P>, NetError> {
        #[cfg_attr(not(feature = "__dnssec"), allow(unused_mut))]
        let Self {
            config:
                ResolverConfig {
                    domain,
                    search,
                    name_servers,
                },
            mut options,
            provider,
            #[cfg(feature = "__tls")]
            tls,
            #[cfg(feature = "__dnssec")]
            trust_anchor,
            #[cfg(feature = "__dnssec")]
            nsec3_soft_iteration_limit,
            #[cfg(feature = "__dnssec")]
            nsec3_hard_iteration_limit,
            opportunistic_encryption,
            encrypted_transport_state,
        } = self;

        #[cfg(feature = "__dnssec")]
        if trust_anchor.is_some() || options.trust_anchor.is_some() {
            options.validate = true;
        }

        let context = Arc::new(PoolContext {
            answer_address_filter: options.answer_address_filter(),
            options,
            #[cfg(feature = "__tls")]
            tls: match tls {
                Some(config) => config,
                None => TlsConfig::new()?.config,
            },
            opportunistic_probe_budget: AtomicU8::new(
                opportunistic_encryption
                    .max_concurrent_probes()
                    .unwrap_or_default(),
            ),
            opportunistic_encryption,
            transport_state: AsyncMutex::new(encrypted_transport_state),
        });

        let pool = NameServerPool::from_config(name_servers, context.clone(), provider);

        let client = RetryDnsHandle::new(pool, context.options.attempts);

        #[cfg(feature = "__dnssec")]
        let either = if context.options.validate {
            let trust_anchor = trust_anchor
                .unwrap_or_else(|| Arc::clone(&DEFAULT_TRUST_ANCHOR));

            LookupEither::Secure(
                DnssecDnsHandle::with_trust_anchor(client, trust_anchor)
                    .nsec3_iteration_limits(nsec3_soft_iteration_limit, nsec3_hard_iteration_limit),
            )
        } else {
            LookupEither::Retry(client)
        };
        #[cfg(not(feature = "__dnssec"))]
        let either = LookupEither::Retry(client);

        if context.options.cache_size == 0 {
            tracing::warn!(
                "cache_size is 0 — response caching is disabled; all DNS lookups will hit the network. Set ResolverOpts::cache_size to a non-zero value to enable caching."
            );
        }

        let cache = ResponseCache::new(
            context.options.cache_size,
            TtlConfig::from_opts(&context.options),
        );
        let client_cache =
            CachingClient::with_cache(cache, either, context.options.preserve_intermediates);

        let hosts = Arc::new(match context.options.use_hosts_file {
            ResolveHosts::Always | ResolveHosts::Auto => Hosts::from_system().unwrap_or_default(),
            ResolveHosts::Never => Hosts::default(),
        });

        let request_opts = Resolver::<P>::build_request_options(&context.options);

        Ok(Resolver {
            domain,
            search: search.into(),  // Vec<Name> → Arc<[Name]>, one allocation, then free clones
            context,
            client_cache,
            hosts,
            request_opts,
        })
    }
}

// Shared empty hosts instance — avoids a heap allocation on every plain `lookup()` call.
static EMPTY_HOSTS: Lazy<Arc<Hosts>> = Lazy::new(|| Arc::new(Hosts::default()));

// Default DNSSEC trust anchors — built from embedded root data once, then shared.
#[cfg(feature = "__dnssec")]
static DEFAULT_TRUST_ANCHOR: Lazy<Arc<TrustAnchors>> =
    Lazy::new(|| Arc::new(TrustAnchors::default()));

/// Internal state for [`LookupFuture`] — avoids a per-retry `Box` allocation
/// by separating "a live future to poll" from "an immediately-available value".
///
/// The type parameter from `LookupFuture<C>` is not needed here because
/// `BoxFuture` is already type-erased; `QueryState` is not generic.
enum QueryState {
    /// A network/cache future is in progress; poll it.
    Running(BoxFuture<'static, Result<Lookup, NetError>>),
    /// An immediately-ready result (hosts-file hit or name-parse error).
    /// Wrapped in `Option` so the value can be taken out without cloning.
    Ready(Option<Result<Lookup, NetError>>),
}

impl QueryState {
    fn from_future(f: BoxFuture<'static, Result<Lookup, NetError>>) -> Self {
        Self::Running(f)
    }
    fn ready(val: Result<Lookup, NetError>) -> Self {
        Self::Ready(Some(val))
    }
}

/// The Future returned from [`Resolver`] when performing a lookup.
#[doc(hidden)]
pub struct LookupFuture<C>
where
    C: DnsHandle + 'static,
{
    client_cache: CachingClient<C>,
    names: Vec<Name>,
    record_type: RecordType,
    options: DnsRequestOptions,
    /// Per-attempt query state. Using an enum avoids boxing a `Ready` value
    /// (hosts-file hits) and makes future substitution on retry explicit.
    query: QueryState,
}

impl<C> LookupFuture<C>
where
    C: DnsHandle + 'static,
{
    /// Perform a lookup from a name and type to a set of RDatas
    ///
    /// # Arguments
    ///
    /// * `names` - a set of DNS names to attempt to resolve, they will be attempted in queue order, i.e. the first is `names.pop()`. Upon each failure, the next will be attempted.
    /// * `record_type` - type of record being sought
    /// * `client_cache` - cache with a connection to use for performing all lookups
    #[doc(hidden)]
    pub fn lookup(
        names: Vec<Name>,
        record_type: RecordType,
        options: DnsRequestOptions,
        client_cache: CachingClient<C>,
    ) -> Self {
        Self::lookup_with_hosts(
            names,
            record_type,
            options,
            client_cache,
            Arc::clone(&EMPTY_HOSTS),  // §5: reuse shared empty hosts; no heap alloc
        )
    }

    /// Perform a lookup from a name and type to a set of RDatas, taking the local
    /// hosts file into account.
    ///
    /// # Arguments
    ///
    /// * `names` - a set of DNS names to attempt to resolve, they will be attempted in queue order, i.e. the first is `names.pop()`. Upon each failure, the next will be attempted.
    /// * `record_type` - type of record being sought
    /// * `client_cache` - cache with a connection to use for performing all lookups
    /// * `hosts` - the local host file, the records inside it will be prioritized over the upstream DNS server
    #[doc(hidden)]
    pub fn lookup_with_hosts(
        mut names: Vec<Name>,
        record_type: RecordType,
        options: DnsRequestOptions,
        client_cache: CachingClient<C>,
        hosts: Arc<Hosts>,
    ) -> Self {
        let name = names
            .pop()
            .ok_or(NetError::Message("can not lookup for no names"));

        let query = match name {
            Ok(name) => {
                let query = Query::new(name, record_type);

                if let Some(lookup) = hosts.lookup_static_host(&query) {
                    // Hosts-file hit: no heap allocation — store directly as Ready.
                    QueryState::ready(Ok(lookup))
                } else {
                    // Network/cache lookup: one Box allocation for this attempt.
                    QueryState::from_future(client_cache.lookup(query, options).boxed())
                }
            }
            Err(err) => QueryState::ready(Err(err)),
        };

        Self {
            client_cache,
            names,
            record_type,
            options,
            query,
        }
    }
}

impl<C> Future for LookupFuture<C>
where
    C: DnsHandle + 'static,
{
    type Output = Result<Lookup, NetError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            // Resolve the current query state into a Poll result.
            let result = match &mut self.query {
                QueryState::Running(fut) => {
                    // Poll the live future. Pending → yield immediately.
                    match fut.as_mut().poll_unpin(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(val) => val,
                    }
                }
                QueryState::Ready(slot) => {
                    // Immediately-ready value (hosts hit or name-parse error).
                    // Take the value out so we can move it.
                    slot.take().expect("QueryState::Ready polled after completion")
                }
            };

            // Dispatch on the resolved result:
            //   Ok with answers  → success, return immediately (no retry)
            //   Ok empty         → treat as miss, retry next name
            //   Err              → treat as miss, retry next name
            if let Ok(ref lookup) = result {
                if !lookup.answers().is_empty() {
                    return Poll::Ready(result);
                }
            }

            // Retry with the next name candidate if one is available.
            if let Some(name) = self.names.pop() {
                let record_type = self.record_type;
                let options = self.options;
                // Replace the state with a new Running future.
                // One Box allocation per name attempt — not per poll cycle.
                self.query = QueryState::from_future(
                    self.client_cache
                        .lookup(Query::new(name, record_type), options)
                        .boxed(),
                );
                continue;
            }

            // No more names to try — surface the last result (empty lookup or error).
            return Poll::Ready(result);
        }
    }
}

/// Unit tests compatible with different runtime.
#[cfg(all(test, feature = "tokio"))]
pub(crate) mod testing {
    use std::{net::*, str::FromStr};

    use tokio::runtime::Runtime;

    use crate::config::{GOOGLE, LookupIpStrategy, NameServerConfig, ResolverConfig};
    use crate::connection_provider::ConnectionProvider;
    use crate::net::runtime::TokioRuntimeProvider;
    use crate::proto::rr::Name;
    use crate::resolver::Resolver;

    /// Test IP lookup from URLs.
    pub(crate) async fn lookup_test<R: ConnectionProvider>(config: ResolverConfig, handle: R) {
        let resolver = Resolver::<R>::builder_with_config(config, handle)
            .build()
            .unwrap();

        let response = resolver
            .lookup_ip("www.example.com.")
            .await
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);
    }

    /// Test IP lookup from IP literals.
    pub(crate) async fn ip_lookup_test<R: ConnectionProvider>(handle: R) {
        let resolver =
            Resolver::<R>::builder_with_config(ResolverConfig::udp_and_tcp(&GOOGLE), handle)
                .build()
                .unwrap();

        let response = resolver
            .lookup_ip("10.1.0.2")
            .await
            .expect("failed to run lookup");

        assert_eq!(
            Some(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2))),
            response.iter().next()
        );

        let response = resolver
            .lookup_ip("2606:2800:21f:cb07:6820:80da:af6b:8b2c")
            .await
            .expect("failed to run lookup");

        assert_eq!(
            Some(IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
            ))),
            response.iter().next()
        );
    }

    /// Test IP lookup from IP literals across threads.
    pub(crate) fn ip_lookup_across_threads_test(handle: TokioRuntimeProvider) {
        // Test ensuring that running the background task on a separate
        // executor in a separate thread from the futures returned by the
        // Resolver works correctly.
        use std::thread;
        let resolver = Resolver::builder_with_config(ResolverConfig::udp_and_tcp(&GOOGLE), handle)
            .build()
            .unwrap();

        let resolver_one = resolver.clone();
        let resolver_two = resolver;

        let test_fn = |resolver: Resolver<TokioRuntimeProvider>| {
            let exec = Runtime::new().unwrap();

            let response = exec
                .block_on(resolver.lookup_ip("10.1.0.2"))
                .expect("failed to run lookup");

            assert_eq!(
                Some(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2))),
                response.iter().next()
            );

            let response = exec
                .block_on(resolver.lookup_ip("2606:2800:21f:cb07:6820:80da:af6b:8b2c"))
                .expect("failed to run lookup");

            assert_eq!(
                Some(IpAddr::V6(Ipv6Addr::new(
                    0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
                ))),
                response.iter().next()
            );
        };

        let thread_one = thread::spawn(move || {
            test_fn(resolver_one);
        });

        let thread_two = thread::spawn(move || {
            test_fn(resolver_two);
        });

        thread_one.join().expect("thread_one failed");
        thread_two.join().expect("thread_two failed");
    }

    /// Test IP lookup from URLs with DNSSEC validation.
    #[cfg(feature = "__dnssec")]
    #[allow(clippy::print_stdout)]
    pub(crate) async fn sec_lookup_test<R: ConnectionProvider>(handle: R) {
        let mut resolver_builder =
            Resolver::builder_with_config(ResolverConfig::udp_and_tcp(&GOOGLE), handle);
        resolver_builder.options_mut().validate = true;
        resolver_builder.options_mut().try_tcp_on_error = true;
        let resolver = resolver_builder.build().unwrap();

        let response = resolver
            .lookup_ip("cloudflare.com.")
            .await
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);
        println!(
            "{:?}",
            response
                .as_lookup()
                .message()
                .all_sections()
                .collect::<Vec<_>>()
        );
        assert!(
            response
                .as_lookup()
                .message()
                .all_sections()
                .any(|record| record.proof.is_secure())
        );
    }

    /// Test IP lookup from domains that exist but unsigned with DNSSEC validation.
    #[cfg(feature = "__dnssec")]
    #[allow(clippy::print_stdout)]
    pub(crate) async fn sec_lookup_fails_test<R: ConnectionProvider>(handle: R) {
        let mut resolver_builder =
            Resolver::builder_with_config(ResolverConfig::udp_and_tcp(&GOOGLE), handle);
        resolver_builder.options_mut().validate = true;
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        let resolver = resolver_builder.build().unwrap();

        // needs to be a domain that exists, but is not signed (eventually this will be)
        let response = resolver.lookup_ip("hickory-dns.org.").await;

        let lookup_ip = response.unwrap();
        println!(
            "{:?}",
            lookup_ip
                .as_lookup()
                .message()
                .all_sections()
                .collect::<Vec<_>>()
        );
        for record in lookup_ip.as_lookup().message().all_sections() {
            assert!(record.proof.is_insecure());
        }
    }

    /// Test Resolver created from system configuration with IP lookup.
    #[cfg(feature = "system-config")]
    pub(crate) async fn system_lookup_test<R: ConnectionProvider>(handle: R) {
        let resolver = Resolver::<R>::builder(handle)
            .expect("failed to create resolver")
            .build()
            .unwrap();

        let response = resolver
            .lookup_ip("www.example.com.")
            .await
            .expect("failed to run lookup");

        assert_eq!(response.iter().count(), 2);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)));
            } else {
                assert_eq!(
                    address,
                    IpAddr::V6(Ipv6Addr::new(
                        0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
                    ))
                );
            }
        }
    }

    /// Test Resolver created from system configuration with host lookups.
    #[cfg(all(unix, feature = "system-config"))]
    pub(crate) async fn hosts_lookup_test<R: ConnectionProvider>(handle: R) {
        let resolver = Resolver::<R>::builder(handle)
            .expect("failed to create resolver")
            .build()
            .unwrap();

        let response = resolver
            .lookup_ip("a.com")
            .await
            .expect("failed to run lookup");

        assert_eq!(response.iter().count(), 1);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(10, 1, 0, 104)));
            } else {
                panic!("failed to run lookup");
            }
        }
    }

    /// Test fqdn.
    pub(crate) async fn fqdn_test<R: ConnectionProvider>(handle: R) {
        let domain = Name::from_str("incorrect.example.com.").unwrap();
        let search = vec![
            Name::from_str("bad.example.com.").unwrap(),
            Name::from_str("wrong.example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> = ResolverConfig::udp_and_tcp(&GOOGLE)
            .name_servers()
            .to_owned();

        let mut resolver_builder = Resolver::<R>::builder_with_config(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            handle,
        );
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        let resolver = resolver_builder.build().unwrap();

        let response = resolver
            .lookup_ip("www.example.com.")
            .await
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);
        for address in response.iter() {
            assert!(address.is_ipv4(), "should only be looking up IPv4");
        }
    }

    /// Test ndots with non-fqdn.
    pub(crate) async fn ndots_test<R: ConnectionProvider>(handle: R) {
        let domain = Name::from_str("incorrect.example.com.").unwrap();
        let search = vec![
            Name::from_str("bad.example.com.").unwrap(),
            Name::from_str("wrong.example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> = ResolverConfig::udp_and_tcp(&GOOGLE)
            .name_servers()
            .to_owned();

        let mut resolver_builder = Resolver::<R>::builder_with_config(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            handle,
        );
        // our name does have 2, the default should be fine, let's just narrow the test criteria a bit.
        resolver_builder.options_mut().ndots = 2;
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        let resolver = resolver_builder.build().unwrap();

        // notice this is not a FQDN, no trailing dot.
        let response = resolver
            .lookup_ip("www.example.com")
            .await
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);
        for address in response.iter() {
            assert!(address.is_ipv4(), "should only be looking up IPv4");
        }
    }

    /// Test large ndots with non-fqdn.
    pub(crate) async fn large_ndots_test<R: ConnectionProvider>(handle: R) {
        let domain = Name::from_str("incorrect.example.com.").unwrap();
        let search = vec![
            Name::from_str("bad.example.com.").unwrap(),
            Name::from_str("wrong.example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> = ResolverConfig::udp_and_tcp(&GOOGLE)
            .name_servers()
            .to_owned();

        let mut resolver_builder = Resolver::<R>::builder_with_config(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            handle,
        );
        // matches kubernetes default
        resolver_builder.options_mut().ndots = 5;
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        let resolver = resolver_builder.build().unwrap();

        // notice this is not a FQDN, no trailing dot.
        let response = resolver
            .lookup_ip("www.example.com")
            .await
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);
        for address in response.iter() {
            assert!(address.is_ipv4(), "should only be looking up IPv4");
        }
    }

    /// Test domain search.
    pub(crate) async fn domain_search_test<R: ConnectionProvider>(handle: R) {
        // domain is good now, should be combined with the name to form www.example.com
        let domain = Name::from_str("example.com.").unwrap();
        let search = vec![
            Name::from_str("bad.example.com.").unwrap(),
            Name::from_str("wrong.example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> = ResolverConfig::udp_and_tcp(&GOOGLE)
            .name_servers()
            .to_owned();

        let mut resolver_builder = Resolver::<R>::builder_with_config(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            handle,
        );
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        let resolver = resolver_builder.build().unwrap();

        // notice no dots, should not trigger ndots rule
        let response = resolver
            .lookup_ip("www")
            .await
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);
        for address in response.iter() {
            assert!(address.is_ipv4(), "should only be looking up IPv4");
        }
    }

    /// Test search lists.
    pub(crate) async fn search_list_test<R: ConnectionProvider>(handle: R) {
        let domain = Name::from_str("incorrect.example.com.").unwrap();
        let search = vec![
            // let's skip one search domain to test the loop...
            Name::from_str("bad.example.com.").unwrap(),
            // this should combine with the search name to form www.example.com
            Name::from_str("example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> = ResolverConfig::udp_and_tcp(&GOOGLE)
            .name_servers()
            .to_owned();

        let mut resolver_builder = Resolver::<R>::builder_with_config(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            handle,
        );
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        let resolver = resolver_builder.build().unwrap();

        // notice no dots, should not trigger ndots rule
        let response = resolver
            .lookup_ip("www")
            .await
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);
        for address in response.iter() {
            assert!(address.is_ipv4(), "should only be looking up IPv4");
        }
    }

    /// Test idna.
    pub(crate) async fn idna_test<R: ConnectionProvider>(handle: R) {
        let resolver =
            Resolver::<R>::builder_with_config(ResolverConfig::udp_and_tcp(&GOOGLE), handle)
                .build()
                .unwrap();

        let response = resolver
            .lookup_ip("中国.icom.museum.")
            .await
            .expect("failed to run lookup");

        // we just care that the request succeeded, not about the actual content
        //   it's not certain that the ip won't change.
        assert!(response.iter().next().is_some());
    }

    /// Test ipv4 localhost.
    pub(crate) async fn localhost_ipv4_test<R: ConnectionProvider>(handle: R) {
        let mut resolver_builder =
            Resolver::<R>::builder_with_config(ResolverConfig::udp_and_tcp(&GOOGLE), handle);
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
        let resolver = resolver_builder.build().unwrap();

        let response = resolver
            .lookup_ip("localhost")
            .await
            .expect("failed to run lookup");

        let mut iter = response.iter();
        assert_eq!(iter.next().expect("no A"), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    /// Test ipv6 localhost.
    pub(crate) async fn localhost_ipv6_test<R: ConnectionProvider>(handle: R) {
        let mut resolver_builder =
            Resolver::<R>::builder_with_config(ResolverConfig::udp_and_tcp(&GOOGLE), handle);
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv6thenIpv4;
        let resolver = resolver_builder.build().unwrap();

        let response = resolver
            .lookup_ip("localhost")
            .await
            .expect("failed to run lookup");

        let mut iter = response.iter();
        assert_eq!(
            iter.next().expect("no AAAA"),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1,))
        );
    }

    /// Test ipv4 search with large ndots.
    pub(crate) async fn search_ipv4_large_ndots_test<R: ConnectionProvider>(handle: R) {
        let mut config = ResolverConfig::udp_and_tcp(&GOOGLE);
        config.add_search(Name::from_str("example.com").unwrap());

        let mut resolver_builder = Resolver::<R>::builder_with_config(config, handle);
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        resolver_builder.options_mut().ndots = 5;
        let resolver = resolver_builder.build().unwrap();

        let response = resolver
            .lookup_ip("198.51.100.35")
            .await
            .expect("failed to run lookup");

        let mut iter = response.iter();
        assert_eq!(
            iter.next().expect("no rdatas"),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 35))
        );
    }

    /// Test ipv6 search with large ndots.
    pub(crate) async fn search_ipv6_large_ndots_test<R: ConnectionProvider>(handle: R) {
        let mut config = ResolverConfig::udp_and_tcp(&GOOGLE);
        config.add_search(Name::from_str("example.com").unwrap());

        let mut resolver_builder = Resolver::<R>::builder_with_config(config, handle);
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        resolver_builder.options_mut().ndots = 5;
        let resolver = resolver_builder.build().unwrap();

        let response = resolver
            .lookup_ip("2001:db8::c633:6423")
            .await
            .expect("failed to run lookup");

        let mut iter = response.iter();
        assert_eq!(
            iter.next().expect("no rdatas"),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0xc633, 0x6423))
        );
    }

    /// Test ipv6 name parse fails.
    pub(crate) async fn search_ipv6_name_parse_fails_test<R: ConnectionProvider>(handle: R) {
        let mut config = ResolverConfig::udp_and_tcp(&GOOGLE);
        config.add_search(Name::from_str("example.com").unwrap());

        let mut resolver_builder = Resolver::<R>::builder_with_config(config, handle);
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        resolver_builder.options_mut().ndots = 5;
        let resolver = resolver_builder.build().unwrap();

        let response = resolver
            .lookup_ip("2001:db8::198.51.100.35")
            .await
            .expect("failed to run lookup");

        let mut iter = response.iter();
        assert_eq!(
            iter.next().expect("no rdatas"),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0xc633, 0x6423))
        );
    }
}

#[cfg(test)]
#[cfg(feature = "tokio")]
#[allow(clippy::extra_unused_type_parameters)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;

    use futures_util::stream::once;
    use futures_util::{Stream, future};
    use test_support::subscribe;

    #[cfg(all(unix, feature = "system-config"))]
    use super::testing::hosts_lookup_test;
    #[cfg(feature = "system-config")]
    use super::testing::system_lookup_test;
    use super::testing::{
        domain_search_test, fqdn_test, idna_test, ip_lookup_across_threads_test, ip_lookup_test,
        large_ndots_test, localhost_ipv4_test, localhost_ipv6_test, lookup_test, ndots_test,
        search_ipv4_large_ndots_test, search_ipv6_large_ndots_test,
        search_ipv6_name_parse_fails_test, search_list_test,
    };
    #[cfg(feature = "__dnssec")]
    use super::testing::{sec_lookup_fails_test, sec_lookup_test};
    use super::*;
    use crate::config::{CLOUDFLARE, GOOGLE, ResolverConfig, ResolverOpts};
    use crate::net::DnsError;
    use crate::net::xfer::DnsExchange;
    use crate::proto::op::{DnsRequest, DnsResponse, Message};
    use crate::proto::rr::rdata::A;

    fn is_send_t<T: Send>() -> bool {
        true
    }

    fn is_sync_t<T: Sync>() -> bool {
        true
    }

    #[test]
    fn test_send_sync() {
        assert!(is_send_t::<ResolverConfig>());
        assert!(is_sync_t::<ResolverConfig>());
        assert!(is_send_t::<ResolverOpts>());
        assert!(is_sync_t::<ResolverOpts>());

        assert!(is_send_t::<Resolver<TokioRuntimeProvider>>());
        assert!(is_sync_t::<Resolver<TokioRuntimeProvider>>());

        assert!(is_send_t::<DnsRequest>());
        assert!(is_send_t::<LookupIpFuture<DnsExchange<TokioRuntimeProvider>>>());
        assert!(is_send_t::<LookupFuture<DnsExchange<TokioRuntimeProvider>>>());
    }

    #[tokio::test]
    async fn test_lookup_google() {
        subscribe();
        let handle = TokioRuntimeProvider::default();
        lookup_test(ResolverConfig::udp_and_tcp(&GOOGLE), handle).await;
    }

    #[tokio::test]
    async fn test_lookup_cloudflare() {
        subscribe();
        let handle = TokioRuntimeProvider::default();
        lookup_test(ResolverConfig::udp_and_tcp(&CLOUDFLARE), handle).await;
    }

    #[tokio::test]
    async fn test_ip_lookup() {
        subscribe();
        let handle = TokioRuntimeProvider::default();
        ip_lookup_test(handle).await;
    }

    #[test]
    fn test_ip_lookup_across_threads() {
        subscribe();
        let handle = TokioRuntimeProvider::default();
        ip_lookup_across_threads_test(handle);
    }

    #[tokio::test]
    #[cfg(feature = "__dnssec")]
    #[ignore = "flaky test against internet server"]
    async fn test_sec_lookup() {
        subscribe();
        let handle = TokioRuntimeProvider::default();
        sec_lookup_test(handle).await;
    }

    #[tokio::test]
    #[cfg(feature = "__dnssec")]
    #[ignore = "flaky test against internet server"]
    async fn test_sec_lookup_fails() {
        subscribe();
        let handle = TokioRuntimeProvider::default();
        sec_lookup_fails_test(handle).await;
    }

    #[tokio::test]
    #[ignore]
    #[cfg(any(unix, target_os = "windows"))]
    #[cfg(feature = "system-config")]
    async fn test_system_lookup() {
        subscribe();
        let handle = TokioRuntimeProvider::default();
        system_lookup_test(handle).await;
    }

    // these appear to not work on CI, test on macos with `10.1.0.104  a.com`
    #[tokio::test]
    #[ignore]
    #[cfg(all(unix, feature = "system-config"))]
    async fn test_hosts_lookup() {
        subscribe();
        let handle = TokioRuntimeProvider::default();
        hosts_lookup_test(handle).await;
    }

    #[tokio::test]
    async fn test_fqdn() {
        subscribe();
        let handle = TokioRuntimeProvider::default();
        fqdn_test(handle).await;
    }

    #[tokio::test]
    async fn test_ndots() {
        subscribe();
        let handle = TokioRuntimeProvider::default();
        ndots_test(handle).await;
    }

    #[tokio::test]
    async fn test_large_ndots() {
        subscribe();
        let handle = TokioRuntimeProvider::default();
        large_ndots_test(handle).await;
    }

    #[tokio::test]
    async fn test_domain_search() {
        subscribe();
        let handle = TokioRuntimeProvider::default();
        domain_search_test(handle).await;
    }

    #[tokio::test]
    async fn test_search_list() {
        subscribe();
        let handle = TokioRuntimeProvider::default();
        search_list_test(handle).await;
    }

    #[tokio::test]
    async fn test_idna() {
        subscribe();
        let handle = TokioRuntimeProvider::default();
        idna_test(handle).await;
    }

    #[tokio::test]
    async fn test_localhost_ipv4() {
        subscribe();
        let handle = TokioRuntimeProvider::default();
        localhost_ipv4_test(handle).await;
    }

    #[tokio::test]
    async fn test_localhost_ipv6() {
        subscribe();
        let handle = TokioRuntimeProvider::default();
        localhost_ipv6_test(handle).await;
    }

    #[tokio::test]
    async fn test_search_ipv4_large_ndots() {
        subscribe();
        let handle = TokioRuntimeProvider::default();
        search_ipv4_large_ndots_test(handle).await;
    }

    #[tokio::test]
    async fn test_search_ipv6_large_ndots() {
        subscribe();
        let handle = TokioRuntimeProvider::default();
        search_ipv6_large_ndots_test(handle).await;
    }

    #[tokio::test]
    async fn test_search_ipv6_name_parse_fails() {
        subscribe();
        let handle = TokioRuntimeProvider::default();
        search_ipv6_name_parse_fails_test(handle).await;
    }

    #[test]
    fn test_build_names() {
        use std::str::FromStr;

        let handle = TokioRuntimeProvider::default();
        let mut config = ResolverConfig::udp_and_tcp(&GOOGLE);
        config.add_search(Name::from_ascii("example.com.").unwrap());
        let resolver = Resolver::builder_with_config(config, handle)
            .build()
            .unwrap();

        assert_eq!(resolver.build_names(Name::from_str("").unwrap()).len(), 2);
        assert_eq!(resolver.build_names(Name::from_str(".").unwrap()).len(), 1);

        let fqdn = Name::from_str("foo.example.com.").unwrap();
        let name_list = resolver.build_names(Name::from_str("foo").unwrap());
        assert!(name_list.contains(&fqdn));

        let name_list = resolver.build_names(fqdn.clone());
        assert_eq!(name_list.len(), 1);
        assert_eq!(name_list.first(), Some(&fqdn));
    }

    #[test]
    fn test_build_names_onion() {
        let handle = TokioRuntimeProvider::default();
        let mut config = ResolverConfig::udp_and_tcp(&GOOGLE);
        config.add_search(Name::from_ascii("example.com.").unwrap());
        let resolver = Resolver::builder_with_config(config, handle)
            .build()
            .unwrap();
        let tor_address = [
            Name::from_ascii("2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion")
                .unwrap(),
            Name::from_ascii("www.2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion")
                .unwrap(), // subdomain are allowed too
        ];
        let not_tor_address = [
            Name::from_ascii("onion").unwrap(),
            Name::from_ascii("www.onion").unwrap(),
            Name::from_ascii("2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.www.onion")
                .unwrap(), // www before key
            Name::from_ascii("2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion.to")
                .unwrap(), // Tor2web
        ];
        for name in &tor_address {
            assert_eq!(resolver.build_names(name.clone()).len(), 1);
        }
        for name in &not_tor_address {
            assert_eq!(resolver.build_names(name.clone()).len(), 2);
        }
    }

    #[tokio::test]
    async fn test_lookup() {
        assert_eq!(
            LookupFuture::lookup(
                vec![Name::root()],
                RecordType::A,
                DnsRequestOptions::default(),
                CachingClient::new(0, mock(vec![v4_message()]), false),
            )
            .await
            .unwrap()
            .answers()
            .iter()
            .map(|r| r.data.ip_addr().unwrap())
            .collect::<Vec<IpAddr>>(),
            vec![Ipv4Addr::LOCALHOST]
        );
    }

    #[tokio::test]
    async fn test_lookup_slice() {
        assert_eq!(
            LookupFuture::lookup(
                vec![Name::root()],
                RecordType::A,
                DnsRequestOptions::default(),
                CachingClient::new(0, mock(vec![v4_message()]), false),
            )
            .await
            .unwrap()
            .answers()[0]
                .data
                .ip_addr()
                .unwrap(),
            Ipv4Addr::LOCALHOST
        );
    }

    #[tokio::test]
    async fn test_lookup_into_iter() {
        assert_eq!(
            LookupFuture::lookup(
                vec![Name::root()],
                RecordType::A,
                DnsRequestOptions::default(),
                CachingClient::new(0, mock(vec![v4_message()]), false),
            )
            .await
            .unwrap()
            .answers()
            .iter()
            .map(|r| r.data.ip_addr().unwrap())
            .collect::<Vec<IpAddr>>(),
            vec![Ipv4Addr::LOCALHOST]
        );
    }

    #[tokio::test]
    async fn test_error() {
        assert!(
            LookupFuture::lookup(
                vec![Name::root()],
                RecordType::A,
                DnsRequestOptions::default(),
                CachingClient::new(0, mock(vec![error()]), false),
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn test_empty_no_response() {
        let error = LookupFuture::lookup(
            vec![Name::root()],
            RecordType::A,
            DnsRequestOptions::default(),
            CachingClient::new(0, mock(vec![empty()]), false),
        )
        .await
        .expect_err("this should have been a NoRecordsFound");

        let NetError::Dns(DnsError::NoRecordsFound(no_records)) = error else {
            panic!("wrong error received");
        };

        assert_eq!(*no_records.query, Query::new(Name::root(), RecordType::A));
        assert_eq!(no_records.negative_ttl, None);
    }

    #[derive(Clone)]
    struct MockDnsHandle {
        messages: Arc<Mutex<Vec<Result<DnsResponse, NetError>>>>,
    }

    impl DnsHandle for MockDnsHandle {
        type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, NetError>> + Send>>;
        type Runtime = TokioRuntimeProvider;

        fn send(&self, _: DnsRequest) -> Self::Response {
            // SAFETY: std::sync::Mutex is intentional here — the lock is acquired
            // and released within a single synchronous expression, never held across
            // an await point. Do not replace with futures_util::lock::Mutex, which
            // would introduce a hold-across-await hazard in tests.
            Box::pin(once(future::ready(
                self.messages.lock().unwrap().pop().unwrap_or_else(empty),
            )))
        }
    }

    fn v4_message() -> Result<DnsResponse, NetError> {
        let mut message = Message::query();
        message.add_query(Query::new(Name::root(), RecordType::A));
        message.insert_answers(vec![Record::from_rdata(
            Name::root(),
            86400,
            RData::A(A::new(127, 0, 0, 1)),
        )]);

        let resp = DnsResponse::from_message(message.into_response()).unwrap();
        assert!(resp.contains_answer());
        Ok(resp)
    }

    fn empty() -> Result<DnsResponse, NetError> {
        Ok(DnsResponse::from_message(Message::query().into_response()).unwrap())
    }

    fn error() -> Result<DnsResponse, NetError> {
        Err(NetError::from(std::io::Error::from(
            std::io::ErrorKind::Other,
        )))
    }

    fn mock(messages: Vec<Result<DnsResponse, NetError>>) -> MockDnsHandle {
        MockDnsHandle {
            messages: Arc::new(Mutex::new(messages)),
        }
    }
}
