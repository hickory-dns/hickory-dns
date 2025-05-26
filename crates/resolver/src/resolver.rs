// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Structs for creating and using a Resolver
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::{FutureExt, future};
use tracing::debug;

use crate::caching_client::CachingClient;
use crate::config::{ResolveHosts, ResolverConfig, ResolverOpts};
use crate::dns_lru::{self, DnsLru, TtlConfig};
use crate::hosts::Hosts;
use crate::lookup::{self, Lookup, LookupEither};
use crate::lookup_ip::{LookupIp, LookupIpFuture};
#[cfg(feature = "tokio")]
use crate::name_server::TokioConnectionProvider;
use crate::name_server::{ConnectionProvider, NameServerPool};
#[cfg(feature = "__dnssec")]
use crate::proto::dnssec::{DnssecDnsHandle, TrustAnchors};
use crate::proto::op::Query;
use crate::proto::rr::domain::usage::ONION;
use crate::proto::rr::{IntoName, Name, RData, Record, RecordType};
use crate::proto::xfer::{DnsHandle, DnsRequestOptions, RetryDnsHandle};
use crate::proto::{ProtoError, ProtoErrorKind};

/// A builder to construct a [`Resolver`].
///
/// Created by [`Resolver::builder`].
pub struct ResolverBuilder<P> {
    config: ResolverConfig,
    options: ResolverOpts,
    provider: P,

    #[cfg(feature = "__dnssec")]
    trust_anchor: Option<Arc<TrustAnchors>>,
    #[cfg(feature = "__dnssec")]
    nsec3_soft_iteration_limit: Option<u16>,
    #[cfg(feature = "__dnssec")]
    nsec3_hard_iteration_limit: Option<u16>,
}

impl<P> ResolverBuilder<P>
where
    P: ConnectionProvider,
{
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
    pub fn build(self) -> Resolver<P> {
        #[cfg_attr(not(feature = "__dnssec"), allow(unused_mut))]
        let Self {
            config,
            mut options,
            provider,
            #[cfg(feature = "__dnssec")]
            trust_anchor,
            #[cfg(feature = "__dnssec")]
            nsec3_soft_iteration_limit,
            #[cfg(feature = "__dnssec")]
            nsec3_hard_iteration_limit,
        } = self;

        let pool = NameServerPool::from_config_with_provider(&config, options.clone(), provider);
        let client = RetryDnsHandle::new(pool, options.attempts);
        let either;

        #[cfg(feature = "__dnssec")]
        if trust_anchor.is_some() || options.trust_anchor.is_some() {
            options.validate = true;
        }

        if options.validate {
            #[cfg(feature = "__dnssec")]
            {
                let trust_anchor =
                    trust_anchor.unwrap_or_else(|| Arc::new(TrustAnchors::default()));

                either = LookupEither::Secure(
                    DnssecDnsHandle::with_trust_anchor(client, trust_anchor)
                        .nsec3_iteration_limits(
                            nsec3_soft_iteration_limit,
                            nsec3_hard_iteration_limit,
                        ),
                );
            }

            #[cfg(not(feature = "__dnssec"))]
            {
                tracing::warn!("validate option is only available with dnssec features");
                either = LookupEither::Retry(client);
            }
        } else {
            either = LookupEither::Retry(client);
        }

        let lru = DnsLru::new(options.cache_size, TtlConfig::from_opts(&options));
        let client_cache = CachingClient::with_cache(lru, either, options.preserve_intermediates);

        let hosts = Arc::new(match options.use_hosts_file {
            ResolveHosts::Always | ResolveHosts::Auto => Hosts::from_system().unwrap_or_default(),
            ResolveHosts::Never => Hosts::default(),
        });

        Resolver {
            config,
            options,
            client_cache,
            hosts,
        }
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
    config: ResolverConfig,
    options: ResolverOpts,
    client_cache: CachingClient<LookupEither<P>>,
    hosts: Arc<Hosts>,
}

/// A Resolver used with Tokio
#[cfg(feature = "tokio")]
pub type TokioResolver = Resolver<TokioConnectionProvider>;

macro_rules! lookup_fn {
    ($p:ident, $l:ty, $r:path) => {
        /// Performs a lookup for the associated type.
        ///
        /// *hint* queries that end with a '.' are fully qualified names and are cheaper lookups
        ///
        /// # Arguments
        ///
        /// * `query` - a string which parses to a domain name, failure to parse will return an error
        pub async fn $p<N: IntoName>(&self, query: N) -> Result<$l, ProtoError> {
            let name = match query.into_name() {
                Ok(name) => name,
                Err(err) => {
                    return Err(err.into());
                }
            };

            self.inner_lookup(name, $r, self.request_options()).await
        }
    };
    ($p:ident, $l:ty, $r:path, $t:ty) => {
        /// Performs a lookup for the associated type.
        ///
        /// # Arguments
        ///
        /// * `query` - a type which can be converted to `Name` via `From`.
        pub async fn $p(&self, query: $t) -> Result<$l, ProtoError> {
            let name = Name::from(query);
            self.inner_lookup(name, $r, self.request_options()).await
        }
    };
}

#[cfg(feature = "tokio")]
impl TokioResolver {
    /// Constructs a new Tokio based Resolver with the system configuration.
    ///
    /// This will use `/etc/resolv.conf` on Unix OSes and the registry on Windows.
    #[cfg(any(unix, target_os = "windows"))]
    #[cfg(feature = "system-config")]
    pub fn builder_tokio() -> Result<ResolverBuilder<TokioConnectionProvider>, ProtoError> {
        Self::builder(TokioConnectionProvider::default())
    }
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
    pub fn builder(provider: R) -> Result<ResolverBuilder<R>, ProtoError> {
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
            #[cfg(feature = "__dnssec")]
            trust_anchor: None,
            #[cfg(feature = "__dnssec")]
            nsec3_soft_iteration_limit: None,
            #[cfg(feature = "__dnssec")]
            nsec3_hard_iteration_limit: None,
        }
    }

    /// Flushes/Removes all entries from the cache
    pub fn clear_cache(&self) {
        self.client_cache.clear_cache();
    }

    /// Read the config for this resolver.
    pub fn config(&self) -> &ResolverConfig {
        &self.config
    }

    /// Read the options for this resolver.
    pub fn options(&self) -> &ResolverOpts {
        &self.options
    }
}

impl<P: ConnectionProvider> Resolver<P> {
    /// Per request options based on the ResolverOpts
    pub(crate) fn request_options(&self) -> DnsRequestOptions {
        let mut request_opts = DnsRequestOptions::default();
        request_opts.recursion_desired = self.options.recursion_desired;
        request_opts.use_edns = self.options.edns0;
        request_opts.case_randomization = self.options.case_randomization;

        request_opts
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
    ) -> Result<Lookup, ProtoError> {
        self.inner_lookup(name.into_name()?, record_type, self.request_options())
            .await
    }

    fn push_name(name: Name, names: &mut Vec<Name>) {
        if !names.contains(&name) {
            names.push(name);
        }
    }

    fn build_names(&self, name: Name) -> Vec<Name> {
        // if it's fully qualified, we can short circuit the lookup logic
        if name.is_fqdn()
            || ONION.zone_of(&name)
                && name
                    .trim_to(2)
                    .iter()
                    .next()
                    .map(|name| name.len() == 56) // size of onion v3 address
                    .unwrap_or(false)
        {
            // if already fully qualified, or if onion address, don't assume it might be a
            // sub-domain
            vec![name]
        } else {
            // Otherwise we have to build the search list
            // Note: the vec is built in reverse order of precedence, for stack semantics
            let mut names =
                Vec::<Name>::with_capacity(1 /*FQDN*/ + 1 /*DOMAIN*/ + self.config.search().len());

            // if not meeting ndots, we always do the raw name in the final lookup, or it's a localhost...
            let raw_name_first: bool =
                name.num_labels() as usize > self.options.ndots || name.is_localhost();

            // if not meeting ndots, we always do the raw name in the final lookup
            if !raw_name_first {
                let mut fqdn = name.clone();
                fqdn.set_fqdn(true);
                names.push(fqdn);
            }

            for search in self.config.search().iter().rev() {
                let name_search = name.clone().append_domain(search);

                match name_search {
                    Ok(name_search) => Self::push_name(name_search, &mut names),
                    Err(e) => debug!(
                        "Not adding {} to {} for search due to error: {}",
                        search, name, e
                    ),
                }
            }

            if let Some(domain) = self.config.domain() {
                let name_search = name.clone().append_domain(domain);

                match name_search {
                    Ok(name_search) => Self::push_name(name_search, &mut names),
                    Err(e) => debug!(
                        "Not adding {} to {} for search due to error: {}",
                        domain, name, e
                    ),
                }
            }

            // this is the direct name lookup
            if raw_name_first {
                // adding the name as though it's an FQDN for lookup
                let mut fqdn = name.clone();
                fqdn.set_fqdn(true);
                names.push(fqdn);
            }

            names
        }
    }

    pub(crate) async fn inner_lookup<L>(
        &self,
        name: Name,
        record_type: RecordType,
        options: DnsRequestOptions,
    ) -> Result<L, ProtoError>
    where
        L: From<Lookup> + Send + Sync + 'static,
    {
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
    pub async fn lookup_ip(&self, host: impl IntoName) -> Result<LookupIp, ProtoError> {
        let mut finally_ip_addr = None;
        let maybe_ip = host.to_ip().map(RData::from);
        let maybe_name = host.into_name();

        // if host is a ip address, return directly.
        if let Some(ip_addr) = maybe_ip {
            let name = maybe_name.clone().unwrap_or_default();
            let record = Record::from_rdata(name.clone(), dns_lru::MAX_TTL, ip_addr.clone());

            // if ndots are greater than 4, then we can't assume the name is an IpAddr
            //   this accepts IPv6 as well, b/c IPv6 can take the form: 2001:db8::198.51.100.35
            //   but `:` is not a valid DNS character, so technically this will fail parsing.
            //   TODO: should we always do search before returning this?
            if self.options.ndots > 4 {
                finally_ip_addr = Some(record);
            } else {
                let query = Query::query(name, ip_addr.record_type());
                let lookup = Lookup::new_with_max_ttl(query, Arc::from([record]));
                return Ok(lookup.into());
            }
        }

        let name = match (maybe_name, finally_ip_addr.as_ref()) {
            (Ok(name), _) => name,
            (Err(_), Some(ip_addr)) => {
                // it was a valid IP, return that...
                let query = Query::query(ip_addr.name().clone(), ip_addr.record_type());
                let lookup = Lookup::new_with_max_ttl(query, Arc::from([ip_addr.clone()]));
                return Ok(lookup.into());
            }
            (Err(err), None) => return Err(err),
        };

        let names = self.build_names(name);
        let hosts = self.hosts.clone();

        LookupIpFuture::lookup(
            names,
            self.options.ip_strategy,
            self.client_cache.clone(),
            self.request_options(),
            hosts,
            finally_ip_addr.map(Record::into_data),
        )
        .await
    }

    /// Customizes the static hosts used in this resolver.
    pub fn set_hosts(&mut self, hosts: Arc<Hosts>) {
        self.hosts = hosts;
    }

    lookup_fn!(
        reverse_lookup,
        lookup::ReverseLookup,
        RecordType::PTR,
        IpAddr
    );
    lookup_fn!(ipv4_lookup, lookup::Ipv4Lookup, RecordType::A);
    lookup_fn!(ipv6_lookup, lookup::Ipv6Lookup, RecordType::AAAA);
    lookup_fn!(mx_lookup, lookup::MxLookup, RecordType::MX);
    lookup_fn!(ns_lookup, lookup::NsLookup, RecordType::NS);
    lookup_fn!(soa_lookup, lookup::SoaLookup, RecordType::SOA);
    lookup_fn!(srv_lookup, lookup::SrvLookup, RecordType::SRV);
    lookup_fn!(tlsa_lookup, lookup::TlsaLookup, RecordType::TLSA);
    lookup_fn!(txt_lookup, lookup::TxtLookup, RecordType::TXT);
    lookup_fn!(cert_lookup, lookup::CertLookup, RecordType::CERT);
}

impl<P: ConnectionProvider> fmt::Debug for Resolver<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resolver").finish()
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
    query: Pin<Box<dyn Future<Output = Result<Lookup, ProtoError>> + Send>>,
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
            Arc::new(Hosts::default()),
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
        let name = names.pop().ok_or_else(|| {
            ProtoError::from(ProtoErrorKind::Message("can not lookup for no names"))
        });

        let query: Pin<Box<dyn Future<Output = Result<Lookup, ProtoError>> + Send>> = match name {
            Ok(name) => {
                let query = Query::query(name, record_type);

                if let Some(lookup) = hosts.lookup_static_host(&query) {
                    future::ok(lookup).boxed()
                } else {
                    client_cache.lookup(query, options).boxed()
                }
            }
            Err(err) => future::err(err).boxed(),
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
    type Output = Result<Lookup, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            // Try polling the underlying DNS query.
            let query = self.query.as_mut().poll_unpin(cx);

            // Determine whether or not we will attempt to retry the query.
            let should_retry = match &query {
                // If the query is NotReady, yield immediately.
                Poll::Pending => return Poll::Pending,
                // If the query returned a successful lookup, we will attempt
                // to retry if the lookup is empty. Otherwise, we will return
                // that lookup.
                Poll::Ready(Ok(lookup)) => lookup.records().is_empty(),
                // If the query failed, we will attempt to retry.
                Poll::Ready(Err(_)) => true,
            };

            if should_retry {
                if let Some(name) = self.names.pop() {
                    let record_type = self.record_type;
                    let options = self.options;

                    // If there's another name left to try, build a new query
                    // for that next name and continue looping.
                    self.query = self
                        .client_cache
                        .lookup(Query::query(name, record_type), options);
                    // Continue looping with the new query. It will be polled
                    // on the next iteration of the loop.
                    continue;
                }
            }
            // If we didn't have to retry the query, or we weren't able to
            // retry because we've exhausted the names to search, return the
            // current query.
            return query;
            // If we skipped retrying the  query, this will return the
            // successful lookup, otherwise, if the retry failed, this will
            // return the last  query result --- either an empty lookup or the
            // last error we saw.
        }
    }
}

/// Unit tests compatible with different runtime.
#[cfg(all(test, feature = "tokio"))]
pub(crate) mod testing {
    use std::{net::*, str::FromStr};

    use crate::Resolver;
    use crate::config::{LookupIpStrategy, NameServerConfig, ResolverConfig};
    use crate::name_server::ConnectionProvider;
    use crate::proto::{rr::Name, runtime::Executor};

    /// Test IP lookup from URLs.
    pub(crate) async fn lookup_test<R: ConnectionProvider>(config: ResolverConfig, handle: R) {
        let resolver = Resolver::<R>::builder_with_config(config, handle).build();

        let response = resolver
            .lookup_ip("www.example.com.")
            .await
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);
    }

    /// Test IP lookup from IP literals.
    pub(crate) async fn ip_lookup_test<R: ConnectionProvider>(handle: R) {
        let resolver =
            Resolver::<R>::builder_with_config(ResolverConfig::default(), handle).build();

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
    pub(crate) fn ip_lookup_across_threads_test<E: Executor, R: ConnectionProvider>(handle: R) {
        // Test ensuring that running the background task on a separate
        // executor in a separate thread from the futures returned by the
        // Resolver works correctly.
        use std::thread;
        let resolver =
            Resolver::<R>::builder_with_config(ResolverConfig::default(), handle).build();

        let resolver_one = resolver.clone();
        let resolver_two = resolver;

        let test_fn = |resolver: Resolver<R>| {
            let mut exec = E::new();

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
    pub(crate) async fn sec_lookup_test<R: ConnectionProvider>(handle: R) {
        let mut resolver_builder = Resolver::builder_with_config(ResolverConfig::default(), handle);
        resolver_builder.options_mut().validate = true;
        resolver_builder.options_mut().try_tcp_on_error = true;
        let resolver = resolver_builder.build();

        let response = resolver
            .lookup_ip("www.example.com.")
            .await
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);
        assert!(
            response
                .as_lookup()
                .record_iter()
                .any(|record| record.proof().is_secure())
        );
    }

    /// Test IP lookup from domains that exist but unsigned with DNSSEC validation.
    #[allow(deprecated)]
    #[cfg(feature = "__dnssec")]
    pub(crate) async fn sec_lookup_fails_test<R: ConnectionProvider>(handle: R) {
        let mut resolver_builder = Resolver::builder_with_config(ResolverConfig::default(), handle);
        resolver_builder.options_mut().validate = true;
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        let resolver = resolver_builder.build();

        // needs to be a domain that exists, but is not signed (eventually this will be)
        let response = resolver.lookup_ip("hickory-dns.org.").await;

        let lookup_ip = response.unwrap();
        for record in lookup_ip.as_lookup().record_iter() {
            assert!(record.proof().is_insecure());
        }
    }

    /// Test Resolver created from system configuration with IP lookup.
    #[cfg(feature = "system-config")]
    pub(crate) async fn system_lookup_test<R: ConnectionProvider>(handle: R) {
        let resolver = Resolver::<R>::builder(handle)
            .expect("failed to create resolver")
            .build();

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
    #[cfg(feature = "system-config")]
    pub(crate) async fn hosts_lookup_test<R: ConnectionProvider>(handle: R) {
        let resolver = Resolver::<R>::builder(handle)
            .expect("failed to create resolver")
            .build();

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
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let mut resolver_builder = Resolver::<R>::builder_with_config(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            handle,
        );
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        let resolver = resolver_builder.build();

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
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let mut resolver_builder = Resolver::<R>::builder_with_config(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            handle,
        );
        // our name does have 2, the default should be fine, let's just narrow the test criteria a bit.
        resolver_builder.options_mut().ndots = 2;
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        let resolver = resolver_builder.build();

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
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let mut resolver_builder = Resolver::<R>::builder_with_config(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            handle,
        );
        // matches kubernetes default
        resolver_builder.options_mut().ndots = 5;
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        let resolver = resolver_builder.build();

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
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let mut resolver_builder = Resolver::<R>::builder_with_config(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            handle,
        );
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        let resolver = resolver_builder.build();

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
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let mut resolver_builder = Resolver::<R>::builder_with_config(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            handle,
        );
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        let resolver = resolver_builder.build();

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
            Resolver::<R>::builder_with_config(ResolverConfig::default(), handle).build();

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
            Resolver::<R>::builder_with_config(ResolverConfig::default(), handle);
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
        let resolver = resolver_builder.build();

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
            Resolver::<R>::builder_with_config(ResolverConfig::default(), handle);
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv6thenIpv4;
        let resolver = resolver_builder.build();

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
        let mut config = ResolverConfig::default();
        config.add_search(Name::from_str("example.com").unwrap());

        let mut resolver_builder = Resolver::<R>::builder_with_config(config, handle);
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        resolver_builder.options_mut().ndots = 5;
        let resolver = resolver_builder.build();

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
        let mut config = ResolverConfig::default();
        config.add_search(Name::from_str("example.com").unwrap());

        let mut resolver_builder = Resolver::<R>::builder_with_config(config, handle);
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        resolver_builder.options_mut().ndots = 5;
        let resolver = resolver_builder.build();

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
        let mut config = ResolverConfig::default();
        config.add_search(Name::from_str("example.com").unwrap());

        let mut resolver_builder = Resolver::<R>::builder_with_config(config, handle);
        resolver_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        resolver_builder.options_mut().ndots = 5;
        let resolver = resolver_builder.build();

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
    use tokio::runtime::Runtime;

    use super::testing::{
        domain_search_test, fqdn_test, idna_test, ip_lookup_across_threads_test, ip_lookup_test,
        large_ndots_test, localhost_ipv4_test, localhost_ipv6_test, lookup_test, ndots_test,
        search_ipv4_large_ndots_test, search_ipv6_large_ndots_test,
        search_ipv6_name_parse_fails_test, search_list_test,
    };
    #[cfg(feature = "system-config")]
    use super::testing::{hosts_lookup_test, system_lookup_test};
    #[cfg(feature = "__dnssec")]
    use super::testing::{sec_lookup_fails_test, sec_lookup_test};
    use super::*;
    use crate::config::{ResolverConfig, ResolverOpts};
    use crate::name_server::GenericConnection;
    use crate::proto::op::Message;
    use crate::proto::rr::rdata::A;
    use crate::proto::xfer::{DnsRequest, DnsResponse};
    use crate::proto::{NoRecords, ProtoError, ProtoErrorKind};

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

        assert!(is_send_t::<Resolver<TokioConnectionProvider>>());
        assert!(is_sync_t::<Resolver<TokioConnectionProvider>>());

        assert!(is_send_t::<DnsRequest>());
        assert!(is_send_t::<LookupIpFuture<GenericConnection>>());
        assert!(is_send_t::<LookupFuture<GenericConnection>>());
    }

    #[tokio::test]
    async fn test_lookup_google() {
        subscribe();
        let handle = TokioConnectionProvider::default();
        lookup_test(ResolverConfig::google(), handle).await;
    }

    #[tokio::test]
    async fn test_lookup_cloudflare() {
        subscribe();
        let handle = TokioConnectionProvider::default();
        lookup_test(ResolverConfig::cloudflare(), handle).await;
    }

    #[tokio::test]
    async fn test_ip_lookup() {
        subscribe();
        let handle = TokioConnectionProvider::default();
        ip_lookup_test(handle).await;
    }

    #[test]
    fn test_ip_lookup_across_threads() {
        subscribe();
        let handle = TokioConnectionProvider::default();
        ip_lookup_across_threads_test::<Runtime, _>(handle);
    }

    #[tokio::test]
    #[cfg(feature = "__dnssec")]
    async fn test_sec_lookup() {
        subscribe();
        let handle = TokioConnectionProvider::default();
        sec_lookup_test(handle).await;
    }

    #[tokio::test]
    #[cfg(feature = "__dnssec")]
    async fn test_sec_lookup_fails() {
        subscribe();
        let handle = TokioConnectionProvider::default();
        sec_lookup_fails_test(handle).await;
    }

    #[tokio::test]
    #[ignore]
    #[cfg(any(unix, target_os = "windows"))]
    #[cfg(feature = "system-config")]
    async fn test_system_lookup() {
        subscribe();
        let handle = TokioConnectionProvider::default();
        system_lookup_test(handle).await;
    }

    #[tokio::test]
    #[ignore]
    // these appear to not work on CI, test on macos with `10.1.0.104  a.com`
    #[cfg(unix)]
    #[cfg(feature = "system-config")]
    async fn test_hosts_lookup() {
        subscribe();
        let handle = TokioConnectionProvider::default();
        hosts_lookup_test(handle).await;
    }

    #[tokio::test]
    async fn test_fqdn() {
        subscribe();
        let handle = TokioConnectionProvider::default();
        fqdn_test(handle).await;
    }

    #[tokio::test]
    async fn test_ndots() {
        subscribe();
        let handle = TokioConnectionProvider::default();
        ndots_test(handle).await;
    }

    #[tokio::test]
    async fn test_large_ndots() {
        subscribe();
        let handle = TokioConnectionProvider::default();
        large_ndots_test(handle).await;
    }

    #[tokio::test]
    async fn test_domain_search() {
        subscribe();
        let handle = TokioConnectionProvider::default();
        domain_search_test(handle).await;
    }

    #[tokio::test]
    async fn test_search_list() {
        subscribe();
        let handle = TokioConnectionProvider::default();
        search_list_test(handle).await;
    }

    #[tokio::test]
    async fn test_idna() {
        subscribe();
        let handle = TokioConnectionProvider::default();
        idna_test(handle).await;
    }

    #[tokio::test]
    async fn test_localhost_ipv4() {
        subscribe();
        let handle = TokioConnectionProvider::default();
        localhost_ipv4_test(handle).await;
    }

    #[tokio::test]
    async fn test_localhost_ipv6() {
        subscribe();
        let handle = TokioConnectionProvider::default();
        localhost_ipv6_test(handle).await;
    }

    #[tokio::test]
    async fn test_search_ipv4_large_ndots() {
        subscribe();
        let handle = TokioConnectionProvider::default();
        search_ipv4_large_ndots_test(handle).await;
    }

    #[tokio::test]
    async fn test_search_ipv6_large_ndots() {
        subscribe();
        let handle = TokioConnectionProvider::default();
        search_ipv6_large_ndots_test(handle).await;
    }

    #[tokio::test]
    async fn test_search_ipv6_name_parse_fails() {
        subscribe();
        let handle = TokioConnectionProvider::default();
        search_ipv6_name_parse_fails_test(handle).await;
    }

    #[test]
    fn test_build_names() {
        use std::str::FromStr;

        let handle = TokioConnectionProvider::default();
        let mut config = ResolverConfig::default();
        config.add_search(Name::from_ascii("example.com.").unwrap());
        let resolver = Resolver::builder_with_config(config, handle).build();

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
        let handle = TokioConnectionProvider::default();
        let mut config = ResolverConfig::default();
        config.add_search(Name::from_ascii("example.com.").unwrap());
        let resolver = Resolver::builder_with_config(config, handle).build();
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
            .iter()
            .map(|r| r.ip_addr().unwrap())
            .collect::<Vec<IpAddr>>(),
            vec![Ipv4Addr::LOCALHOST]
        );
    }

    #[tokio::test]
    async fn test_lookup_slice() {
        assert_eq!(
            Record::data(
                &LookupFuture::lookup(
                    vec![Name::root()],
                    RecordType::A,
                    DnsRequestOptions::default(),
                    CachingClient::new(0, mock(vec![v4_message()]), false),
                )
                .await
                .unwrap()
                .records()[0]
            )
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
            .into_iter()
            .map(|r| r.ip_addr().unwrap())
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
        if let ProtoErrorKind::NoRecordsFound(NoRecords {
            query,
            negative_ttl,
            ..
        }) = LookupFuture::lookup(
            vec![Name::root()],
            RecordType::A,
            DnsRequestOptions::default(),
            CachingClient::new(0, mock(vec![empty()]), false),
        )
        .await
        .expect_err("this should have been a NoRecordsFound")
        .kind()
        {
            assert_eq!(**query, Query::query(Name::root(), RecordType::A));
            assert_eq!(*negative_ttl, None);
        } else {
            panic!("wrong error received");
        }
    }

    #[derive(Clone)]
    struct MockDnsHandle {
        messages: Arc<Mutex<Vec<Result<DnsResponse, ProtoError>>>>,
    }

    impl DnsHandle for MockDnsHandle {
        type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send>>;

        fn send<R: Into<DnsRequest>>(&self, _: R) -> Self::Response {
            Box::pin(once(
                future::ready(self.messages.lock().unwrap().pop().unwrap_or_else(empty)).boxed(),
            ))
        }
    }

    fn v4_message() -> Result<DnsResponse, ProtoError> {
        let mut message = Message::query();
        message.add_query(Query::query(Name::root(), RecordType::A));
        message.insert_answers(vec![Record::from_rdata(
            Name::root(),
            86400,
            RData::A(A::new(127, 0, 0, 1)),
        )]);

        let resp = DnsResponse::from_message(message).unwrap();
        assert!(resp.contains_answer());
        Ok(resp)
    }

    fn empty() -> Result<DnsResponse, ProtoError> {
        Ok(DnsResponse::from_message(Message::query()).unwrap())
    }

    fn error() -> Result<DnsResponse, ProtoError> {
        Err(ProtoError::from(std::io::Error::from(
            std::io::ErrorKind::Other,
        )))
    }

    fn mock(messages: Vec<Result<DnsResponse, ProtoError>>) -> MockDnsHandle {
        MockDnsHandle {
            messages: Arc::new(Mutex::new(messages)),
        }
    }
}
