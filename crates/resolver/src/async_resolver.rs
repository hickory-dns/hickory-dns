// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Structs for creating and using a AsyncResolver
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;

use futures_util::{self, future};
use proto::error::ProtoResult;
use proto::op::Query;
use proto::rr::domain::usage::ONION;
use proto::rr::domain::TryParseIp;
use proto::rr::{IntoName, Name, Record, RecordType};
use proto::xfer::{DnsRequestOptions, RetryDnsHandle};
use proto::DnsHandle;

use crate::caching_client::CachingClient;
use crate::config::{ResolverConfig, ResolverOpts};
use crate::dns_lru::{self, DnsLru};
use crate::error::*;
use crate::lookup::{self, Lookup, LookupEither, LookupFuture};
use crate::lookup_ip::{LookupIp, LookupIpFuture};
use crate::name_server::{
    ConnectionProvider, GenericConnection, GenericConnectionProvider, NameServerPool,
    RuntimeProvider,
};
#[cfg(feature = "tokio-runtime")]
use crate::name_server::{TokioConnection, TokioConnectionProvider, TokioHandle};

use crate::Hosts;

/// An asynchronous resolver for DNS generic over async Runtimes.
///
/// Creating a `AsyncResolver` returns a new handle and a future that should
/// be spawned on an executor to drive the background work. The lookup methods
/// on `AsyncResolver` request lookups from the background task.
///
/// The futures returned by a `AsyncResolver` and the corresponding background
/// task need not be spawned on the same executor, or be in the same thread.
///  Additionally, one background task may have any number of handles; calling
/// `clone()` on a handle will create a new handle linked to the same
/// background task.
///
/// *NOTE* If lookup futures returned by a `AsyncResolver` and the background
/// future are spawned on two separate `CurrentThread` executors, one thread
/// cannot run both executors simultaneously, so the `run` or `block_on`
/// functions will cause the thread to deadlock. If both the background work
/// and the lookup futures are intended to be run on the same thread, they
/// should be spawned on the same executor.
///
/// The background task manages the name server pool and other state used
/// to drive lookups. When this future is spawned on an executor, it will
/// first construct and configure the necessary client state, before checking
/// for any incoming lookup requests, handling them, and yielding. It will
/// continue to do so as long as there are still any [`AsyncResolver`] handle
/// linked to it. When all of its [`AsyncResolver`]s have been dropped, the
/// background future will finish.
#[derive(Clone)]
pub struct AsyncResolver<C: DnsHandle<Error = ResolveError>, P: ConnectionProvider<Conn = C>> {
    config: ResolverConfig,
    options: ResolverOpts,
    client_cache: CachingClient<LookupEither<C, P>, ResolveError>,
    hosts: Option<Arc<Hosts>>,
}

/// An AsyncResolver used with Tokio
#[cfg(feature = "tokio-runtime")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio-runtime")))]
pub type TokioAsyncResolver = AsyncResolver<TokioConnection, TokioConnectionProvider>;

macro_rules! lookup_fn {
    ($p:ident, $l:ty, $r:path) => {
        /// Performs a lookup for the associated type.
        ///
        /// *hint* queries that end with a '.' are fully qualified names and are cheaper lookups
        ///
        /// # Arguments
        ///
        /// * `query` - a string which parses to a domain name, failure to parse will return an error
        pub async fn $p<N: IntoName>(&self, query: N) -> Result<$l, ResolveError> {
            let name = match query.into_name() {
                Ok(name) => name,
                Err(err) => {
                    return Err(err.into());
                }
            };

            let mut request_opts = DnsRequestOptions::default();
            request_opts.use_edns = self.options.edns0;

            self.inner_lookup(name, $r, request_opts).await
        }
    };
    ($p:ident, $l:ty, $r:path, $t:ty) => {
        /// Performs a lookup for the associated type.
        ///
        /// # Arguments
        ///
        /// * `query` - a type which can be converted to `Name` via `From`.
        pub async fn $p(&self, query: $t) -> Result<$l, ResolveError> {
            let name = Name::from(query);
            self.inner_lookup(name, $r, DnsRequestOptions::default())
                .await
        }
    };
}

#[cfg(feature = "tokio-runtime")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio-runtime")))]
impl TokioAsyncResolver {
    /// Construct a new Tokio based `AsyncResolver` with the provided configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - configuration, name_servers, etc. for the Resolver
    /// * `options` - basic lookup options for the resolver
    ///
    /// # Returns
    ///
    /// A tuple containing the new `AsyncResolver` and a future that drives the
    /// background task that runs resolutions for the `AsyncResolver`. See the
    /// documentation for `AsyncResolver` for more information on how to use
    /// the background future.
    pub fn tokio(config: ResolverConfig, options: ResolverOpts) -> Result<Self, ResolveError> {
        Self::new(config, options, TokioHandle)
    }

    /// Constructs a new Tokio based Resolver with the system configuration.
    ///
    /// This will use `/etc/resolv.conf` on Unix OSes and the registry on Windows.
    #[cfg(any(unix, target_os = "windows"))]
    #[cfg(feature = "system-config")]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(feature = "system-config", any(unix, target_os = "windows"))))
    )]
    pub fn tokio_from_system_conf() -> Result<Self, ResolveError> {
        Self::from_system_conf(TokioHandle)
    }
}

impl<R: RuntimeProvider> AsyncResolver<GenericConnection, GenericConnectionProvider<R>> {
    /// Construct a new generic `AsyncResolver` with the provided configuration.
    ///
    /// see [TokioAsyncResolver::tokio(..)] instead.
    ///
    /// # Arguments
    ///
    /// * `config` - configuration, name_servers, etc. for the Resolver
    /// * `options` - basic lookup options for the resolver
    ///
    /// # Returns
    ///
    /// A tuple containing the new `AsyncResolver` and a future that drives the
    /// background task that runs resolutions for the `AsyncResolver`. See the
    /// documentation for `AsyncResolver` for more information on how to use
    /// the background future.
    pub fn new(
        config: ResolverConfig,
        options: ResolverOpts,
        runtime: R::Handle,
    ) -> Result<Self, ResolveError> {
        Self::new_with_conn(
            config,
            options,
            GenericConnectionProvider::<R>::new(runtime),
        )
    }

    /// Constructs a new Resolver with the system configuration.
    ///
    /// see [TokioAsyncResolver::tokio_from_system_conf(..)] instead.
    ///
    /// This will use `/etc/resolv.conf` on Unix OSes and the registry on Windows.
    #[cfg(any(unix, target_os = "windows"))]
    #[cfg(feature = "system-config")]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(feature = "system-config", any(unix, target_os = "windows"))))
    )]
    pub fn from_system_conf(runtime: R::Handle) -> Result<Self, ResolveError> {
        Self::from_system_conf_with_provider(GenericConnectionProvider::<R>::new(runtime))
    }

    /// Flushes/Removes all entries from the cache
    pub async fn clear_cache(&mut self) {
        self.client_cache.clear_cache();
    }
}

impl<C: DnsHandle<Error = ResolveError>, P: ConnectionProvider<Conn = C>> AsyncResolver<C, P> {
    /// Construct a new `AsyncResolver` with the provided configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - configuration, name_servers, etc. for the Resolver
    /// * `options` - basic lookup options for the resolver
    ///
    /// # Returns
    ///
    /// A tuple containing the new `AsyncResolver` and a future that drives the
    /// background task that runs resolutions for the `AsyncResolver`. See the
    /// documentation for `AsyncResolver` for more information on how to use
    /// the background future.
    #[allow(clippy::unnecessary_wraps)]
    pub fn new_with_conn(
        config: ResolverConfig,
        options: ResolverOpts,
        conn_provider: P,
    ) -> Result<Self, ResolveError> {
        let pool = NameServerPool::from_config_with_provider(&config, &options, conn_provider);
        let either;
        let client = RetryDnsHandle::new(pool, options.attempts);
        if options.validate {
            #[cfg(feature = "dnssec")]
            {
                use proto::xfer::DnssecDnsHandle;
                either = LookupEither::Secure(DnssecDnsHandle::new(client));
            }

            #[cfg(not(feature = "dnssec"))]
            {
                // TODO: should this just be a panic, or a pinned error?
                warn!("validate option is only available with 'dnssec' feature");
                either = LookupEither::Retry(client);
            }
        } else {
            either = LookupEither::Retry(client);
        }

        let hosts = if options.use_hosts_file {
            Some(Arc::new(Hosts::new()))
        } else {
            None
        };

        trace!("handle passed back");
        let lru = DnsLru::new(options.cache_size, dns_lru::TtlConfig::from_opts(&options));
        Ok(Self {
            config,
            options,
            client_cache: CachingClient::with_cache(lru, either, options.preserve_intermediates),
            hosts,
        })
    }

    /// Constructs a new Resolver with the system configuration.
    ///
    /// This will use `/etc/resolv.conf` on Unix OSes and the registry on Windows.
    #[cfg(any(unix, target_os = "windows"))]
    #[cfg(feature = "system-config")]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(feature = "system-config", any(unix, target_os = "windows"))))
    )]
    pub fn from_system_conf_with_provider(conn_provider: P) -> Result<Self, ResolveError> {
        let (config, options) = super::system_conf::read_system_conf()?;
        Self::new_with_conn(config, options, conn_provider)
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
    pub fn lookup<N: IntoName>(
        &self,
        name: N,
        record_type: RecordType,
        options: DnsRequestOptions,
    ) -> impl Future<Output = Result<Lookup, ResolveError>> + Send + Unpin + 'static {
        let name = match name.into_name() {
            Ok(name) => name,
            Err(err) => return future::Either::Left(future::err(err.into())),
        };

        let names = self.build_names(name);
        future::Either::Right(LookupFuture::lookup(
            names,
            record_type,
            options,
            self.client_cache.clone(),
        ))
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
                names.push(name.clone());
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
                names.push(name);
            }

            names
        }
    }

    pub(crate) async fn inner_lookup<L>(
        &self,
        name: Name,
        record_type: RecordType,
        options: DnsRequestOptions,
    ) -> Result<L, ResolveError>
    where
        L: From<Lookup> + Send + 'static,
    {
        self.lookup(name, record_type, options).await.map(L::from)
    }

    /// Performs a dual-stack DNS lookup for the IP for the given hostname.
    ///
    /// See the configuration and options parameters for controlling the way in which A(Ipv4) and AAAA(Ipv6) lookups will be performed. For the least expensive query a fully-qualified-domain-name, FQDN, which ends in a final `.`, e.g. `www.example.com.`, will only issue one query. Anything else will always incur the cost of querying the `ResolverConfig::domain` and `ResolverConfig::search`.
    ///
    /// # Arguments
    /// * `host` - string hostname, if this is an invalid hostname, an error will be returned.
    pub async fn lookup_ip<N: IntoName + TryParseIp>(
        &self,
        host: N,
    ) -> Result<LookupIp, ResolveError> {
        let mut finally_ip_addr: Option<Record> = None;
        let maybe_ip = host.try_parse_ip();
        let maybe_name: ProtoResult<Name> = host.into_name();

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
                let query = Query::query(name, ip_addr.to_record_type());
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
            (Err(err), None) => {
                return Err(err.into());
            }
        };

        let names = self.build_names(name);
        let hosts = self.hosts.as_ref().cloned();

        LookupIpFuture::lookup(
            names,
            self.options.ip_strategy,
            self.client_cache.clone(),
            DnsRequestOptions::default(),
            hosts,
            finally_ip_addr.and_then(Record::into_data),
        )
        .await
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
}

impl<C: DnsHandle<Error = ResolveError>, P: ConnectionProvider<Conn = C>> fmt::Debug
    for AsyncResolver<C, P>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncResolver")
            .field("request_tx", &"...")
            .finish()
    }
}

/// Unit tests compatible with different runtime.
#[cfg(any(test, feature = "testing"))]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
#[allow(dead_code, unreachable_pub)]
pub mod testing {
    use std::{net::*, str::FromStr};

    use crate::config::{LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts};
    use crate::name_server::{GenericConnection, GenericConnectionProvider, RuntimeProvider};
    use crate::AsyncResolver;
    use proto::{rr::Name, Executor};

    /// Test IP lookup from URLs.
    pub fn lookup_test<E: Executor, R: RuntimeProvider>(
        config: ResolverConfig,
        mut exec: E,
        handle: R::Handle,
    ) {
        let resolver = AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::new(
            config,
            ResolverOpts::default(),
            handle,
        )
        .expect("failed to create resolver");

        let response = exec
            .block_on(resolver.lookup_ip("www.example.com."))
            .expect("failed to run lookup");

        assert_eq!(response.iter().count(), 1);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                assert_eq!(
                    address,
                    IpAddr::V6(Ipv6Addr::new(
                        0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
                    ))
                );
            }
        }
    }

    /// Test IP lookup from IP literals.
    pub fn ip_lookup_test<E: Executor, R: RuntimeProvider>(mut exec: E, handle: R::Handle) {
        let resolver = AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::new(
            ResolverConfig::default(),
            ResolverOpts::default(),
            handle,
        )
        .expect("failed to create resolver");

        let response = exec
            .block_on(resolver.lookup_ip("10.1.0.2"))
            .expect("failed to run lookup");

        assert_eq!(
            Some(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2))),
            response.iter().next()
        );

        let response = exec
            .block_on(resolver.lookup_ip("2606:2800:220:1:248:1893:25c8:1946"))
            .expect("failed to run lookup");

        assert_eq!(
            Some(IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            ))),
            response.iter().next()
        );
    }

    /// Test IP lookup from IP literals across threads.
    pub fn ip_lookup_across_threads_test<E: Executor + Send + 'static, R: RuntimeProvider>(
        handle: R::Handle,
    ) {
        // Test ensuring that running the background task on a separate
        // executor in a separate thread from the futures returned by the
        // AsyncResolver works correctly.
        use std::thread;
        let resolver = AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::new(
            ResolverConfig::default(),
            ResolverOpts::default(),
            handle,
        )
        .expect("failed to create resolver");

        let resolver_one = resolver.clone();
        let resolver_two = resolver;

        let test_fn = |resolver: AsyncResolver<GenericConnection, GenericConnectionProvider<R>>| {
            let mut exec = E::new();

            let response = exec
                .block_on(resolver.lookup_ip("10.1.0.2"))
                .expect("failed to run lookup");

            assert_eq!(
                Some(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2))),
                response.iter().next()
            );

            let response = exec
                .block_on(resolver.lookup_ip("2606:2800:220:1:248:1893:25c8:1946"))
                .expect("failed to run lookup");

            assert_eq!(
                Some(IpAddr::V6(Ipv6Addr::new(
                    0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
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

    /// Test IP lookup from URLs with DNSSec validation.
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    pub fn sec_lookup_test<E: Executor + Send + 'static, R: RuntimeProvider>(
        mut exec: E,
        handle: R::Handle,
    ) {
        //env_logger::try_init().ok();

        let resolver = AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::new(
            ResolverConfig::default(),
            ResolverOpts {
                validate: true,
                try_tcp_on_error: true,
                ..ResolverOpts::default()
            },
            handle,
        )
        .expect("failed to create resolver");

        let response = exec
            .block_on(resolver.lookup_ip("www.example.com."))
            .expect("failed to run lookup");

        // TODO: this test is flaky, sometimes 1 is returned, sometimes 2...
        //assert_eq!(response.iter().count(), 1);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                assert_eq!(
                    address,
                    IpAddr::V6(Ipv6Addr::new(
                        0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
                    ))
                );
            }
        }
    }

    /// Test IP lookup from domains that exist but unsigned with DNSSec validation.
    #[allow(deprecated)]
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    pub fn sec_lookup_fails_test<E: Executor + Send + 'static, R: RuntimeProvider>(
        mut exec: E,
        handle: R::Handle,
    ) {
        use crate::error::*;
        use proto::rr::RecordType;
        let resolver = AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::new(
            ResolverConfig::default(),
            ResolverOpts {
                validate: true,
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
            handle,
        )
        .expect("failed to create resolver");

        // needs to be a domain that exists, but is not signed (eventually this will be)
        let response = exec.block_on(resolver.lookup_ip("trust-dns.org."));

        assert!(response.is_err());
        let error = response.unwrap_err();

        use proto::error::{ProtoError, ProtoErrorKind};

        let error_str = format!("{}", error);
        let name = Name::from_str("trust-dns.org.").unwrap();
        let expected_str = format!(
            "{}",
            ResolveError::from(ProtoError::from(ProtoErrorKind::RrsigsNotPresent {
                name,
                record_type: RecordType::A
            }))
        );
        assert_eq!(error_str, expected_str);
        if let ResolveErrorKind::Proto(_) = *error.kind() {
        } else {
            panic!("wrong error")
        }
    }

    /// Test AsyncResolver created from system configuration with IP lookup.
    #[cfg(feature = "system-config")]
    #[cfg_attr(docsrs, doc(cfg(feature = "system-config")))]
    pub fn system_lookup_test<E: Executor + Send + 'static, R: RuntimeProvider>(
        mut exec: E,
        handle: R::Handle,
    ) {
        let resolver =
            AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::from_system_conf(
                handle,
            )
            .expect("failed to create resolver");

        let response = exec
            .block_on(resolver.lookup_ip("www.example.com."))
            .expect("failed to run lookup");

        assert_eq!(response.iter().count(), 2);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                assert_eq!(
                    address,
                    IpAddr::V6(Ipv6Addr::new(
                        0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
                    ))
                );
            }
        }
    }

    /// Test AsyncResolver created from system configuration with host lookups.
    #[cfg(feature = "system-config")]
    #[cfg_attr(docsrs, doc(cfg(feature = "system-config")))]
    pub fn hosts_lookup_test<E: Executor + Send + 'static, R: RuntimeProvider>(
        mut exec: E,
        handle: R::Handle,
    ) {
        let resolver =
            AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::from_system_conf(
                handle,
            )
            .expect("failed to create resolver");

        let response = exec
            .block_on(resolver.lookup_ip("a.com"))
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
    pub fn fqdn_test<E: Executor + Send + 'static, R: RuntimeProvider>(
        mut exec: E,
        handle: R::Handle,
    ) {
        let domain = Name::from_str("incorrect.example.com.").unwrap();
        let search = vec![
            Name::from_str("bad.example.com.").unwrap(),
            Name::from_str("wrong.example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let resolver = AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::new(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
            handle,
        )
        .expect("failed to create resolver");

        let response = exec
            .block_on(resolver.lookup_ip("www.example.com."))
            .expect("failed to run lookup");

        assert_eq!(response.iter().count(), 1);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                panic!("should only be looking up IPv4");
            }
        }
    }

    /// Test ndots with non-fqdn.
    pub fn ndots_test<E: Executor + Send + 'static, R: RuntimeProvider>(
        mut exec: E,
        handle: R::Handle,
    ) {
        let domain = Name::from_str("incorrect.example.com.").unwrap();
        let search = vec![
            Name::from_str("bad.example.com.").unwrap(),
            Name::from_str("wrong.example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let resolver = AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::new(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            ResolverOpts {
                // our name does have 2, the default should be fine, let's just narrow the test criteria a bit.
                ndots: 2,
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
            handle,
        )
        .expect("failed to create resolver");

        // notice this is not a FQDN, no trailing dot.
        let response = exec
            .block_on(resolver.lookup_ip("www.example.com"))
            .expect("failed to run lookup");

        assert_eq!(response.iter().count(), 1);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                panic!("should only be looking up IPv4");
            }
        }
    }

    /// Test large ndots with non-fqdn.
    pub fn large_ndots_test<E: Executor + Send + 'static, R: RuntimeProvider>(
        mut exec: E,
        handle: R::Handle,
    ) {
        let domain = Name::from_str("incorrect.example.com.").unwrap();
        let search = vec![
            Name::from_str("bad.example.com.").unwrap(),
            Name::from_str("wrong.example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let resolver = AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::new(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            ResolverOpts {
                // matches kubernetes default
                ndots: 5,
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
            handle,
        )
        .expect("failed to create resolver");

        // notice this is not a FQDN, no trailing dot.
        let response = exec
            .block_on(resolver.lookup_ip("www.example.com"))
            .expect("failed to run lookup");

        assert_eq!(response.iter().count(), 1);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                panic!("should only be looking up IPv4");
            }
        }
    }

    /// Test domain search.
    pub fn domain_search_test<E: Executor + Send + 'static, R: RuntimeProvider>(
        mut exec: E,
        handle: R::Handle,
    ) {
        //env_logger::try_init().ok();

        // domain is good now, should be combined with the name to form www.example.com
        let domain = Name::from_str("example.com.").unwrap();
        let search = vec![
            Name::from_str("bad.example.com.").unwrap(),
            Name::from_str("wrong.example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let resolver = AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::new(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
            handle,
        )
        .expect("failed to create resolver");

        // notice no dots, should not trigger ndots rule
        let response = exec
            .block_on(resolver.lookup_ip("www"))
            .expect("failed to run lookup");

        assert_eq!(response.iter().count(), 1);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                panic!("should only be looking up IPv4");
            }
        }
    }

    /// Test search lists.
    pub fn search_list_test<E: Executor + Send + 'static, R: RuntimeProvider>(
        mut exec: E,
        handle: R::Handle,
    ) {
        let domain = Name::from_str("incorrect.example.com.").unwrap();
        let search = vec![
            // let's skip one search domain to test the loop...
            Name::from_str("bad.example.com.").unwrap(),
            // this should combine with the search name to form www.example.com
            Name::from_str("example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let resolver = AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::new(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
            handle,
        )
        .expect("failed to create resolver");

        // notice no dots, should not trigger ndots rule
        let response = exec
            .block_on(resolver.lookup_ip("www"))
            .expect("failed to run lookup");

        assert_eq!(response.iter().count(), 1);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                panic!("should only be looking up IPv4");
            }
        }
    }

    /// Test idna.
    pub fn idna_test<E: Executor + Send + 'static, R: RuntimeProvider>(
        mut exec: E,
        handle: R::Handle,
    ) {
        let resolver = AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::new(
            ResolverConfig::default(),
            ResolverOpts::default(),
            handle,
        )
        .expect("failed to create resolver");

        let response = exec
            .block_on(resolver.lookup_ip("中国.icom.museum."))
            .expect("failed to run lookup");

        // we just care that the request succeeded, not about the actual content
        //   it's not certain that the ip won't change.
        assert!(response.iter().next().is_some());
    }

    /// Test ipv4 localhost.
    pub fn localhost_ipv4_test<E: Executor + Send + 'static, R: RuntimeProvider>(
        mut exec: E,
        handle: R::Handle,
    ) {
        let resolver = AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::new(
            ResolverConfig::default(),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4thenIpv6,
                ..ResolverOpts::default()
            },
            handle,
        )
        .expect("failed to create resolver");

        let response = exec
            .block_on(resolver.lookup_ip("localhost"))
            .expect("failed to run lookup");

        let mut iter = response.iter();
        assert_eq!(
            iter.next().expect("no A"),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        );
    }

    /// Test ipv6 localhost.
    pub fn localhost_ipv6_test<E: Executor + Send + 'static, R: RuntimeProvider>(
        mut exec: E,
        handle: R::Handle,
    ) {
        let resolver = AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::new(
            ResolverConfig::default(),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv6thenIpv4,
                ..ResolverOpts::default()
            },
            handle,
        )
        .expect("failed to create resolver");

        let response = exec
            .block_on(resolver.lookup_ip("localhost"))
            .expect("failed to run lookup");

        let mut iter = response.iter();
        assert_eq!(
            iter.next().expect("no AAAA"),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1,))
        );
    }

    /// Test ipv4 search with large ndots.
    pub fn search_ipv4_large_ndots_test<E: Executor + Send + 'static, R: RuntimeProvider>(
        mut exec: E,
        handle: R::Handle,
    ) {
        let mut config = ResolverConfig::default();
        config.add_search(Name::from_str("example.com").unwrap());

        let resolver = AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::new(
            config,
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ndots: 5,
                ..ResolverOpts::default()
            },
            handle,
        )
        .expect("failed to create resolver");

        let response = exec
            .block_on(resolver.lookup_ip("198.51.100.35"))
            .expect("failed to run lookup");

        let mut iter = response.iter();
        assert_eq!(
            iter.next().expect("no rdatas"),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 35))
        );
    }

    /// Test ipv6 search with large ndots.
    pub fn search_ipv6_large_ndots_test<E: Executor + Send + 'static, R: RuntimeProvider>(
        mut exec: E,
        handle: R::Handle,
    ) {
        let mut config = ResolverConfig::default();
        config.add_search(Name::from_str("example.com").unwrap());

        let resolver = AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::new(
            config,
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ndots: 5,
                ..ResolverOpts::default()
            },
            handle,
        )
        .expect("failed to create resolver");

        let response = exec
            .block_on(resolver.lookup_ip("2001:db8::c633:6423"))
            .expect("failed to run lookup");

        let mut iter = response.iter();
        assert_eq!(
            iter.next().expect("no rdatas"),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0xc633, 0x6423))
        );
    }

    /// Test ipv6 name parse fails.
    pub fn search_ipv6_name_parse_fails_test<E: Executor + Send + 'static, R: RuntimeProvider>(
        mut exec: E,
        handle: R::Handle,
    ) {
        let mut config = ResolverConfig::default();
        config.add_search(Name::from_str("example.com").unwrap());

        let resolver = AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::new(
            config,
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ndots: 5,
                ..ResolverOpts::default()
            },
            handle,
        )
        .expect("failed to create resolver");

        let response = exec
            .block_on(resolver.lookup_ip("2001:db8::198.51.100.35"))
            .expect("failed to run lookup");

        let mut iter = response.iter();
        assert_eq!(
            iter.next().expect("no rdatas"),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0xc633, 0x6423))
        );
    }
}
#[cfg(test)]
#[cfg(feature = "tokio-runtime")]
mod tests {
    use proto::xfer::DnsRequest;
    use tokio::runtime::Runtime;

    use crate::config::{ResolverConfig, ResolverOpts};
    use crate::name_server::{TokioConnection, TokioConnectionProvider, TokioRuntime};

    use super::*;

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

        assert!(is_send_t::<
            AsyncResolver<TokioConnection, TokioConnectionProvider>,
        >());
        assert!(is_sync_t::<
            AsyncResolver<TokioConnection, TokioConnectionProvider>,
        >());

        assert!(is_send_t::<DnsRequest>());
        assert!(is_send_t::<LookupIpFuture<TokioConnection, ResolveError>>());
        assert!(is_send_t::<LookupFuture<TokioConnection, ResolveError>>());
    }

    #[test]
    fn test_lookup_google() {
        use super::testing::lookup_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime");
        let handle = TokioHandle;
        lookup_test::<Runtime, TokioRuntime>(ResolverConfig::google(), io_loop, handle)
    }

    #[test]
    fn test_lookup_cloudflare() {
        use super::testing::lookup_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime");
        let handle = TokioHandle;
        lookup_test::<Runtime, TokioRuntime>(ResolverConfig::cloudflare(), io_loop, handle)
    }

    #[test]
    fn test_lookup_quad9() {
        use super::testing::lookup_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime");
        let handle = TokioHandle;
        lookup_test::<Runtime, TokioRuntime>(ResolverConfig::quad9(), io_loop, handle)
    }

    #[test]
    fn test_ip_lookup() {
        use super::testing::ip_lookup_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime");
        let handle = TokioHandle;
        ip_lookup_test::<Runtime, TokioRuntime>(io_loop, handle)
    }

    #[test]
    fn test_ip_lookup_across_threads() {
        use super::testing::ip_lookup_across_threads_test;
        let _io_loop = Runtime::new().expect("failed to create tokio runtime io_loop");
        let handle = TokioHandle;
        ip_lookup_across_threads_test::<Runtime, TokioRuntime>(handle)
    }

    #[test]
    #[cfg(feature = "dnssec")]
    fn test_sec_lookup() {
        use super::testing::sec_lookup_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime io_loop");
        let handle = TokioHandle;
        sec_lookup_test::<Runtime, TokioRuntime>(io_loop, handle);
    }

    #[test]
    #[cfg(feature = "dnssec")]
    fn test_sec_lookup_fails() {
        use super::testing::sec_lookup_fails_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime io_loop");
        let handle = TokioHandle;
        sec_lookup_fails_test::<Runtime, TokioRuntime>(io_loop, handle);
    }

    #[test]
    #[ignore]
    #[cfg(any(unix, target_os = "windows"))]
    #[cfg(feature = "system-config")]
    fn test_system_lookup() {
        use super::testing::system_lookup_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime io_loop");
        let handle = TokioHandle;
        system_lookup_test::<Runtime, TokioRuntime>(io_loop, handle);
    }

    #[test]
    #[ignore]
    // these appear to not work on CI, test on macos with `10.1.0.104  a.com`
    #[cfg(unix)]
    fn test_hosts_lookup() {
        use super::testing::hosts_lookup_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime io_loop");
        let handle = TokioHandle;
        hosts_lookup_test::<Runtime, TokioRuntime>(io_loop, handle);
    }

    #[test]
    fn test_fqdn() {
        use super::testing::fqdn_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime io_loop");
        let handle = TokioHandle;
        fqdn_test::<Runtime, TokioRuntime>(io_loop, handle);
    }

    #[test]
    fn test_ndots() {
        use super::testing::ndots_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime io_loop");
        let handle = TokioHandle;
        ndots_test::<Runtime, TokioRuntime>(io_loop, handle);
    }

    #[test]
    fn test_large_ndots() {
        use super::testing::large_ndots_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime io_loop");
        let handle = TokioHandle;
        large_ndots_test::<Runtime, TokioRuntime>(io_loop, handle);
    }

    #[test]
    fn test_domain_search() {
        use super::testing::domain_search_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime io_loop");
        let handle = TokioHandle;
        domain_search_test::<Runtime, TokioRuntime>(io_loop, handle);
    }

    #[test]
    fn test_search_list() {
        use super::testing::search_list_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime io_loop");
        let handle = TokioHandle;
        search_list_test::<Runtime, TokioRuntime>(io_loop, handle);
    }

    #[test]
    fn test_idna() {
        use super::testing::idna_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime io_loop");
        let handle = TokioHandle;
        idna_test::<Runtime, TokioRuntime>(io_loop, handle);
    }

    #[test]
    fn test_localhost_ipv4() {
        use super::testing::localhost_ipv4_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime io_loop");
        let handle = TokioHandle;
        localhost_ipv4_test::<Runtime, TokioRuntime>(io_loop, handle);
    }

    #[test]
    fn test_localhost_ipv6() {
        use super::testing::localhost_ipv6_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime io_loop");
        let handle = TokioHandle;
        localhost_ipv6_test::<Runtime, TokioRuntime>(io_loop, handle);
    }

    #[test]
    fn test_search_ipv4_large_ndots() {
        use super::testing::search_ipv4_large_ndots_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime io_loop");
        let handle = TokioHandle;
        search_ipv4_large_ndots_test::<Runtime, TokioRuntime>(io_loop, handle);
    }

    #[test]
    fn test_search_ipv6_large_ndots() {
        use super::testing::search_ipv6_large_ndots_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime io_loop");
        let handle = TokioHandle;
        search_ipv6_large_ndots_test::<Runtime, TokioRuntime>(io_loop, handle);
    }

    #[test]
    fn test_search_ipv6_name_parse_fails() {
        use super::testing::search_ipv6_name_parse_fails_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime io_loop");
        let handle = TokioHandle;
        search_ipv6_name_parse_fails_test::<Runtime, TokioRuntime>(io_loop, handle);
    }

    #[test]
    fn test_build_names_onion() {
        let handle = TokioHandle;
        let mut config = ResolverConfig::default();
        config.add_search(Name::from_ascii("example.com.").unwrap());
        let resolver =
            AsyncResolver::<GenericConnection, GenericConnectionProvider<TokioRuntime>>::new(
                config,
                ResolverOpts::default(),
                handle,
            )
            .expect("failed to create resolver");
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
}
