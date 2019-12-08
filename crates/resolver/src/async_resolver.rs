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

use futures::{self, future, lock::Mutex, TryFutureExt};
use proto::error::ProtoResult;
use proto::op::Query;
use proto::rr::domain::TryParseIp;
use proto::rr::{IntoName, Name, Record, RecordType};
use proto::xfer::{DnsRequestOptions, RetryDnsHandle};
use tokio::runtime::Handle;

use crate::config::{ResolverConfig, ResolverOpts};
use crate::dns_lru::{self, DnsLru};
use crate::error::*;
use crate::lookup::{self, Lookup, LookupEither, LookupFuture};
use crate::lookup_ip::{LookupIp, LookupIpFuture};
use crate::lookup_state::CachingClient;
use crate::name_server::{Connection, NameServerPool, StandardConnection};
use crate::{Hosts, SpawnBg, TokioSpawnBg};

type ClientCache<S> = CachingClient<LookupEither<Connection, StandardConnection, S>>;

// TODO: Consider renaming to ResolverAsync
/// A handle for resolving DNS records.
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
pub struct AsyncResolver<S: SpawnBg> {
    config: ResolverConfig,
    options: ResolverOpts,
    client_cache: ClientCache<S>,
    hosts: Option<Arc<Hosts>>,
}

/// An AsyncResolver used with Tokio
pub type TokioAsyncResolver = AsyncResolver<TokioSpawnBg>;

macro_rules! lookup_fn {
    ($p:ident, $l:ty, $r:path) => {
/// Performs a lookup for the associated type.
///
/// *hint* queries that end with a '.' are fully qualified names and are cheaper lookups
///
/// # Arguments
///
/// * `query` - a string which parses to a domain name, failure to parse will return an error
pub fn $p<N: IntoName>(&self, query: N) -> impl Future<Output = Result<$l, ResolveError>> + Send + Unpin + 'static {
    let name = match query.into_name() {
        Ok(name) => name,
        Err(err) => {
            return future::Either::Left(future::err(err.into()));
        }
    };

    future::Either::Right(self.inner_lookup(name, $r, DnsRequestOptions::default(),))
}
    };
    ($p:ident, $l:ty, $r:path, $t:ty) => {
/// Performs a lookup for the associated type.
///
/// # Arguments
///
/// * `query` - a type which can be converted to `Name` via `From`.
pub fn $p(&self, query: $t) -> impl Future<Output = Result<$l, ResolveError>> + Send + Unpin + 'static {
    let name = Name::from(query);
    self.inner_lookup(name, $r, DnsRequestOptions::default(),)
}
    };
}

impl AsyncResolver<TokioSpawnBg> {
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
    pub async fn new(
        config: ResolverConfig,
        options: ResolverOpts,
        runtime: Handle,
    ) -> Result<Self, ResolveError> {
        AsyncResolver::new_with_spawn(config, options, TokioSpawnBg::new(runtime)).await
    }

    /// Constructs a new Resolver with the system configuration.
    ///
    /// This will use `/etc/resolv.conf` on Unix OSes and the registry on Windows.
    #[cfg(any(unix, target_os = "windows"))]
    pub async fn from_system_conf(runtime: Handle) -> Result<Self, ResolveError> {
        Self::from_system_conf_with_spawn(TokioSpawnBg::new(runtime)).await
    }
}

impl<S: SpawnBg + Send> AsyncResolver<S> {
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
    pub async fn new_with_spawn(
        config: ResolverConfig,
        options: ResolverOpts,
        spawn_bg: S,
    ) -> Result<Self, ResolveError> {
        let lru = DnsLru::new(options.cache_size, dns_lru::TtlConfig::from_opts(&options));
        let lru = Arc::new(Mutex::new(lru));

        Self::with_cache_with_spawn(config, options, lru, spawn_bg).await
    }

    /// Construct a new `AsyncResolver` with the associated Client and configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - configuration, name_servers, etc. for the Resolver
    /// * `options` - basic lookup options for the resolver
    /// * `lru` - the cache to be used with the resolver
    ///
    /// # Returns
    ///
    /// A tuple containing the new `AsyncResolver` and a future that drives the
    /// background task that runs resolutions for the `AsyncResolver`. See the
    /// documentation for `AsyncResolver` for more information on how to use
    /// the background future.
    pub(crate) async fn with_cache_with_spawn(
        config: ResolverConfig,
        options: ResolverOpts,
        lru: Arc<Mutex<DnsLru>>,
        spawn_bg: S,
    ) -> Result<Self, ResolveError> {
        debug!("trust-dns resolver running");

        let pool = NameServerPool::<Connection, StandardConnection, S>::from_config_with_provider(
            &config,
            &options,
            StandardConnection,
            spawn_bg,
        );
        let either;
        let client = RetryDnsHandle::new(pool, options.attempts);
        if options.validate {
            #[cfg(feature = "dnssec")]
            {
                use proto::xfer::SecureDnsHandle;
                either = LookupEither::Secure(SecureDnsHandle::new(client));
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
        Ok(AsyncResolver {
            config,
            options,
            client_cache: CachingClient::with_cache(lru, either),
            hosts,
        })
    }

    /// Constructs a new Resolver with the system configuration.
    ///
    /// This will use `/etc/resolv.conf` on Unix OSes and the registry on Windows.
    #[cfg(any(unix, target_os = "windows"))]
    pub async fn from_system_conf_with_spawn(spawn_bg: S) -> Result<Self, ResolveError> {
        let (config, options) = super::system_conf::read_system_conf()?;
        Self::new_with_spawn(config, options, spawn_bg).await
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
        if name.is_fqdn() {
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
                Self::push_name(name_search, &mut names);
            }

            if let Some(domain) = self.config.domain() {
                let name_search = name.clone().append_domain(domain);
                Self::push_name(name_search, &mut names);
            }

            // this is the direct name lookup
            if raw_name_first {
                // adding the name as though it's an FQDN for lookup
                names.push(name);
            }

            names
        }
    }

    pub(crate) fn inner_lookup<L>(
        &self,
        name: Name,
        record_type: RecordType,
        options: DnsRequestOptions,
    ) -> impl Future<Output = Result<L, ResolveError>> + Send + Unpin + 'static
    where
        L: From<Lookup> + Send + 'static,
    {
        self.lookup(name, record_type, options).map_ok(L::from)
    }

    /// Performs a dual-stack DNS lookup for the IP for the given hostname.
    ///
    /// See the configuration and options parameters for controlling the way in which A(Ipv4) and AAAA(Ipv6) lookups will be performed. For the least expensive query a fully-qualified-domain-name, FQDN, which ends in a final `.`, e.g. `www.example.com.`, will only issue one query. Anything else will always incur the cost of querying the `ResolverConfig::domain` and `ResolverConfig::search`.
    ///
    /// # Arguments
    /// * `host` - string hostname, if this is an invalid hostname, an error will be returned.
    pub fn lookup_ip<N: IntoName + TryParseIp>(
        &self,
        host: N,
    ) -> impl Future<Output = Result<LookupIp, ResolveError>> + Send + Unpin + 'static {
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
                let lookup = Lookup::new_with_max_ttl(query, Arc::new(vec![record]));
                return future::Either::Left(future::ok(lookup.into()));
            }
        }

        let name = match (maybe_name, finally_ip_addr.as_ref()) {
            (Ok(name), _) => name,
            (Err(_), Some(ip_addr)) => {
                // it was a valid IP, return that...
                let query = Query::query(ip_addr.name().clone(), ip_addr.record_type());
                let lookup = Lookup::new_with_max_ttl(query, Arc::new(vec![ip_addr.clone()]));
                return future::Either::Left(future::ok(lookup.into()));
            }
            (Err(err), None) => {
                return future::Either::Left(future::err(err.into()));
            }
        };

        let names = self.build_names(name);
        let hosts = self.hosts.as_ref().cloned();

        future::Either::Right(LookupIpFuture::lookup(
            names,
            self.options.ip_strategy,
            self.client_cache.clone(),
            DnsRequestOptions::default(),
            hosts,
            finally_ip_addr.map(Record::unwrap_rdata),
        ))
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
    lookup_fn!(txt_lookup, lookup::TxtLookup, RecordType::TXT);
}

impl<S: SpawnBg> fmt::Debug for AsyncResolver<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AsyncResolver")
            .field("request_tx", &"...")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate env_logger;
    extern crate tokio;

    use failure::Fail;
    use std::net::*;
    use std::str::FromStr;

    use self::tokio::runtime::Runtime;
    use proto::xfer::DnsRequest;

    use crate::config::{LookupIpStrategy, NameServerConfig};

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
        assert!(is_send_t::<ResolverConfig>());
        assert!(is_send_t::<ResolverOpts>());
        assert!(is_sync_t::<ResolverOpts>());

        assert!(is_send_t::<AsyncResolver<TokioSpawnBg>>());
        assert!(is_sync_t::<AsyncResolver<TokioSpawnBg>>());

        assert!(is_send_t::<DnsRequest>());
        assert!(is_send_t::<LookupIpFuture>());
        assert!(is_send_t::<LookupFuture>());
    }

    fn lookup_test(config: ResolverConfig) {
        //env_logger::try_init().ok();

        let mut io_loop = Runtime::new().unwrap();
        let resolver =
            AsyncResolver::new(config, ResolverOpts::default(), io_loop.handle().clone());
        let resolver = io_loop
            .block_on(resolver)
            .expect("failed to create resolver");

        let response = io_loop
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

    #[test]
    fn test_lookup_google() {
        lookup_test(ResolverConfig::google())
    }

    #[test]
    fn test_lookup_cloudflare() {
        lookup_test(ResolverConfig::cloudflare())
    }

    #[test]
    fn test_lookup_quad9() {
        lookup_test(ResolverConfig::quad9())
    }

    #[test]
    fn test_ip_lookup() {
        //env_logger::try_init().ok();

        let mut io_loop = Runtime::new().unwrap();
        let resolver = AsyncResolver::new(
            ResolverConfig::default(),
            ResolverOpts::default(),
            io_loop.handle().clone(),
        );
        let resolver = io_loop
            .block_on(resolver)
            .expect("failed to create resolver");

        let response = io_loop
            .block_on(resolver.lookup_ip("10.1.0.2"))
            .expect("failed to run lookup");

        assert_eq!(
            Some(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2))),
            response.iter().next()
        );

        let response = io_loop
            .block_on(resolver.lookup_ip("2606:2800:220:1:248:1893:25c8:1946"))
            .expect("failed to run lookup");

        assert_eq!(
            Some(IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            ))),
            response.iter().next()
        );
    }

    #[test]
    fn test_ip_lookup_across_threads() {
        // Test ensuring that running the background task on a separate Tokio
        // executor in a separate thread from the futures returned by the
        // AsyncResolver works correctly.
        use std::thread;
        let mut io_loop = Runtime::new().unwrap();
        let resolver = AsyncResolver::new(
            ResolverConfig::default(),
            ResolverOpts::default(),
            io_loop.handle().clone(),
        );
        let resolver = io_loop
            .block_on(resolver)
            .expect("failed to create resolver");

        let resolver_one = resolver.clone();
        let resolver_two = resolver.clone();

        //FIXME: put the logic in two separate threads...

        let test_fn = |resolver: AsyncResolver<TokioSpawnBg>| {
            let mut io_loop = Runtime::new().unwrap();

            let response = io_loop
                .block_on(resolver.lookup_ip("10.1.0.2"))
                .expect("failed to run lookup");

            assert_eq!(
                Some(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2))),
                response.iter().next()
            );

            let response = io_loop
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

    #[test]
    #[ignore] // these appear to not work on travis
    fn test_sec_lookup() {
        let mut io_loop = Runtime::new().unwrap();
        let resolver = AsyncResolver::new(
            ResolverConfig::default(),
            ResolverOpts {
                validate: true,
                ..ResolverOpts::default()
            },
            io_loop.handle().clone(),
        );
        let resolver = io_loop
            .block_on(resolver)
            .expect("failed to create resolver");

        let response = io_loop
            .block_on(resolver.lookup_ip("www.example.com."))
            .expect("failed to run lookup");

        // TODO: this test is flaky, sometimes 1 is returned, sometimes 2...
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

    #[allow(deprecated)]
    #[test]
    #[ignore] // these appear to not work on travis
    #[allow(deprecated)]
    fn test_sec_lookup_fails() {
        let mut io_loop = Runtime::new().unwrap();
        let resolver = AsyncResolver::new(
            ResolverConfig::default(),
            ResolverOpts {
                validate: true,
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
            io_loop.handle().clone(),
        );
        let resolver = io_loop
            .block_on(resolver)
            .expect("failed to create resolver");

        // needs to be a domain that exists, but is not signed (eventually this will be)
        let name = Name::from_str("www.trust-dns.org.").unwrap();
        let response = io_loop.block_on(resolver.lookup_ip("www.trust-dns.org."));

        assert!(response.is_err());
        let error = response.unwrap_err();

        use proto::error::{ProtoError, ProtoErrorKind};

        let error_str = format!("{}", error.root_cause());
        let expected_str = format!(
            "{}",
            ProtoError::from(ProtoErrorKind::RrsigsNotPresent {
                name,
                record_type: RecordType::A
            })
        );
        assert_eq!(error_str, expected_str);
        assert_eq!(*error.kind(), ResolveErrorKind::Proto);
    }

    #[test]
    #[ignore]
    #[cfg(any(unix, target_os = "windows"))]
    fn test_system_lookup() {
        let mut io_loop = Runtime::new().unwrap();
        let resolver = AsyncResolver::from_system_conf(io_loop.handle().clone());
        let resolver = io_loop
            .block_on(resolver)
            .expect("failed to create resolver");

        let response = io_loop
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

    #[test]
    #[ignore]
    // these appear to not work on travis, test on macos with `10.1.0.104  a.com`
    #[cfg(unix)]
    fn test_hosts_lookup() {
        let mut io_loop = Runtime::new().unwrap();
        let resolver = AsyncResolver::from_system_conf(io_loop.handle().clone());
        let resolver = io_loop
            .block_on(resolver)
            .expect("failed to create resolver");

        let response = io_loop
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

    #[test]
    fn test_fqdn() {
        let domain = Name::from_str("incorrect.example.com.").unwrap();
        let search = vec![
            Name::from_str("bad.example.com.").unwrap(),
            Name::from_str("wrong.example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let mut io_loop = Runtime::new().unwrap();
        let resolver = AsyncResolver::new(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
            io_loop.handle().clone(),
        );
        let resolver = io_loop
            .block_on(resolver)
            .expect("failed to create resolver");

        let response = io_loop
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

    #[test]
    fn test_ndots() {
        let domain = Name::from_str("incorrect.example.com.").unwrap();
        let search = vec![
            Name::from_str("bad.example.com.").unwrap(),
            Name::from_str("wrong.example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let mut io_loop = Runtime::new().unwrap();
        let resolver = AsyncResolver::new(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            ResolverOpts {
                // our name does have 2, the default should be fine, let's just narrow the test criteria a bit.
                ndots: 2,
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
            io_loop.handle().clone(),
        );
        let resolver = io_loop
            .block_on(resolver)
            .expect("failed to create resolver");

        // notice this is not a FQDN, no trailing dot.
        let response = io_loop
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

    #[test]
    fn test_large_ndots() {
        let domain = Name::from_str("incorrect.example.com.").unwrap();
        let search = vec![
            Name::from_str("bad.example.com.").unwrap(),
            Name::from_str("wrong.example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let mut io_loop = Runtime::new().unwrap();
        let resolver = AsyncResolver::new(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            ResolverOpts {
                // matches kubernetes default
                ndots: 5,
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
            io_loop.handle().clone(),
        );
        let resolver = io_loop
            .block_on(resolver)
            .expect("failed to create resolver");

        // notice this is not a FQDN, no trailing dot.
        let response = io_loop
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

    #[test]
    fn test_domain_search() {
        //env_logger::try_init().ok();

        // domain is good now, should be combined with the name to form www.example.com
        let domain = Name::from_str("example.com.").unwrap();
        let search = vec![
            Name::from_str("bad.example.com.").unwrap(),
            Name::from_str("wrong.example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let mut io_loop = Runtime::new().unwrap();
        let resolver = AsyncResolver::new(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
            io_loop.handle().clone(),
        );
        let resolver = io_loop
            .block_on(resolver)
            .expect("failed to create resolver");

        // notice no dots, should not trigger ndots rule
        let response = io_loop
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

    #[test]
    fn test_search_list() {
        //env_logger::try_init().ok();

        let domain = Name::from_str("incorrect.example.com.").unwrap();
        let search = vec![
            // let's skip one search domain to test the loop...
            Name::from_str("bad.example.com.").unwrap(),
            // this should combine with the search name to form www.example.com
            Name::from_str("example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let mut io_loop = Runtime::new().unwrap();
        let resolver = AsyncResolver::new(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
            io_loop.handle().clone(),
        );
        let resolver = io_loop
            .block_on(resolver)
            .expect("failed to create resolver");

        // notice no dots, should not trigger ndots rule
        let response = io_loop
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

    #[test]
    fn test_idna() {
        let mut io_loop = Runtime::new().unwrap();
        let resolver = AsyncResolver::new(
            ResolverConfig::default(),
            ResolverOpts::default(),
            io_loop.handle().clone(),
        );
        let resolver = io_loop
            .block_on(resolver)
            .expect("failed to create resolver");

        let response = io_loop
            .block_on(resolver.lookup_ip("中国.icom.museum."))
            .expect("failed to run lookup");

        // we just care that the request succeeded, not about the actual content
        //   it's not certain that the ip won't change.
        assert!(response.iter().next().is_some());
    }

    #[test]
    fn test_localhost_ipv4() {
        let mut io_loop = Runtime::new().unwrap();
        let resolver = AsyncResolver::new(
            ResolverConfig::default(),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4thenIpv6,
                ..ResolverOpts::default()
            },
            io_loop.handle().clone(),
        );
        let resolver = io_loop
            .block_on(resolver)
            .expect("failed to create resolver");

        let response = io_loop
            .block_on(resolver.lookup_ip("localhost"))
            .expect("failed to run lookup");

        let mut iter = response.iter();
        assert_eq!(
            iter.next().expect("no A"),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        );
    }

    #[test]
    fn test_localhost_ipv6() {
        let mut io_loop = Runtime::new().unwrap();
        let resolver = AsyncResolver::new(
            ResolverConfig::default(),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv6thenIpv4,
                ..ResolverOpts::default()
            },
            io_loop.handle().clone(),
        );
        let resolver = io_loop
            .block_on(resolver)
            .expect("failed to create resolver");

        let response = io_loop
            .block_on(resolver.lookup_ip("localhost"))
            .expect("failed to run lookup");

        let mut iter = response.iter();
        assert_eq!(
            iter.next().expect("no AAAA"),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1,))
        );
    }

    #[test]
    fn test_search_ipv4_large_ndots() {
        let mut io_loop = Runtime::new().unwrap();
        let mut config = ResolverConfig::default();
        config.add_search(Name::from_str("example.com").unwrap());

        let resolver = AsyncResolver::new(
            config,
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ndots: 5,
                ..ResolverOpts::default()
            },
            io_loop.handle().clone(),
        );
        let resolver = io_loop
            .block_on(resolver)
            .expect("failed to create resolver");

        let response = io_loop
            .block_on(resolver.lookup_ip("198.51.100.35"))
            .expect("failed to run lookup");

        let mut iter = response.iter();
        assert_eq!(
            iter.next().expect("no rdatas"),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 35))
        );
    }

    #[test]
    fn test_search_ipv6_large_ndots() {
        let mut io_loop = Runtime::new().unwrap();
        let mut config = ResolverConfig::default();
        config.add_search(Name::from_str("example.com").unwrap());

        let resolver = AsyncResolver::new(
            config,
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ndots: 5,
                ..ResolverOpts::default()
            },
            io_loop.handle().clone(),
        );
        let resolver = io_loop
            .block_on(resolver)
            .expect("failed to create resolver");

        let response = io_loop
            .block_on(resolver.lookup_ip("2001:db8::c633:6423"))
            .expect("failed to run lookup");

        let mut iter = response.iter();
        assert_eq!(
            iter.next().expect("no rdatas"),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0xc633, 0x6423))
        );
    }

    #[test]
    fn test_search_ipv6_name_parse_fails() {
        let mut io_loop = Runtime::new().unwrap();
        let mut config = ResolverConfig::default();
        config.add_search(Name::from_str("example.com").unwrap());

        let resolver = AsyncResolver::new(
            config,
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ndots: 5,
                ..ResolverOpts::default()
            },
            io_loop.handle().clone(),
        );
        let resolver = io_loop
            .block_on(resolver)
            .expect("failed to create resolver");

        let response = io_loop
            .block_on(resolver.lookup_ip("2001:db8::198.51.100.35"))
            .expect("failed to run lookup");

        let mut iter = response.iter();
        assert_eq!(
            iter.next().expect("no rdatas"),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0xc633, 0x6423))
        );
    }
}
