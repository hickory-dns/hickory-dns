// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Structs for creating and using a AsyncResolver
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use futures::{
    self, future,
    sync::{mpsc, oneshot},
    Future, Poll,
};
use proto::error::ProtoResult;
use proto::rr::domain::TryParseIp;
use proto::rr::{IntoName, Name, RData, RecordType};
use proto::xfer::DnsRequestOptions;

use config::{ResolverConfig, ResolverOpts};
use dns_lru::{self, DnsLru};
use error::*;
use lookup::{self, LookupFuture};
use lookup_ip::LookupIpFuture;

mod background;

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
/// for any incoming lookup requests, handling them, and and yielding. It will
/// continue to do so as long as there are still any [`AsyncResolver`] handle
/// linked to it. When all of its [`AsyncResolver`]s have been dropped, the
/// background future will finish.
#[derive(Clone)]
pub struct AsyncResolver {
    request_tx: mpsc::UnboundedSender<Request>,
}

/// A future that represents sending a request to a background task,
/// waiting for it to send back a lookup future, and then running the
/// lookup future.
#[derive(Debug)]
pub struct Background<F, G = F>
where
    F: Future<Error = ResolveError>,
    G: Future<Error = ResolveError>,
{
    inner: BgInner<G::Item, F, G>,
}

/// Future returned by `LookupIp` requests to the background task.
pub type BackgroundLookupIp = Background<LookupIpFuture>;

/// Future returned by lookup requests to the background task.
pub type BackgroundLookup<F = LookupFuture> = Background<LookupFuture, F>;

/// Type alias for the complex inner part of a `Background` future.
type BgInner<T, F, G> = future::Either<BgSend<F, G>, future::FutureResult<T, ResolveError>>;

/// The branch of `BgInner` where the request was successfully sent
/// to the background task.
type BgSend<F, G> = futures::AndThen<
    futures::MapErr<oneshot::Receiver<F>, fn(oneshot::Canceled) -> ResolveError>,
    G,
    fn(F) -> G,
>;

/// Used by `AsyncResolver` for communicating with the background resolver task.
#[allow(clippy::large_enum_variant)]
enum Request {
    /// Requests a lookup of the specified `RecordType`.
    Lookup {
        name: Name,
        record_type: RecordType,
        options: DnsRequestOptions,
        tx: oneshot::Sender<LookupFuture>,
    },
    /// Requests an IP lookup for a name or IP address.
    Ip {
        maybe_name: ProtoResult<Name>,
        maybe_ip: Option<RData>,
        tx: oneshot::Sender<LookupIpFuture>,
    },
}

macro_rules! lookup_fn {
    ($p:ident, $f:ty, $r:path) => {
/// Performs a lookup for the associated type.
///
/// *hint* queries that end with a '.' are fully qualified names and are cheaper lookups
///
/// # Arguments
///
/// * `query` - a string which parses to a domain name, failure to parse will return an error
pub fn $p<N: IntoName>(&self, query: N) -> BackgroundLookup<$f> {
    let name = match query.into_name() {
        Ok(name) => name,
        Err(err) => {
            return err.into();
        }
    };

    self.inner_lookup(name, $r, DnsRequestOptions::default(),)
}
    };
    ($p:ident, $f:ty, $r:path, $t:ty) => {
/// Performs a lookup for the associated type.
///
/// # Arguments
///
/// * `query` - a type which can be converted to `Name` via `From`.
pub fn $p(&self, query: $t) -> BackgroundLookup<$f> {
    let name = Name::from(query);
    self.inner_lookup(name, $r, DnsRequestOptions::default(),)
}
    };
}

impl AsyncResolver {
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
    pub fn new(
        config: ResolverConfig,
        options: ResolverOpts,
    ) -> (Self, impl Future<Item = (), Error = ()>) {
        let lru = DnsLru::new(options.cache_size, dns_lru::TtlConfig::from_opts(&options));
        let lru = Arc::new(Mutex::new(lru));

        Self::with_cache(config, options, lru)
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
    pub(crate) fn with_cache(
        config: ResolverConfig,
        options: ResolverOpts,
        lru: Arc<Mutex<DnsLru>>,
    ) -> (Self, impl Future<Item = (), Error = ()>) {
        let (request_tx, request_rx) = mpsc::unbounded();
        let background = background::task(config, options, lru, request_rx);
        let handle = Self { request_tx };
        (handle, background)
    }

    /// Constructs a new Resolver with the system configuration.
    ///
    /// This will use `/etc/resolv.conf` on Unix OSes and the registry on Windows.
    #[cfg(any(unix, target_os = "windows"))]
    pub fn from_system_conf() -> ResolveResult<(Self, impl Future<Item = (), Error = ()>)> {
        let (config, options) = super::system_conf::read_system_conf()?;
        Ok(Self::new(config, options))
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
    pub fn lookup<N: IntoName>(&self, name: N, record_type: RecordType) -> BackgroundLookup {
        let name = match name.into_name() {
            Ok(name) => name,
            Err(err) => return err.into(),
        };

        self.inner_lookup(name, record_type, DnsRequestOptions::default())
    }

    fn oneshot_canceled(_: oneshot::Canceled) -> ResolveError {
        ResolveErrorKind::Message("oneshot canceled unexpectedly, this is a bug").into()
    }

    pub(crate) fn inner_lookup<F>(
        &self,
        name: Name,
        record_type: RecordType,
        options: DnsRequestOptions,
    ) -> BackgroundLookup<F>
    where
        F: Future<Error = ResolveError>,
        F: From<LookupFuture>,
    {
        let (tx, rx) = oneshot::channel();
        let request = Request::Lookup {
            name,
            record_type,
            options,
            tx,
        };
        if self.request_tx.unbounded_send(request).is_err() {
            return ResolveErrorKind::Message("background resolver gone, this is a bug").into();
        }
        let f: BgSend<LookupFuture, F> = rx
            .map_err(Self::oneshot_canceled as fn(oneshot::Canceled) -> ResolveError)
            .and_then(F::from);
        BackgroundLookup::from(f)
    }

    /// Performs a dual-stack DNS lookup for the IP for the given hostname.
    ///
    /// See the configuration and options parameters for controlling the way in which A(Ipv4) and AAAA(Ipv6) lookups will be performed. For the least expensive query a fully-qualified-domain-name, FQDN, which ends in a final `.`, e.g. `www.example.com.`, will only issue one query. Anything else will always incur the cost of querying the `ResolverConfig::domain` and `ResolverConfig::search`.
    ///
    /// # Arguments
    /// * `host` - string hostname, if this is an invalid hostname, an error will be returned.
    pub fn lookup_ip<N: IntoName + TryParseIp>(&self, host: N) -> BackgroundLookupIp {
        let (tx, rx) = oneshot::channel();
        let maybe_ip = host.try_parse_ip();
        let request = Request::Ip {
            maybe_name: host.into_name(),
            maybe_ip,
            tx,
        };

        if self.request_tx.unbounded_send(request).is_err() {
            // Note: this shouldn't happen. We return a ResolveError here, but it would
            // probably be okay to just `expect` the unbounded send to be successful.
            return ResolveErrorKind::Message("background resolver gone, this is a bug").into();
        }
        let f: BgSend<LookupIpFuture, LookupIpFuture> = rx
            .map_err(Self::oneshot_canceled as fn(oneshot::Canceled) -> ResolveError)
            .and_then(LookupIpFuture::from);
        BackgroundLookupIp::from(f)
    }

    /// Performs a DNS lookup for an SRV record for the specified service type and protocol at the given name.
    ///
    /// This is a convenience method over `lookup_srv`, it combines the service, protocol and name into a single name: `_service._protocol.name`.
    ///
    /// # Arguments
    ///
    /// * `service` - service to lookup, e.g. ldap or http
    /// * `protocol` - wire protocol, e.g. udp or tcp
    /// * `name` - zone or other name at which the service is located.
    #[deprecated(note = "use lookup_srv instead, this interface is none ideal")]
    pub fn lookup_service(
        &self,
        service: &str,
        protocol: &str,
        name: &str,
    ) -> BackgroundLookup<lookup::SrvLookupFuture> {
        let name = format!("_{}._{}.{}", service, protocol, name);
        self.srv_lookup(name)
    }

    /// Lookup an SRV record.
    pub fn lookup_srv<N: IntoName>(&self, name: N) -> BackgroundLookup<lookup::SrvLookupFuture> {
        let name = match name.into_name() {
            Ok(name) => name,
            Err(err) => return err.into(),
        };

        self.inner_lookup(name, RecordType::SRV, DnsRequestOptions::default())
    }

    lookup_fn!(
        reverse_lookup,
        lookup::ReverseLookupFuture,
        RecordType::PTR,
        IpAddr
    );
    lookup_fn!(ipv4_lookup, lookup::Ipv4LookupFuture, RecordType::A);
    lookup_fn!(ipv6_lookup, lookup::Ipv6LookupFuture, RecordType::AAAA);
    lookup_fn!(mx_lookup, lookup::MxLookupFuture, RecordType::MX);
    #[deprecated(note = "use lookup_srv instead, this interface is none ideal")]
    lookup_fn!(srv_lookup, lookup::SrvLookupFuture, RecordType::SRV);
    lookup_fn!(txt_lookup, lookup::TxtLookupFuture, RecordType::TXT);
}

impl fmt::Debug for AsyncResolver {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AsyncResolver")
            // We probably don't want to print out the `fmt::Debug` output
            // for `mpsc::UnboundedSender`, as it's *quite* wordy but not
            // terribly useful...
            .field("request_tx", &"...")
            .finish()
    }
}

// ===== impl Background =====

impl<F, G> Future for Background<F, G>
where
    F: Future<Error = ResolveError>,
    G: Future<Error = ResolveError>,
    BgInner<G::Item, F, G>: Future<Item = G::Item, Error = ResolveError>,
{
    type Item = G::Item;
    type Error = ResolveError;

    #[inline]
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.inner.poll()
    }
}

impl<E, F, G> From<E> for Background<F, G>
where
    E: Into<ResolveError>,
    F: Future<Error = ResolveError>,
    G: Future<Error = ResolveError>,
{
    fn from(err: E) -> Self {
        Background {
            inner: future::Either::B(future::err(err.into())),
        }
    }
}

impl<F, G> From<BgSend<F, G>> for Background<F, G>
where
    F: Future<Error = ResolveError>,
    G: Future<Error = ResolveError>,
{
    fn from(f: BgSend<F, G>) -> Self {
        Background {
            inner: future::Either::A(f),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate env_logger;
    extern crate tokio;

    use failure::Fail;
    use std::net::*;
    use std::str::FromStr;

    use self::tokio::runtime::current_thread::Runtime;
    use proto::xfer::DnsRequest;

    use config::{LookupIpStrategy, NameServerConfig};

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

        assert!(is_send_t::<AsyncResolver>());
        assert!(is_sync_t::<AsyncResolver>());

        assert!(is_send_t::<DnsRequest>());
        assert!(is_send_t::<LookupIpFuture>());
        assert!(is_send_t::<LookupFuture>());
    }

    fn lookup_test(config: ResolverConfig) {
        let mut io_loop = Runtime::new().unwrap();
        let (resolver, bg) = AsyncResolver::new(config, ResolverOpts::default());
        io_loop.spawn(bg);

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
        env_logger::try_init().ok();

        let mut io_loop = Runtime::new().unwrap();
        let (resolver, bg) = AsyncResolver::new(ResolverConfig::default(), ResolverOpts::default());

        io_loop.spawn(bg);

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
        let (resolver, bg) = AsyncResolver::new(ResolverConfig::default(), ResolverOpts::default());

        thread::spawn(move || {
            let mut background_runtime = Runtime::new().unwrap();
            background_runtime
                .block_on(bg)
                .expect("background task failed");
        });

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
    #[ignore] // these appear to not work on travis
    fn test_sec_lookup() {
        let mut io_loop = Runtime::new().unwrap();
        let (resolver, bg) = AsyncResolver::new(
            ResolverConfig::default(),
            ResolverOpts {
                validate: true,
                ..ResolverOpts::default()
            },
        );

        io_loop.spawn(bg);

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
        let (resolver, bg) = AsyncResolver::new(
            ResolverConfig::default(),
            ResolverOpts {
                validate: true,
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
        );

        io_loop.spawn(bg);

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
        let (resolver, bg) = AsyncResolver::from_system_conf().unwrap();

        io_loop.spawn(bg);

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
        let (resolver, bg) = AsyncResolver::from_system_conf().unwrap();

        io_loop.spawn(bg);

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
        let (resolver, bg) = AsyncResolver::new(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
        );

        io_loop.spawn(bg);

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
        let (resolver, bg) = AsyncResolver::new(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            ResolverOpts {
                // our name does have 2, the default should be fine, let's just narrow the test criteria a bit.
                ndots: 2,
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
        );

        io_loop.spawn(bg);

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
        let (resolver, bg) = AsyncResolver::new(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            ResolverOpts {
                // matches kubernetes default
                ndots: 5,
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
        );

        io_loop.spawn(bg);

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
        env_logger::try_init().ok();

        // domain is good now, shoudl be combined with the name to form www.example.com
        let domain = Name::from_str("example.com.").unwrap();
        let search = vec![
            Name::from_str("bad.example.com.").unwrap(),
            Name::from_str("wrong.example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let mut io_loop = Runtime::new().unwrap();
        let (resolver, bg) = AsyncResolver::new(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
        );

        io_loop.spawn(bg);

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
        env_logger::try_init().ok();

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
        let (resolver, bg) = AsyncResolver::new(
            ResolverConfig::from_parts(Some(domain), search, name_servers),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
        );

        io_loop.spawn(bg);

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
        let (resolver, bg) = AsyncResolver::new(ResolverConfig::default(), ResolverOpts::default());

        io_loop.spawn(bg);

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
        let (resolver, bg) = AsyncResolver::new(
            ResolverConfig::default(),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4thenIpv6,
                ..ResolverOpts::default()
            },
        );

        io_loop.spawn(bg);

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
        let (resolver, bg) = AsyncResolver::new(
            ResolverConfig::default(),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv6thenIpv4,
                ..ResolverOpts::default()
            },
        );

        io_loop.spawn(bg);

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

        let (resolver, bg) = AsyncResolver::new(
            config,
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ndots: 5,
                ..ResolverOpts::default()
            },
        );

        io_loop.spawn(bg);

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

        let (resolver, bg) = AsyncResolver::new(
            config,
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ndots: 5,
                ..ResolverOpts::default()
            },
        );

        io_loop.spawn(bg);

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

        let (resolver, bg) = AsyncResolver::new(
            config,
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ndots: 5,
                ..ResolverOpts::default()
            },
        );

        io_loop.spawn(bg);

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
