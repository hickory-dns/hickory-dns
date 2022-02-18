// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Structs for creating and using a Resolver
use std::io;
use std::net::IpAddr;
use std::sync::Mutex;

use proto::rr::domain::TryParseIp;
use proto::rr::IntoName;
use proto::rr::RecordType;
use tokio::runtime::{self, Runtime};
use trust_dns_proto::xfer::DnsRequestOptions;

use crate::config::{ResolverConfig, ResolverOpts};
use crate::error::*;
use crate::lookup;
use crate::lookup::Lookup;
use crate::lookup_ip::LookupIp;
use crate::name_server::{TokioConnection, TokioConnectionProvider, TokioHandle};
use crate::AsyncResolver;

/// The Resolver is used for performing DNS queries.
///
/// For forward (A) lookups, hostname -> IP address, see: `Resolver::lookup_ip`
///
/// Special note about resource consumption. The Resolver and all Trust-DNS software is built around the Tokio async-io library. This synchronous Resolver is intended to be a simpler wrapper for of the [`AsyncResolver`]. To allow the `Resolver` to be [`Send`] + [`Sync`], the construction of the `AsyncResolver` is lazy, this means some of the features of the `AsyncResolver`, like performance based resolution via the most efficient `NameServer` will be lost (the lookup cache is shared across invocations of the `Resolver`). If these other features of the Trust-DNS Resolver are desired, please use the tokio based [`AsyncResolver`].
///
/// *Note: Threaded/Sync usage*: In multithreaded scenarios, the internal Tokio Runtime will block on an internal Mutex for the tokio Runtime in use. For higher performance, it's recommended to use the [`AsyncResolver`].
pub struct Resolver {
    // TODO: Mutex allows this to be Sync, another option would be to instantiate a thread_local, but that has other
    //   drawbacks. One major issues, is if this Resolver is shared across threads, it will cause all to block on any
    //   query. A TLS on the other hand would not, at the cost of only allowing a Resolver to be configured once per Thread
    runtime: Mutex<Runtime>,
    async_resolver: AsyncResolver<TokioConnection, TokioConnectionProvider>,
}

macro_rules! lookup_fn {
    ($p:ident, $l:ty) => {
        /// Performs a lookup for the associated type.
        ///
        /// *hint* queries that end with a '.' are fully qualified names and are cheaper lookups
        ///
        /// # Arguments
        ///
        /// * `query` - a `&str` which parses to a domain name, failure to parse will return an error
        pub fn $p<N: IntoName>(&self, query: N) -> ResolveResult<$l> {
            let lookup = self.async_resolver.$p(query);
            self.runtime.lock()?.block_on(lookup)
        }
    };
    ($p:ident, $l:ty, $t:ty) => {
        /// Performs a lookup for the associated type.
        ///
        /// # Arguments
        ///
        /// * `query` - a type which can be converted to `Name` via `From`.
        pub fn $p(&self, query: $t) -> ResolveResult<$l> {
            let lookup = self.async_resolver.$p(query);
            self.runtime.lock()?.block_on(lookup)
        }
    };
}

impl Resolver {
    /// Constructs a new Resolver with the specified configuration.
    ///
    /// # Arguments
    /// * `config` - configuration for the resolver
    /// * `options` - resolver options for performing lookups
    ///
    /// # Returns
    ///
    /// A new `Resolver` or an error if there was an error with the configuration.
    pub fn new(config: ResolverConfig, options: ResolverOpts) -> io::Result<Self> {
        let mut builder = runtime::Builder::new_current_thread();
        builder.enable_all();

        let runtime = builder.build()?;
        let async_resolver =
            AsyncResolver::new(config, options, TokioHandle).expect("failed to create resolver");

        Ok(Self {
            runtime: Mutex::new(runtime),
            async_resolver,
        })
    }

    /// Constructs a new Resolver with default config and default options.
    ///
    /// See [`ResolverConfig::default`] and [`ResolverOpts::default`] for more information.
    ///
    /// # Returns
    ///
    /// A new `Resolver` or an error if there was an error with the configuration.
    pub fn default() -> io::Result<Self> {
        Self::new(ResolverConfig::default(), ResolverOpts::default())
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
    pub fn from_system_conf() -> io::Result<Self> {
        let (config, options) = super::system_conf::read_system_conf()?;
        Self::new(config, options)
    }

    /// Flushes/Removes all entries from the cache
    pub fn clear_cache(&mut self) -> ResolveResult<()> {
        let clearing = self.async_resolver.clear_cache();
        self.runtime.lock()?.block_on(clearing);
        Ok(())
    }

    /// Generic lookup for any RecordType
    ///
    /// *WARNING* This interface may change in the future, please use [`Self::lookup_ip`] or another variant for more stable interfaces.
    ///
    /// # Arguments
    ///
    /// * `name` - name of the record to lookup, if name is not a valid domain name, an error will be returned
    /// * `record_type` - type of record to lookup
    pub fn lookup<N: IntoName>(&self, name: N, record_type: RecordType) -> ResolveResult<Lookup> {
        let lookup = self
            .async_resolver
            .lookup(name, record_type, DnsRequestOptions::default());
        self.runtime.lock()?.block_on(lookup)
    }

    /// Performs a dual-stack DNS lookup for the IP for the given hostname.
    ///
    /// See the configuration and options parameters for controlling the way in which A(Ipv4) and AAAA(Ipv6) lookups will be performed. For the least expensive query a fully-qualified-domain-name, FQDN, which ends in a final `.`, e.g. `www.example.com.`, will only issue one query. Anything else will always incur the cost of querying the `ResolverConfig::domain` and `ResolverConfig::search`.
    ///
    /// # Arguments
    ///
    /// * `host` - string hostname, if this is an invalid hostname, an error will be returned.
    pub fn lookup_ip<N: IntoName + TryParseIp>(&self, host: N) -> ResolveResult<LookupIp> {
        let lookup = self.async_resolver.lookup_ip(host);
        self.runtime.lock()?.block_on(lookup)
    }

    lookup_fn!(reverse_lookup, lookup::ReverseLookup, IpAddr);
    lookup_fn!(ipv4_lookup, lookup::Ipv4Lookup);
    lookup_fn!(ipv6_lookup, lookup::Ipv6Lookup);
    lookup_fn!(mx_lookup, lookup::MxLookup);
    lookup_fn!(ns_lookup, lookup::NsLookup);
    lookup_fn!(soa_lookup, lookup::SoaLookup);
    lookup_fn!(srv_lookup, lookup::SrvLookup);
    lookup_fn!(tlsa_lookup, lookup::TlsaLookup);
    lookup_fn!(txt_lookup, lookup::TxtLookup);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use std::net::*;

    use super::*;

    fn require_send_sync<S: Send + Sync>() {}

    #[test]
    fn test_resolver_sendable() {
        require_send_sync::<Resolver>();
    }

    #[test]
    fn test_lookup() {
        let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();

        let response = resolver.lookup_ip("www.example.com.").unwrap();
        println!("response records: {:?}", response);

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
    #[ignore]
    #[cfg(any(unix, target_os = "windows"))]
    fn test_system_lookup() {
        let resolver = Resolver::from_system_conf().unwrap();

        let response = resolver.lookup_ip("www.example.com.").unwrap();
        println!("response records: {:?}", response);

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
}
