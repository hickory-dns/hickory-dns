// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Structs for creating and using a Resolver

use std::cell::RefCell;
use std::net::IpAddr;
use std::io;

use tokio_core::reactor::Core;
use trust_dns_proto::rr::RecordType;

use config::{ResolverConfig, ResolverOpts};
use error::*;
use lookup;
use lookup::Lookup;
use lookup_ip::LookupIp;
use ResolverFuture;

/// The Resolver is used for performing DNS queries.
///
/// For forward (A) lookups, hostname -> IP address, see: `Resolver::lookup_ip`
pub struct Resolver {
    resolver_future: RefCell<ResolverFuture>,
    io_loop: RefCell<Core>,
}

macro_rules! lookup_fn {
    ($p:ident, $l:ty) => {
/// Performs a lookup for the associated type.
///
/// *hint* queries that end with a '.' are fully qualified names and are cheaper lookups
///
/// # Arguments
///
/// * `query` - a str which parses to a domain name, failure to parse will return an error
pub fn $p(&self, query: &str) -> ResolveResult<$l> {
    self.io_loop.borrow_mut().run(
            self.resolver_future
                .borrow()
                .$p(query),
        )
}
    };
    ($p:ident, $l:ty, $t:ty) => {
/// Performs a lookup for the associated type.
///
/// # Arguments
///
/// * `query` - a type which can be converted to `Name` via `From`.
pub fn $p(&self, query: $t) -> ResolveResult<$l> {
    self.io_loop.borrow_mut().run(
            self.resolver_future
                .borrow()            
                .$p(query),
        )
}
    };
}

impl Resolver {
    /// Constructs a new Resolver with the specified configuration.
    ///
    /// # Arguments
    /// * `config` - configuration for the resolver
    /// * `options` - resolver options for performing lookups
    /// * `client_connection` - ClientConnection for establishing the connection to the DNS server
    ///
    /// # Returns
    /// A new Resolver
    pub fn new(config: ResolverConfig, options: ResolverOpts) -> io::Result<Self> {
        let io_loop = Core::new()?;
        let resolver = ResolverFuture::new(config, options, &io_loop.handle());

        Ok(Resolver {
            resolver_future: RefCell::new(resolver),
            io_loop: RefCell::new(io_loop),
        })
    }

    /// Constructs a new Resolver with the system configuration.
    ///
    /// This will use `/etc/resolv.conf` on Unix OSes and the registry on Windows.
    #[cfg(any(unix,
              all(feature = "ipconfig", target_os = "windows", target_pointer_width = "64")))]
    pub fn from_system_conf() -> io::Result<Self> {
        let (config, options) = super::system_conf::read_system_conf()?;
        Self::new(config, options)
    }

    /// Generic lookup for any RecordType
    ///
    /// *WARNING* This interface may change in the future
    ///
    /// # Arguments
    ///
    /// * `name` - name of the record to lookup, if name is not a valid domain name, an error will be returned
    /// * `record_type` - type of record to lookup
    pub fn lookup(&self, name: &str, record_type: RecordType) -> ResolveResult<Lookup> {
        self.io_loop.borrow_mut().run(
            self.resolver_future
                .borrow()
                .lookup(name, record_type),
        )
    }

    /// Performs a dual-stack DNS lookup for the IP for the given hostname.
    ///
    /// See the configuration and options parameters for controlling the way in which A(Ipv4) and AAAA(Ipv6) lookups will be performed. For the least expensive query a fully-qualified-domain-name, FQDN, which ends in a final `.`, e.g. `www.example.com.`, will only issue one query. Anything else will always incur the cost of querying the `ResolverConfig::domain` and `ResolverConfig::search`.
    ///
    /// # Arguments
    ///
    /// * `host` - string hostname, if this is an invalid hostname, an error will be returned.
    pub fn lookup_ip(&self, host: &str) -> ResolveResult<LookupIp> {
        self.io_loop.borrow_mut().run(
            self.resolver_future
                .borrow()
                .lookup_ip(host),
        )
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
    pub fn lookup_service(
        &self,
        service: &str,
        protocol: &str,
        name: &str,
    ) -> ResolveResult<lookup::SrvLookup> {
        self.io_loop.borrow_mut().run(
            self.resolver_future.borrow().lookup_service(
                service,
                protocol,
                name,
            ),
        )
    }

    lookup_fn!(reverse_lookup, lookup::ReverseLookup, IpAddr);
    lookup_fn!(ipv4_lookup, lookup::Ipv4Lookup);
    lookup_fn!(ipv6_lookup, lookup::Ipv6Lookup);
    lookup_fn!(mx_lookup, lookup::MxLookup);
    lookup_fn!(srv_lookup, lookup::SrvLookup);
    lookup_fn!(txt_lookup, lookup::TxtLookup);
}

#[cfg(test)]
mod tests {
    use std::net::*;

    use super::*;

    #[test]
    fn test_lookup() {
        let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();

        let response = resolver.lookup_ip("www.example.com.").unwrap();
        println!("response records: {:?}", response);

        assert_eq!(response.iter().count(), 2);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                assert_eq!(
                    address,
                    IpAddr::V6(Ipv6Addr::new(
                        0x2606,
                        0x2800,
                        0x220,
                        0x1,
                        0x248,
                        0x1893,
                        0x25c8,
                        0x1946,
                    ))
                );
            }
        }
    }

    #[test]
    #[ignore]
    #[cfg(any(unix,
             all(feature = "ipconfig", target_os = "windows", target_pointer_width = "64")))]
    fn test_system_lookup() {
        let resolver = Resolver::from_system_conf().unwrap();

        let response = resolver.lookup_ip("www.example.com.").unwrap();
        println!("response records: {:?}", response);

        assert_eq!(response.iter().count(), 2);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                assert_eq!(
                    address,
                    IpAddr::V6(Ipv6Addr::new(
                        0x2606,
                        0x2800,
                        0x220,
                        0x1,
                        0x248,
                        0x1893,
                        0x25c8,
                        0x1946,
                    ))
                );
            }
        }
    }
}
