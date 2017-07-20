// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Structs for creating and using a Resolver

use std::cell::RefCell;
use std::io;

use tokio_core::reactor::Core;

use config::{ResolverConfig, ResolverOpts};
use lookup_ip::LookupIp;
use ResolverFuture;

/// The Resolver is used for performing DNS queries.
///
/// For forward (A) lookups, hostname -> IP address, see: `Resolver::lookup_ip`
pub struct Resolver {
    resolver_future: RefCell<ResolverFuture>,
    io_loop: RefCell<Core>,
}


impl Resolver {
    /// Construct a new Resolver with the given ClientConnection, see UdpClientConnection and/or TcpCLientConnection
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

    // TODO: need to support ndot lookup options...
    /// Performs a DNS lookup for the IP for the given hostname.
    ///
    /// Based on the configuration and options passed in, this may do either a A or a AAAA lookup,
    ///  returning IpV4 or IpV6 addresses. (*Note*: current release only queries A, IPv4)
    ///
    /// # Arguments
    /// * `host` - string hostname, if this is an invalid hostname, an error will be thrown. Currently this must be a FQDN, with a trailing `.`, e.g. `www.example.com.`. This will be fixed in a future release.
    pub fn lookup_ip(&mut self, host: &str) -> io::Result<LookupIp> {
        self.io_loop.borrow_mut().run(
            self.resolver_future
                .borrow_mut()
                .lookup_ip(host),
        )
    }
}

#[cfg(test)]
mod tests {
    extern crate tokio_core;

    use std::net::*;

    use super::*;

    #[test]
    fn test_lookup() {
        let mut resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())
            .unwrap();

        let response = resolver.lookup_ip("www.example.com.").unwrap();
        println!("response records: {:?}", response);

        assert_eq!(response.iter().count(), 2);
        for address in response {
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
