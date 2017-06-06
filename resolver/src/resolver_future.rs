// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Structs for creating and using a ResolverFuture

use trust_dns::client::ClientHandle;
use trust_dns::rr::RecordType;

use config::{ResolverConfig, ResolverOpts};
use pool::NameServerPool;
use lookup_ip::LookupIpFuture;

/// A Recursive Resolver for DNS records.
pub struct ResolverFuture {
    // config: ResolverConfig,
    // options: ResolverOpts,
    pool: NameServerPool,
}

impl ResolverFuture {
    /// Construct a new ResolverFuture with the associated Client.
    pub fn new(config: ResolverConfig, options: ResolverOpts) -> Self {
        let pool = NameServerPool::from_config(&config, &options);
        ResolverFuture { pool }
    }

    /// A basic host name lookup lookup
    pub fn lookup_ip(&mut self, host: &str) -> LookupIpFuture {
        // create the lookup
        LookupIpFuture::lookup(host, RecordType::A, &mut self.pool)
    }
}



#[cfg(test)]
mod tests {
    extern crate tokio_core;

    use futures::Future;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
    use self::tokio_core::reactor::Core;
    use trust_dns::client::ClientFuture;
    use trust_dns::udp::UdpClientStream;

    use super::*;

    #[test]
    fn test_lookup() {
        let mut io_loop = Core::new().unwrap();
        let addr: SocketAddr = ("8.8.8.8", 53)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let (stream, sender) = UdpClientStream::new(addr, io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, io_loop.handle(), None);
        let mut resolver =
            ResolverFuture::new(ResolverConfig::default(), ResolverOpts::default(), client);

        io_loop
            .run(resolver
                     .lookup_ip("www.example.com.")
                     .map(move |mut response| {
                              println!("response records: {:?}", response);

                              let address = response.next().expect("no addresses returned");
                              assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))
                          })
                     .map_err(|e| {
                                  assert!(false, "query failed: {}", e);
                              }))
            .unwrap();
    }
}