// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Configuration for a resolver
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Configuration for the upstream nameservers to use for resolution
#[derive(Clone, Debug)]
pub struct ResolverConfig {
    name_servers: Vec<NameServerConfig>,
}

impl ResolverConfig {
    pub fn add_name_server(&mut self, name_server: NameServerConfig) {
        self.name_servers.push(name_server);
    }

    pub fn name_servers(&self) -> &[NameServerConfig] {
        &self.name_servers
    }
}

impl Default for ResolverConfig {
    fn default() -> Self {
        let ns = NameServerConfig
 {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol: Protocol::Udp,
        };
        ResolverConfig { name_servers: vec![ns] }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Protocol {
    Udp,
    Tcp,
    // TODO: add client certificate for mTLS
    Tls,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameServerConfig {
    socket_addr: SocketAddr,
    protocol: Protocol,
}

/// Configuration for the Resolver
#[derive(Clone, Copy)]
pub struct ResolverOpts {
    /// Sets the number of dots that must appear (unless it's a final dot representing the root)
    ///  that must appear before a query is assumted to include the TLD. The default is one, which
    ///  means that `www` would never be assumed to be a TLD, and would always be appended to either
    ///  the search
    pub ndots: usize,
    /// Specify the timeout for a request. Defaults to 5 seconds
    pub timeout: Duration,
    /// Number of attempts before giving up. Defaults to 2
    pub attempts: usize,
    /// Rotate through the resource records in the response (if there is more than one for a given name)
    pub rotate: bool,
    /// Validate the names in the response
    pub check_names: bool,
    /// Enable edns, for larger records
    pub edns0: bool,
    /// Use DNSSec to validate the request
    pub validate: bool,
}

impl Default for ResolverOpts {
    /// Default values for the Reolver configuration.
    ///
    /// This follows the resolv.conf defaults as defined in the [Linux man pages](http://man7.org/linux/man-pages/man5/resolv.conf.5.html)
    fn default() -> Self {
        ResolverOpts {
            ndots: 1,
            timeout: Duration::from_secs(5),
            attempts: 2,
            rotate: false,
            check_names: true,
            edns0: false,
            validate: false,
        }
    }
}