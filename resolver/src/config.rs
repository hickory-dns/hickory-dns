// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Configuration for a resolver
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use trust_dns::rr::Name;

/// Configuration for the upstream nameservers to use for resolution
#[derive(Clone, Debug)]
pub struct ResolverConfig {
    // base search domain
    domain: Name,
    // search domains
    search: Vec<Name>,
    // nameservers to use for resolution.
    name_servers: Vec<NameServerConfig>,
}

impl ResolverConfig {
    /// Creates a new empty configuration
    pub fn new() -> Self {
        ResolverConfig {
            // TODO: this should get the hostname and use the basename as the default
            domain: Name::root(),
            search: vec![],
            name_servers: vec![],
        }
    }

    /// Create a ResolverConfig with all parts specified
    ///
    /// # Arguments
    ///
    /// * `domain` - domain of the entity querying results. If the `Name` being lookedup is not an FQDN, then this is the first part appended to attempt a lookup. `ndots` in in the `ResolverOption` does take precidence over this. Default should be `.` aka `Name::root`
    /// * `search` - additional search domains that are attempted if the `Name` is not found in `domain`, defaults to `vec![]`
    /// * `name_servers` - set of name servers to use for lookups, defaults are Google: `8.8.8.8`, `8.8.4.4` and `2001:4860:4860::8888`, `2001:4860:4860::8844`
    pub fn from_parts(
        domain: Name,
        search: Vec<Name>,
        name_servers: Vec<NameServerConfig>,
    ) -> Self {
        ResolverConfig {
            domain,
            search,
            name_servers,
        }
    }

    /// Returns the local domain
    ///
    /// By default any names will be appended to all non-fully-qualified-domain names, and searched for after any ndots rules
    pub fn domain(&self) -> &Name {
        &self.domain
    }

    /// Returns the search domains
    ///
    /// These will be queried after any local domain and then in the order of the set of search domains
    pub fn search(&self) -> &[Name] {
        &self.search
    }

    // TODO: consider allowing options per NameServer... like different timeouts?
    /// Add the configuration for a name server
    pub fn add_name_server(&mut self, name_server: NameServerConfig) {
        self.name_servers.push(name_server);
    }

    /// Returns a reference to the name servers
    pub fn name_servers(&self) -> &[NameServerConfig] {
        &self.name_servers
    }
}

impl Default for ResolverConfig {
    /// Creates a default configuration, using `8.8.8.8`, `8.8.4.4` and `2001:4860:4860::8888`, `2001:4860:4860::8844` (thank you, Google).
    ///
    /// Please see Google's [privacy statement](https://developers.google.com/speed/public-dns/privacy) for important information about what they track, many ISP's track similar information in DNS. To use the the system configuration see: `Resolver::from_system_conf` and `ResolverFuture::from_system_conf`
    fn default() -> Self {
        let domain = Name::root();
        let google_ns1 = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol: Protocol::Udp,
        };

        let google_ns2 = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53),
            protocol: Protocol::Udp,
        };

        let google_v6_ns1 = NameServerConfig {
            socket_addr: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(
                    0x20,
                    0x01,
                    0x48,
                    0x60,
                    0x48,
                    0x60,
                    0x88,
                    0x88,
                )),
                53,
            ),
            protocol: Protocol::Udp,
        };

        let google_v6_ns2 = NameServerConfig {
            socket_addr: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(
                    0x20,
                    0x01,
                    0x48,
                    0x60,
                    0x48,
                    0x60,
                    0x88,
                    0x44,
                )),
                53,
            ),
            protocol: Protocol::Udp,
        };

        ResolverConfig {
            domain,
            search: vec![],
            name_servers: vec![google_ns1, google_ns2, google_v6_ns1, google_v6_ns2],
        }
    }
}

/// The protocol on which a NameServer should be communicated with
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    /// UDP is the traditional DNS port, this is generally the correct choice
    Udp,
    /// TCP can be used for large queries, but not all NameServers support it
    Tcp,
    // TODO: add client certificate for mTLS?
    // Tls,
}

impl Protocol {
    /// Returns true if this is a datagram oriented protocol, e.g. UDP
    pub fn is_datagram(&self) -> bool {
        match *self {
            Protocol::Udp => true,
            Protocol::Tcp => false,
        }
    }

    /// Returns true if this is a stream oriented protocol, e.g. TCP
    pub fn is_stream(&self) -> bool {
        !self.is_datagram()
    }
}

/// Configuration for the NameServer
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameServerConfig {
    /// The address which the DNS NameServer is registered at.
    pub socket_addr: SocketAddr,
    /// The protocol to use when communicating with the NameServer.
    pub protocol: Protocol,
}

/// The lookup ip strategy
#[derive(Clone, Copy)]
pub enum LookupIpStrategy {
    /// Only query for A (Ipv4) records
    Ipv4Only,
    /// Only query for AAAA (Ipv6) recrods
    Ipv6Only,
    /// Query for A and AAAA in parallel (default)
    Ipv4AndIpv6,
    /// Query for Ipv6 if that fails, query for Ipv4
    Ipv6thenIpv4,
    /// Query for Ipv4 if that fails, query for Ipv6
    Ipv4thenIpv6,
}

impl Default for LookupIpStrategy {
    /// Returns Ipv4AndIpv6 as the default.
    fn default() -> Self {
        LookupIpStrategy::Ipv4AndIpv6
    }
}

/// Configuration for the Resolver
#[derive(Clone, Copy)]
#[allow(dead_code)] // TODO: remove after all params are supported
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
    pub(crate) rotate: bool,
    /// Validate the names in the response, not implemented don't really see the point unless you need to support
    ///  badly configured DNS
    pub(crate) check_names: bool,
    /// Enable edns, for larger records
    pub(crate) edns0: bool,
    /// Use DNSSec to validate the request
    pub validate: bool,
    /// The ip_strategy for the Resolver to use when lookup Ipv4 or Ipv6 addresses
    pub ip_strategy: LookupIpStrategy,
    /// Cache size is in number of records (some records can be large)
    pub cache_size: usize,
    /// Check /ect/hosts file before dns requery (only works for unix like OS)
    pub use_hosts_file: bool,
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
            ip_strategy: LookupIpStrategy::default(),
            cache_size: 32,
            use_hosts_file: true,
        }
    }
}
