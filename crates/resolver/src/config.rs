// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Configuration for a resolver
#![allow(clippy::use_self)]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(any(feature = "__https", feature = "__h3"))]
use crate::proto::http::DEFAULT_DNS_QUERY_PATH;
use crate::proto::rr::Name;
use crate::proto::xfer::Protocol;

/// Configuration for the upstream nameservers to use for resolution
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ResolverConfig {
    /// Base search domain
    #[cfg_attr(feature = "serde", serde(default))]
    pub domain: Option<Name>,
    /// Search domains
    #[cfg_attr(feature = "serde", serde(default))]
    pub search: Vec<Name>,
    /// Name servers to use for resolution
    pub name_servers: Vec<NameServerConfig>,
}

impl ResolverConfig {
    /// Create a new `ResolverConfig` from [`ServerGroup`] configuration.
    ///
    /// Connects via UDP and TCP.
    pub fn udp_and_tcp(config: &ServerGroup<'_>) -> Self {
        Self {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: config.udp_and_tcp().collect(),
        }
    }

    /// Create a new `ResolverConfig` from [`ServerGroup`] configuration.
    ///
    /// Only connects via TLS.
    #[cfg(feature = "__tls")]
    pub fn tls(config: &ServerGroup<'_>) -> Self {
        Self {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: config.tls().collect(),
        }
    }

    /// Create a new `ResolverConfig` from [`ServerGroup`] configuration.
    ///
    /// Only connects via HTTPS (HTTP/2).
    #[cfg(feature = "__https")]
    pub fn https(config: &ServerGroup<'_>) -> Self {
        Self {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: config.https().collect(),
        }
    }

    /// Create a new `ResolverConfig` from [`ServerGroup`] configuration.
    ///
    /// Only connects via QUIC.
    #[cfg(feature = "__quic")]
    pub fn quic(config: &ServerGroup<'_>) -> Self {
        Self {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: config.quic().collect(),
        }
    }

    /// Create a new `ResolverConfig` from [`ServerGroup`] configuration.
    ///
    /// Only connects via HTTP/3.
    #[cfg(feature = "__h3")]
    pub fn h3(config: &ServerGroup<'_>) -> Self {
        Self {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: config.h3().collect(),
        }
    }

    /// Create a ResolverConfig with all parts specified
    ///
    /// # Arguments
    ///
    /// * `domain` - domain of the entity querying results. If the `Name` being looked up is not an FQDN, then this is the first part appended to attempt a lookup. `ndots` in the `ResolverOption` does take precedence over this.
    /// * `search` - additional search domains that are attempted if the `Name` is not found in `domain`, defaults to `vec![]`
    /// * `name_servers` - set of name servers to use for lookups
    pub fn from_parts(
        domain: Option<Name>,
        search: Vec<Name>,
        name_servers: Vec<NameServerConfig>,
    ) -> Self {
        Self {
            domain,
            search,
            name_servers,
        }
    }

    /// Take the `domain`, `search`, and `name_servers` from the config.
    pub fn into_parts(self) -> (Option<Name>, Vec<Name>, Vec<NameServerConfig>) {
        (self.domain, self.search, self.name_servers)
    }

    /// Returns the local domain
    ///
    /// By default any names will be appended to all non-fully-qualified-domain names, and searched for after any ndots rules
    pub fn domain(&self) -> Option<&Name> {
        self.domain.as_ref()
    }

    /// Set the domain of the entity querying results.
    pub fn set_domain(&mut self, domain: Name) {
        self.domain = Some(domain.clone());
        self.search = vec![domain];
    }

    /// Returns the search domains
    ///
    /// These will be queried after any local domain and then in the order of the set of search domains
    pub fn search(&self) -> &[Name] {
        &self.search
    }

    /// Add a search domain
    pub fn add_search(&mut self, search: Name) {
        self.search.push(search)
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

/// Configuration for the NameServer
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(deny_unknown_fields)
)]
#[non_exhaustive]
pub struct NameServerConfig {
    /// The address which the DNS NameServer is registered at.
    pub ip: IpAddr,
    /// Whether to trust `NXDOMAIN` responses from upstream nameservers.
    ///
    /// When this is `true`, and an empty `NXDOMAIN` response with an empty answers set is
    /// received, the query will not be retried against other configured name servers.
    ///
    /// (On a response with any other error response code, the query will still be retried
    /// regardless of this configuration setting.)
    ///
    /// Defaults to `true`.
    #[cfg_attr(feature = "serde", serde(default = "default_trust_negative_responses"))]
    pub trust_negative_responses: bool,
    /// Connection protocols configured for this server.
    pub connections: Vec<ConnectionConfig>,
}

impl NameServerConfig {
    /// Constructs a nameserver configuration with a UDP and TCP connections
    pub fn udp_and_tcp(ip: IpAddr) -> Self {
        Self {
            ip,
            trust_negative_responses: true,
            connections: vec![ConnectionConfig::udp(), ConnectionConfig::tcp()],
        }
    }

    /// Constructs a nameserver configuration with a single UDP connection
    pub fn udp(ip: IpAddr) -> Self {
        Self {
            ip,
            trust_negative_responses: true,
            connections: vec![ConnectionConfig::udp()],
        }
    }

    /// Constructs a nameserver configuration with a single TCP connection
    pub fn tcp(ip: IpAddr) -> Self {
        Self {
            ip,
            trust_negative_responses: true,
            connections: vec![ConnectionConfig::tcp()],
        }
    }

    /// Constructs a nameserver configuration with a single TLS connection
    #[cfg(feature = "__tls")]
    pub fn tls(ip: IpAddr, server_name: Arc<str>) -> Self {
        Self {
            ip,
            trust_negative_responses: true,
            connections: vec![ConnectionConfig::tls(server_name)],
        }
    }

    /// Constructs a nameserver configuration with a single HTTP/2 connection
    #[cfg(feature = "__https")]
    pub fn https(ip: IpAddr, server_name: Arc<str>, path: Option<Arc<str>>) -> Self {
        Self {
            ip,
            trust_negative_responses: true,
            connections: vec![ConnectionConfig::https(server_name, path)],
        }
    }

    /// Constructs a nameserver configuration with a single QUIC connection
    #[cfg(feature = "__quic")]
    pub fn quic(ip: IpAddr, server_name: Arc<str>) -> Self {
        Self {
            ip,
            trust_negative_responses: true,
            connections: vec![ConnectionConfig::quic(server_name)],
        }
    }

    /// Constructs a nameserver configuration with a single HTTP/3 connection
    #[cfg(feature = "__h3")]
    pub fn h3(ip: IpAddr, server_name: Arc<str>, path: Option<Arc<str>>) -> Self {
        Self {
            ip,
            trust_negative_responses: true,
            connections: vec![ConnectionConfig::h3(server_name, path)],
        }
    }

    /// Create a new [`NameServerConfig`] from its constituent parts.
    pub fn new(
        ip: IpAddr,
        trust_negative_responses: bool,
        connections: Vec<ConnectionConfig>,
    ) -> Self {
        Self {
            ip,
            trust_negative_responses,
            connections,
        }
    }
}

#[cfg(feature = "serde")]
fn default_trust_negative_responses() -> bool {
    true
}

/// Configuration for a connection to a nameserver
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[non_exhaustive]
pub struct ConnectionConfig {
    /// The remote port to connect to
    pub port: u16,
    /// The protocol to use for the connection
    pub protocol: ProtocolConfig,
    /// The client address (IP and port) to use for connecting to the server
    pub bind_addr: Option<SocketAddr>,
}

impl ConnectionConfig {
    /// Constructs a new ConnectionConfig for UDP
    pub fn udp() -> Self {
        Self::new(ProtocolConfig::Udp)
    }

    /// Constructs a new ConnectionConfig for TCP
    pub fn tcp() -> Self {
        Self::new(ProtocolConfig::Tcp)
    }

    /// Constructs a new ConnectionConfig for TLS
    #[cfg(feature = "__tls")]
    pub fn tls(server_name: Arc<str>) -> Self {
        Self::new(ProtocolConfig::Tls { server_name })
    }

    /// Constructs a new ConnectionConfig for HTTPS (HTTP/2)
    #[cfg(feature = "__https")]
    pub fn https(server_name: Arc<str>, path: Option<Arc<str>>) -> Self {
        Self::new(ProtocolConfig::Https {
            server_name,
            path: path.unwrap_or_else(|| Arc::from(DEFAULT_DNS_QUERY_PATH)),
        })
    }

    /// Constructs a new ConnectionConfig for QUIC
    #[cfg(feature = "__quic")]
    pub fn quic(server_name: Arc<str>) -> Self {
        Self::new(ProtocolConfig::Quic { server_name })
    }

    /// Constructs a new ConnectionConfig for HTTP/3
    #[cfg(feature = "__h3")]
    pub fn h3(server_name: Arc<str>, path: Option<Arc<str>>) -> Self {
        Self::new(ProtocolConfig::H3 {
            server_name,
            path: path.unwrap_or_else(|| Arc::from(DEFAULT_DNS_QUERY_PATH)),
            disable_grease: false,
        })
    }

    /// Constructs a new ConnectionConfig with the specified [`ProtocolConfig`].
    pub fn new(protocol: ProtocolConfig) -> Self {
        Self {
            port: protocol.default_port(),
            protocol,
            bind_addr: None,
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ConnectionConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct OptionalParts {
            #[serde(default)]
            port: Option<u16>,
            protocol: ProtocolConfig,
            #[serde(default)]
            bind_addr: Option<SocketAddr>,
        }

        let parts = OptionalParts::deserialize(deserializer)?;
        Ok(Self {
            port: parts.port.unwrap_or_else(|| parts.protocol.default_port()),
            protocol: parts.protocol,
            bind_addr: parts.bind_addr,
        })
    }
}

/// Protocol configuration
#[allow(missing_docs, missing_copy_implementations)]
#[derive(Clone, Debug, Default, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(deny_unknown_fields, rename_all = "snake_case", tag = "type")
)]
pub enum ProtocolConfig {
    #[default]
    Udp,
    Tcp,
    #[cfg(feature = "__tls")]
    Tls {
        /// The server name to use in the TLS handshake.
        server_name: Arc<str>,
    },
    #[cfg(feature = "__https")]
    Https {
        /// The server name to use in the TLS handshake.
        server_name: Arc<str>,
        /// The path (or endpoint) to use for the DNS query.
        path: Arc<str>,
    },
    #[cfg(feature = "__quic")]
    Quic {
        /// The server name to use in the TLS handshake.
        server_name: Arc<str>,
    },
    #[cfg(feature = "__h3")]
    H3 {
        /// The server name to use in the TLS handshake.
        server_name: Arc<str>,
        /// The path (or endpoint) to use for the DNS query.
        path: Arc<str>,
        /// Whether to disable sending "grease"
        #[cfg_attr(feature = "serde", serde(default))]
        disable_grease: bool,
    },
}

impl ProtocolConfig {
    /// Get the [`Protocol`] for this [`ProtocolConfig`].
    pub fn to_protocol(&self) -> Protocol {
        match self {
            ProtocolConfig::Udp => Protocol::Udp,
            ProtocolConfig::Tcp => Protocol::Tcp,
            #[cfg(feature = "__tls")]
            ProtocolConfig::Tls { .. } => Protocol::Tls,
            #[cfg(feature = "__https")]
            ProtocolConfig::Https { .. } => Protocol::Https,
            #[cfg(feature = "__quic")]
            ProtocolConfig::Quic { .. } => Protocol::Quic,
            #[cfg(feature = "__h3")]
            ProtocolConfig::H3 { .. } => Protocol::H3,
        }
    }

    /// Default port for the protocol.
    pub fn default_port(&self) -> u16 {
        match self {
            ProtocolConfig::Udp => 53,
            ProtocolConfig::Tcp => 53,
            #[cfg(feature = "__tls")]
            ProtocolConfig::Tls { .. } => 853,
            #[cfg(feature = "__https")]
            ProtocolConfig::Https { .. } => 443,
            #[cfg(feature = "__quic")]
            ProtocolConfig::Quic { .. } => 853,
            #[cfg(feature = "__h3")]
            ProtocolConfig::H3 { .. } => 443,
        }
    }
}

/// Configuration for the Resolver
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(default, deny_unknown_fields)
)]
#[allow(missing_copy_implementations)]
#[non_exhaustive]
pub struct ResolverOpts {
    /// Sets the number of dots that must appear (unless it's a final dot representing the root)
    ///  before a query is assumed to include the TLD. The default is one, which means that `www`
    ///  would never be assumed to be a TLD, and would always be appended to either the search
    #[cfg_attr(feature = "serde", serde(default = "default_ndots"))]
    pub ndots: usize,
    /// Specify the timeout for a request. Defaults to 5 seconds
    #[cfg_attr(
        feature = "serde",
        serde(default = "default_timeout", with = "duration")
    )]
    pub timeout: Duration,
    /// Number of retries after lookup failure before giving up. Defaults to 2
    #[cfg_attr(feature = "serde", serde(default = "default_attempts"))]
    pub attempts: usize,
    /// Enable edns, for larger records
    pub edns0: bool,
    /// Use DNSSEC to validate the request
    #[cfg(feature = "__dnssec")]
    pub validate: bool,
    /// The strategy for the Resolver to use when looking up host IP addresses
    pub ip_strategy: LookupIpStrategy,
    /// Cache size is in number of responses (some responses can be large)
    #[cfg_attr(feature = "serde", serde(default = "default_cache_size"))]
    pub cache_size: u64,
    /// Check /etc/hosts file before dns requery (only works for unix like OS)
    pub use_hosts_file: ResolveHosts,
    /// Optional minimum TTL for positive responses.
    ///
    /// If this is set, any positive responses with a TTL lower than this value will have a TTL of
    /// `positive_min_ttl` instead. Otherwise, this will default to 0 seconds.
    #[cfg_attr(feature = "serde", serde(with = "duration_opt"))]
    pub positive_min_ttl: Option<Duration>,
    /// Optional minimum TTL for negative (`NXDOMAIN`) responses.
    ///
    /// If this is set, any negative responses with a TTL lower than this value will have a TTL of
    /// `negative_min_ttl` instead. Otherwise, this will default to 0 seconds.
    #[cfg_attr(feature = "serde", serde(with = "duration_opt"))]
    pub negative_min_ttl: Option<Duration>,
    /// Optional maximum TTL for positive responses.
    ///
    /// If this is set, any positive responses with a TTL higher than this value will have a TTL of
    /// `positive_max_ttl` instead. Otherwise, this will default to [`MAX_TTL`](crate::MAX_TTL) seconds.
    #[cfg_attr(feature = "serde", serde(with = "duration_opt"))]
    pub positive_max_ttl: Option<Duration>,
    /// Optional maximum TTL for negative (`NXDOMAIN`) responses.
    ///
    /// If this is set, any negative responses with a TTL higher than this value will have a TTL of
    /// `negative_max_ttl` instead. Otherwise, this will default to [`MAX_TTL`](crate::MAX_TTL) seconds.
    #[cfg_attr(feature = "serde", serde(with = "duration_opt"))]
    pub negative_max_ttl: Option<Duration>,
    /// Number of concurrent requests per query
    ///
    /// Where more than one nameserver is configured, this configures the resolver to send queries
    /// to a number of servers in parallel. Defaults to 2; 0 or 1 will execute requests serially.
    #[cfg_attr(feature = "serde", serde(default = "default_num_concurrent_reqs"))]
    pub num_concurrent_reqs: usize,
    /// Preserve all intermediate records in the lookup response, such as CNAME records
    #[cfg_attr(feature = "serde", serde(default = "default_preserve_intermediates"))]
    pub preserve_intermediates: bool,
    /// Try queries over TCP if they fail over UDP.
    pub try_tcp_on_error: bool,
    /// The server ordering strategy that the resolver should use.
    pub server_ordering_strategy: ServerOrderingStrategy,
    /// Request upstream recursive resolvers to not perform any recursion.
    ///
    /// This is true by default, disabling this is useful for requesting single records, but may prevent successful resolution.
    #[cfg_attr(feature = "serde", serde(default = "default_recursion_desired"))]
    pub recursion_desired: bool,
    /// Local UDP ports to avoid when making outgoing queries
    pub avoid_local_udp_ports: Arc<HashSet<u16>>,
    /// Request UDP bind ephemeral ports directly from the OS
    ///
    /// Boolean parameter to specify whether to use the operating system's standard UDP port
    /// selection logic instead of Hickory's logic to securely select a random source port. We do
    /// not recommend using this option unless absolutely necessary, as the operating system may
    /// select ephemeral ports from a smaller range than Hickory, which can make response poisoning
    /// attacks easier to conduct. Some operating systems (notably, Windows) might display a
    /// user-prompt to allow a Hickory-specified port to be used, and setting this option will
    /// prevent those prompts from being displayed. If os_port_selection is true, avoid_local_udp_ports
    /// will be ignored.
    pub os_port_selection: bool,
    /// Enable case randomization.
    ///
    /// Randomize the case of letters in query names, and require that responses preserve the case
    /// of the query name, in order to mitigate spoofing attacks. This is only applied over UDP.
    ///
    /// This implements the mechanism described in
    /// [draft-vixie-dnsext-dns0x20-00](https://datatracker.ietf.org/doc/html/draft-vixie-dnsext-dns0x20-00).
    pub case_randomization: bool,
    /// Path to a DNSSEC trust anchor file.
    ///
    /// If this is provided, `validate` will automatically be set to `true`, enabling DNSSEC validation.
    pub trust_anchor: Option<PathBuf>,
}

impl Default for ResolverOpts {
    /// Default values for the Resolver configuration.
    ///
    /// This follows the resolv.conf defaults as defined in the [Linux man pages](https://man7.org/linux/man-pages/man5/resolv.conf.5.html)
    fn default() -> Self {
        Self {
            ndots: default_ndots(),
            timeout: default_timeout(),
            attempts: default_attempts(),
            edns0: false,
            #[cfg(feature = "__dnssec")]
            validate: false,
            ip_strategy: LookupIpStrategy::default(),
            cache_size: default_cache_size(),
            use_hosts_file: ResolveHosts::default(),
            positive_min_ttl: None,
            negative_min_ttl: None,
            positive_max_ttl: None,
            negative_max_ttl: None,
            num_concurrent_reqs: default_num_concurrent_reqs(),

            // Defaults to `true` to match the behavior of dig and nslookup.
            preserve_intermediates: default_preserve_intermediates(),

            try_tcp_on_error: false,
            server_ordering_strategy: ServerOrderingStrategy::default(),
            recursion_desired: default_recursion_desired(),
            avoid_local_udp_ports: Arc::default(),
            os_port_selection: false,
            case_randomization: false,
            trust_anchor: None,
        }
    }
}

fn default_ndots() -> usize {
    1
}

fn default_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_attempts() -> usize {
    2
}

fn default_cache_size() -> u64 {
    32
}

fn default_num_concurrent_reqs() -> usize {
    2
}

fn default_preserve_intermediates() -> bool {
    true
}

fn default_recursion_desired() -> bool {
    true
}

/// The lookup ip strategy
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LookupIpStrategy {
    /// Only query for A (Ipv4) records
    Ipv4Only,
    /// Only query for AAAA (Ipv6) records
    Ipv6Only,
    /// Query for A and AAAA in parallel
    #[default]
    Ipv4AndIpv6,
    /// Query for Ipv6 if that fails, query for Ipv4
    Ipv6thenIpv4,
    /// Query for Ipv4 if that fails, query for Ipv6 (default)
    Ipv4thenIpv6,
}

/// The strategy for establishing the query order of name servers in a pool.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum ServerOrderingStrategy {
    /// Servers are ordered based on collected query statistics. The ordering
    /// may vary over time.
    #[default]
    QueryStatistics,
    /// The order provided to the resolver is used. The ordering does not vary
    /// over time.
    UserProvidedOrder,
    /// The order of servers is rotated in a round-robin fashion. This is useful for
    /// load balancing and ensuring that all servers are used evenly.
    RoundRobin,
}

/// Whether the system hosts file should be respected by the resolver.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ResolveHosts {
    /// Always attempt to look up IP addresses from the system hosts file.
    /// If the hostname cannot be found, query the DNS.
    Always,
    /// The DNS will always be queried.
    Never,
    /// Use local resolver configurations only when this resolver is not used in
    /// a DNS forwarder. This is the default.
    #[default]
    Auto,
}

/// Google Public DNS configuration.
///
/// Please see Google's [privacy statement](https://developers.google.com/speed/public-dns/privacy)
/// for important information about what they track, many ISP's track similar information in DNS.
/// To use the system configuration see: `Resolver::from_system_conf`.
pub const GOOGLE: ServerGroup<'static> = ServerGroup {
    ips: &[
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)),
    ],
    server_name: "dns.google",
    path: "/dns-query",
};

/// Cloudflare's 1.1.1.1 DNS service configuration.
///
/// See <https://www.cloudflare.com/dns/> for more information.
pub const CLOUDFLARE: ServerGroup<'static> = ServerGroup {
    ips: &[
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
    ],
    server_name: "cloudflare-dns.com",
    path: "/dns-query",
};

/// The Quad9 DNS service configuration.
///
/// See <https://www.quad9.net/faq/> for more information.
pub const QUAD9: ServerGroup<'static> = ServerGroup {
    ips: &[
        IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
        IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)),
        IpAddr::V6(Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe)),
        IpAddr::V6(Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0x00fe, 0x0009)),
    ],
    server_name: "dns.quad9.net",
    path: "/dns-query",
};

/// A group of DNS servers.
#[derive(Clone, Copy, Debug)]
pub struct ServerGroup<'a> {
    /// IP addresses of the DNS servers in this group.
    pub ips: &'a [IpAddr],
    /// The TLS server name to use for servers.
    pub server_name: &'a str,
    /// The query path to use for HTTP queries.
    pub path: &'a str,
}

impl<'a> ServerGroup<'a> {
    /// Create an iterator with `NameServerConfig` for each IP address in the group.
    pub fn udp_and_tcp(&self) -> impl Iterator<Item = NameServerConfig> + 'a {
        self.ips.iter().map(|&ip| {
            NameServerConfig::new(
                ip,
                true,
                vec![ConnectionConfig::udp(), ConnectionConfig::tcp()],
            )
        })
    }

    /// Create an iterator with `NameServerConfig` for each IP address in the group.
    pub fn udp(&self) -> impl Iterator<Item = NameServerConfig> + 'a {
        self.ips
            .iter()
            .map(|&ip| NameServerConfig::new(ip, true, vec![ConnectionConfig::udp()]))
    }

    /// Create an iterator with `NameServerConfig` for each IP address in the group.
    pub fn tcp(&self) -> impl Iterator<Item = NameServerConfig> + 'a {
        self.ips
            .iter()
            .map(|&ip| NameServerConfig::new(ip, true, vec![ConnectionConfig::tcp()]))
    }

    /// Create an iterator with `NameServerConfig` for each IP address in the group.
    #[cfg(feature = "__tls")]
    pub fn tls(&self) -> impl Iterator<Item = NameServerConfig> + 'a {
        let this = *self;
        self.ips.iter().map(move |&ip| {
            NameServerConfig::new(
                ip,
                true,
                vec![ConnectionConfig::tls(Arc::from(this.server_name))],
            )
        })
    }

    /// Create an iterator with `NameServerConfig` for each IP address in the group.
    #[cfg(feature = "__https")]
    pub fn https(&self) -> impl Iterator<Item = NameServerConfig> + 'a {
        let this = *self;
        self.ips.iter().map(move |&ip| {
            NameServerConfig::new(
                ip,
                true,
                vec![ConnectionConfig::https(
                    Arc::from(this.server_name),
                    Some(Arc::from(this.path)),
                )],
            )
        })
    }

    /// Create an iterator with `NameServerConfig` for each IP address in the group.
    #[cfg(feature = "__quic")]
    pub fn quic(&self) -> impl Iterator<Item = NameServerConfig> + 'a {
        let this = *self;
        self.ips.iter().map(move |&ip| {
            NameServerConfig::new(
                ip,
                true,
                vec![ConnectionConfig::quic(Arc::from(this.server_name))],
            )
        })
    }

    /// Create an iterator with `NameServerConfig` for each IP address in the group.
    #[cfg(feature = "__h3")]
    pub fn h3(&self) -> impl Iterator<Item = NameServerConfig> + 'a {
        let this = *self;
        self.ips.iter().map(move |&ip| {
            NameServerConfig::new(
                ip,
                true,
                vec![ConnectionConfig::h3(
                    Arc::from(this.server_name),
                    Some(Arc::from(this.path)),
                )],
            )
        })
    }
}

#[cfg(feature = "serde")]
pub(crate) mod duration {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// This is an alternate serialization function for a [`Duration`] that emits a single number,
    /// representing the number of seconds, instead of a struct with `secs` and `nanos` fields.
    pub(super) fn serialize<S: Serializer>(
        duration: &Duration,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        duration.as_secs().serialize(serializer)
    }

    /// This is an alternate deserialization function for a [`Duration`] that expects a single number,
    /// representing the number of seconds, instead of a struct with `secs` and `nanos` fields.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Duration, D::Error> {
        Ok(Duration::from_secs(u64::deserialize(deserializer)?))
    }
}

#[cfg(feature = "serde")]
pub(crate) mod duration_opt {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// This is an alternate serialization function for an optional [`Duration`] that emits a single
    /// number, representing the number of seconds, instead of a struct with `secs` and `nanos` fields.
    pub(super) fn serialize<S: Serializer>(
        duration: &Option<Duration>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        struct Wrapper<'a>(&'a Duration);

        impl Serialize for Wrapper<'_> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                super::duration::serialize(self.0, serializer)
            }
        }

        match duration {
            Some(duration) => serializer.serialize_some(&Wrapper(duration)),
            None => serializer.serialize_none(),
        }
    }

    /// This is an alternate deserialization function for an optional [`Duration`] that expects a single
    /// number, representing the number of seconds, instead of a struct with `secs` and `nanos` fields.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Duration>, D::Error> {
        Ok(Option::<u64>::deserialize(deserializer)?.map(Duration::from_secs))
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[cfg(feature = "serde")]
    #[test]
    fn default_opts() {
        let code = ResolverOpts::default();
        let json = serde_json::from_str::<ResolverOpts>("{}").unwrap();
        assert_eq!(code.ndots, json.ndots);
        assert_eq!(code.timeout, json.timeout);
        assert_eq!(code.attempts, json.attempts);
        assert_eq!(code.edns0, json.edns0);
        #[cfg(feature = "__dnssec")]
        assert_eq!(code.validate, json.validate);
        assert_eq!(code.ip_strategy, json.ip_strategy);
        assert_eq!(code.cache_size, json.cache_size);
        assert_eq!(code.use_hosts_file, json.use_hosts_file);
        assert_eq!(code.positive_min_ttl, json.positive_min_ttl);
        assert_eq!(code.negative_min_ttl, json.negative_min_ttl);
        assert_eq!(code.positive_max_ttl, json.positive_max_ttl);
        assert_eq!(code.negative_max_ttl, json.negative_max_ttl);
        assert_eq!(code.num_concurrent_reqs, json.num_concurrent_reqs);
        assert_eq!(code.preserve_intermediates, json.preserve_intermediates);
        assert_eq!(code.try_tcp_on_error, json.try_tcp_on_error);
        assert_eq!(code.recursion_desired, json.recursion_desired);
        assert_eq!(code.server_ordering_strategy, json.server_ordering_strategy);
        assert_eq!(code.avoid_local_udp_ports, json.avoid_local_udp_ports);
        assert_eq!(code.os_port_selection, json.os_port_selection);
        assert_eq!(code.case_randomization, json.case_randomization);
        assert_eq!(code.trust_anchor, json.trust_anchor);
    }
}
