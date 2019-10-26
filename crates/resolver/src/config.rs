// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Configuration for a resolver
#[cfg(feature = "dns-over-rustls")]
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::{Deref, DerefMut};
use std::time::Duration;

#[cfg(feature = "dns-over-rustls")]
use std::sync::Arc;

use proto::rr::Name;
#[cfg(feature = "dns-over-rustls")]
use rustls::ClientConfig;

#[cfg(all(feature = "serde-config", feature = "dns-over-rustls"))]
use serde::{
    de::{Deserialize as DeserializeT, Deserializer},
    ser::{Serialize as SerializeT, Serializer},
};

/// Configuration for the upstream nameservers to use for resolution
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde-config", derive(Serialize, Deserialize))]
pub struct ResolverConfig {
    // base search domain
    domain: Option<Name>,
    // search domains
    search: Vec<Name>,
    // nameservers to use for resolution.
    name_servers: NameServerConfigGroup,
}

impl ResolverConfig {
    /// Creates a new empty configuration
    pub fn new() -> Self {
        ResolverConfig {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: NameServerConfigGroup::new(),
        }
    }

    /// Creates a default configuration, using `8.8.8.8`, `8.8.4.4` and `2001:4860:4860::8888`, `2001:4860:4860::8844` (thank you, Google).
    ///
    /// Please see Google's [privacy statement](https://developers.google.com/speed/public-dns/privacy) for important information about what they track, many ISP's track similar information in DNS. To use the system configuration see: `Resolver::from_system_conf` and `AsyncResolver::from_system_conf`
    ///
    /// NameServerConfigGroups can be combined to use a set of different providers, see `NameServerConfigGroup` and `ResolverConfig::from_parts`
    pub fn google() -> Self {
        ResolverConfig {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: NameServerConfigGroup::google(),
        }
    }

    /// Creates a default configuration, using `1.1.1.1`, `1.0.0.1` and `2606:4700:4700::1111`, `2606:4700:4700::1001` (thank you, Cloudflare).
    ///
    /// Please see: https://www.cloudflare.com/dns/
    ///
    /// NameServerConfigGroups can be combined to use a set of different providers, see `NameServerConfigGroup` and `ResolverConfig::from_parts`
    pub fn cloudflare() -> Self {
        ResolverConfig {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: NameServerConfigGroup::cloudflare(),
        }
    }

    /// Creates a configuration, using `1.1.1.1`, `1.0.0.1` and `2606:4700:4700::1111`, `2606:4700:4700::1001` (thank you, Cloudflare). This limits the registered connections to just TLS lookups
    ///
    /// Please see: https://www.cloudflare.com/dns/
    ///
    /// NameServerConfigGroups can be combined to use a set of different providers, see `NameServerConfigGroup` and `ResolverConfig::from_parts`
    #[cfg(feature = "dns-over-tls")]
    pub fn cloudflare_tls() -> Self {
        ResolverConfig {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: NameServerConfigGroup::cloudflare_tls(),
        }
    }

    /// Creates a configuration, using `1.1.1.1`, `1.0.0.1` and `2606:4700:4700::1111`, `2606:4700:4700::1001` (thank you, Cloudflare). This limits the registered connections to just HTTPS lookups
    ///
    /// Please see: https://www.cloudflare.com/dns/
    ///
    /// NameServerConfigGroups can be combined to use a set of different providers, see `NameServerConfigGroup` and `ResolverConfig::from_parts`
    #[cfg(feature = "dns-over-https")]
    pub fn cloudflare_https() -> Self {
        ResolverConfig {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: NameServerConfigGroup::cloudflare_https(),
        }
    }

    /// Creates a configuration, using `9.9.9.9` and `2620:fe::fe`, the "secure" variants of the quad9 settings (thank you, Quad9).
    ///
    /// Please see: https://www.quad9.net/faq/
    ///
    /// NameServerConfigGroups can be combined to use a set of different providers, see `NameServerConfigGroup` and `ResolverConfig::from_parts`
    pub fn quad9() -> Self {
        ResolverConfig {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: NameServerConfigGroup::quad9(),
        }
    }

    /// Creates a configuration, using `9.9.9.9` and `2620:fe::fe`, the "secure" variants of the quad9 settings. This limits the registered connections to just TLS lookups
    ///
    /// Please see: https://www.quad9.net/faq/
    ///
    /// NameServerConfigGroups can be combined to use a set of different providers, see `NameServerConfigGroup` and `ResolverConfig::from_parts`
    #[cfg(feature = "dns-over-tls")]
    pub fn quad9_tls() -> Self {
        ResolverConfig {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: NameServerConfigGroup::quad9_tls(),
        }
    }

    /// Create a ResolverConfig with all parts specified
    ///
    /// # Arguments
    ///
    /// * `domain` - domain of the entity querying results. If the `Name` being looked up is not an FQDN, then this is the first part appended to attempt a lookup. `ndots` in the `ResolverOption` does take precedence over this.
    /// * `search` - additional search domains that are attempted if the `Name` is not found in `domain`, defaults to `vec![]`
    /// * `name_servers` - set of name servers to use for lookups, defaults are Google: `8.8.8.8`, `8.8.4.4` and `2001:4860:4860::8888`, `2001:4860:4860::8844`
    pub fn from_parts<G: Into<NameServerConfigGroup>>(
        domain: Option<Name>,
        search: Vec<Name>,
        name_servers: G,
    ) -> Self {
        ResolverConfig {
            domain,
            search,
            name_servers: name_servers.into(),
        }
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

    /// return the associated TlsClientConfig
    #[cfg(feature = "dns-over-rustls")]
    pub fn client_config(&self) -> &Option<TlsClientConfig> {
        &self.name_servers.1
    }

    /// adds the [`rustls::ClientConf`] for every configured NameServer
    /// of the Resolver.
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// use rustls::{ClientConfig, ProtocolVersion, RootCertStore};
    /// use trust_dns_resolver::config::ResolverConfig;
    /// use webpki_roots;
    ///
    /// let mut root_store = RootCertStore::empty();
    /// root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    /// let versions = vec![ProtocolVersion::TLSv1_2];
    ///
    /// let mut client_config = ClientConfig::new();
    /// client_config.root_store = root_store;
    /// client_config.versions = versions;
    ///
    /// let mut resolver_config = ResolverConfig::quad9_tls();
    /// resolver_config.set_tls_client_config(Arc::new(client_config));
    /// ```
    #[cfg(feature = "dns-over-rustls")]
    pub fn set_tls_client_config(&mut self, client_config: Arc<ClientConfig>) {
        self.name_servers = self.name_servers.clone().with_client_config(client_config);
    }
}

impl Default for ResolverConfig {
    /// Creates a default configuration, using `8.8.8.8`, `8.8.4.4` and `2001:4860:4860::8888`, `2001:4860:4860::8844` (thank you, Google).
    ///
    /// Please see Google's [privacy statement](https://developers.google.com/speed/public-dns/privacy) for important information about what they track, many ISP's track similar information in DNS. To use the system configuration see: `Resolver::from_system_conf` and `AsyncResolver::from_system_conf`
    fn default() -> Self {
        ResolverConfig::google()
    }
}

/// The protocol on which a NameServer should be communicated with
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde-config", derive(Serialize, Deserialize))]
pub enum Protocol {
    /// UDP is the traditional DNS port, this is generally the correct choice
    Udp,
    /// TCP can be used for large queries, but not all NameServers support it
    Tcp,
    /// Tls for DNS over TLS
    #[cfg(feature = "dns-over-tls")]
    Tls,
    /// Https for DNS over HTTPS
    #[cfg(feature = "dns-over-https")]
    Https,
    /// mDNS protocol for performing multicast lookups
    #[cfg(feature = "mdns")]
    Mdns,
}

impl Protocol {
    /// Returns true if this is a datagram oriented protocol, e.g. UDP
    pub fn is_datagram(self) -> bool {
        match self {
            Protocol::Udp => true,
            Protocol::Tcp => false,
            #[cfg(feature = "dns-over-tls")]
            Protocol::Tls => false,
            #[cfg(feature = "dns-over-https")]
            Protocol::Https => false,
            #[cfg(feature = "mdns")]
            Protocol::Mdns => true,
        }
    }

    /// Returns true if this is a stream oriented protocol, e.g. TCP
    pub fn is_stream(self) -> bool {
        !self.is_datagram()
    }

    /// Is this an encrypted protocol, i.e. TLS or HTTPS
    pub fn is_encrypted(self) -> bool {
        match self {
            Protocol::Udp => false,
            Protocol::Tcp => false,
            #[cfg(feature = "dns-over-tls")]
            Protocol::Tls => true,
            #[cfg(feature = "dns-over-https")]
            Protocol::Https => true,
            #[cfg(feature = "mdns")]
            Protocol::Mdns => false,
        }
    }
}

#[cfg(feature = "dns-over-rustls")]
#[derive(Clone)]
/// a compatibility wrapper around rustls
/// ClientConfig
pub struct TlsClientConfig(pub Arc<ClientConfig>);

#[cfg(feature = "dns-over-rustls")]
impl std::cmp::PartialEq for TlsClientConfig {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

#[cfg(feature = "dns-over-rustls")]
impl std::cmp::Eq for TlsClientConfig {}

#[cfg(feature = "dns-over-rustls")]
impl std::fmt::Debug for TlsClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rustls client config")
    }
}

/// Configuration for the NameServer
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde-config", derive(Serialize, Deserialize))]
pub struct NameServerConfig {
    /// The address which the DNS NameServer is registered at.
    pub socket_addr: SocketAddr,
    /// The protocol to use when communicating with the NameServer.
    pub protocol: Protocol,
    /// SPKI name, only relevant for TLS connections
    pub tls_dns_name: Option<String>,
    #[cfg(feature = "dns-over-rustls")]
    #[cfg_attr(feature = "serde-config", serde(skip))]
    /// optional configuration for the tls client
    pub tls_config: Option<TlsClientConfig>,
}

/// A set of name_servers to associate with a [`ResolverConfig`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    all(feature = "serde-config", not(feature = "dns-over-rustls")),
    derive(Serialize, Deserialize)
)]
pub struct NameServerConfigGroup(
    Vec<NameServerConfig>,
    #[cfg(feature = "dns-over-rustls")] Option<TlsClientConfig>,
);

#[cfg(all(feature = "serde-config", feature = "dns-over-rustls"))]
impl SerializeT for NameServerConfigGroup {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[cfg(all(feature = "serde-config", feature = "dns-over-rustls"))]
impl<'de> DeserializeT<'de> for NameServerConfigGroup {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::deserialize(deserializer).map(|nameservers| Self(nameservers, None))
    }
}

impl NameServerConfigGroup {
    /// Creates a new `NameServerConfigGroup` with a default size of 2
    pub fn new() -> Self {
        // this might be a nice opportunity for SmallVec
        //   most name_server configs will be 2.
        Self::with_capacity(2)
    }

    /// Creates a new `NameServiceConfigGroup` with the specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        NameServerConfigGroup(
            Vec::with_capacity(capacity),
            #[cfg(feature = "dns-over-rustls")]
            None,
        )
    }

    /// Configure a NameServer address and port
    ///
    /// This will create UDP and TCP connections, using the same port.
    pub fn from_ips_clear(ips: &[IpAddr], port: u16) -> Self {
        let mut name_servers = Self::with_capacity(ips.len());

        for ip in ips {
            let udp = NameServerConfig {
                socket_addr: SocketAddr::new(*ip, port),
                protocol: Protocol::Udp,
                tls_dns_name: None,
                #[cfg(feature = "dns-over-rustls")]
                tls_config: None,
            };
            let tcp = NameServerConfig {
                socket_addr: SocketAddr::new(*ip, port),
                protocol: Protocol::Tcp,
                tls_dns_name: None,
                #[cfg(feature = "dns-over-rustls")]
                tls_config: None,
            };

            name_servers.push(udp);
            name_servers.push(tcp);
        }

        name_servers
    }

    #[cfg(any(feature = "dns-over-tls", feature = "dns-over-https"))]
    fn from_ips_encrypted(
        ips: &[IpAddr],
        port: u16,
        tls_dns_name: String,
        protocol: Protocol,
    ) -> Self {
        assert!(protocol.is_encrypted());

        let mut name_servers = Self::with_capacity(ips.len());

        for ip in ips {
            let config = NameServerConfig {
                socket_addr: SocketAddr::new(*ip, port),
                protocol,
                tls_dns_name: Some(tls_dns_name.clone()),
                #[cfg(feature = "dns-over-rustls")]
                tls_config: None,
            };

            name_servers.push(config);
        }

        name_servers
    }

    /// Configure a NameServer address and port for DNS-over-TLS
    ///
    /// This will create a TLS connections.
    #[cfg(feature = "dns-over-tls")]
    pub fn from_ips_tls(ips: &[IpAddr], port: u16, tls_dns_name: String) -> Self {
        Self::from_ips_encrypted(ips, port, tls_dns_name, Protocol::Tls)
    }

    /// Configure a NameServer address and port for DNS-over-HTTPS
    ///
    /// This will create a HTTPS connections.
    #[cfg(feature = "dns-over-https")]
    pub fn from_ips_https(ips: &[IpAddr], port: u16, tls_dns_name: String) -> Self {
        Self::from_ips_encrypted(ips, port, tls_dns_name, Protocol::Https)
    }

    /// Creates a default configuration, using `8.8.8.8`, `8.8.4.4` and `2001:4860:4860::8888`, `2001:4860:4860::8844` (thank you, Google).
    ///
    /// Please see Google's [privacy statement](https://developers.google.com/speed/public-dns/privacy) for important information about what they track, many ISP's track similar information in DNS. To use the system configuration see: `Resolver::from_system_conf` and `AsyncResolver::from_system_conf`
    pub fn google() -> Self {
        Self::from_ips_clear(
            &[
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)),
            ],
            53,
        )
    }

    /// Creates a default configuration, using `1.1.1.1`, `1.0.0.1` and `2606:4700:4700::1111`, `2606:4700:4700::1001` (thank you, Cloudflare).
    ///
    /// Please see: https://www.cloudflare.com/dns/
    pub fn cloudflare() -> Self {
        Self::from_ips_clear(
            &[
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
            ],
            53,
        )
    }

    /// Creates a configuration, using `1.1.1.1`, `1.0.0.1` and `2606:4700:4700::1111`, `2606:4700:4700::1001` (thank you, Cloudflare). This limits the registered connections to just TLS lookups
    ///
    /// Please see: https://www.cloudflare.com/dns/
    #[cfg(feature = "dns-over-tls")]
    pub fn cloudflare_tls() -> Self {
        Self::from_ips_tls(
            &[
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
            ],
            853,
            "cloudflare-dns.com".to_string(),
        )
    }

    /// Creates a configuration, using `1.1.1.1`, `1.0.0.1` and `2606:4700:4700::1111`, `2606:4700:4700::1001` (thank you, Cloudflare). This limits the registered connections to just TLS lookups
    ///
    /// Please see: https://www.cloudflare.com/dns/
    #[cfg(feature = "dns-over-https")]
    pub fn cloudflare_https() -> Self {
        Self::from_ips_https(
            &[
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
            ],
            443,
            "cloudflare-dns.com".to_string(),
        )
    }

    /// Creates a configuration, using `9.9.9.9` and `2620:fe::fe`, the "secure" variants of the quad9 settings (thank you, Quad9).
    ///
    /// Please see: https://www.quad9.net/faq/
    pub fn quad9() -> Self {
        Self::from_ips_clear(
            &[
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                IpAddr::V6(Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe)),
            ],
            53,
        )
    }

    /// Creates a configuration, using `9.9.9.9` and `2620:fe::fe`, the "secure" variants of the quad9 settings. This limits the registered connections to just TLS lookups
    ///
    /// Please see: https://www.quad9.net/faq/
    #[cfg(feature = "dns-over-tls")]
    pub fn quad9_tls() -> Self {
        Self::from_ips_tls(
            &[
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                IpAddr::V6(Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe)),
            ],
            853,
            "dns.quad9.net".to_string(),
        )
    }

    /// Merges this set of [`NameServerConfig`]s with the other
    ///
    /// ```
    /// use std::net::{SocketAddr, Ipv4Addr};
    /// use trust_dns_resolver::config::NameServerConfigGroup;
    ///
    /// let mut group = NameServerConfigGroup::google();
    /// group.merge(NameServerConfigGroup::cloudflare());
    /// group.merge(NameServerConfigGroup::quad9());
    ///
    /// assert!(group.iter().any(|c| c.socket_addr == SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 53)));
    /// assert!(group.iter().any(|c| c.socket_addr == SocketAddr::new(Ipv4Addr::new(1, 1, 1, 1).into(), 53)));
    /// assert!(group.iter().any(|c| c.socket_addr == SocketAddr::new(Ipv4Addr::new(9, 9, 9, 9).into(), 53)));
    /// ```
    pub fn merge(&mut self, mut other: Self) {
        #[cfg(not(feature = "dns-over-rustls"))]
        {
            self.append(&mut other);
        }
        #[cfg(feature = "dns-over-rustls")]
        {
            self.0.append(&mut other);
        }
    }

    #[cfg(feature = "dns-over-rustls")]
    /// add a [`rustls::ClientConfig`]
    pub fn with_client_config(self, client_config: Arc<ClientConfig>) -> Self {
        Self(self.0, Some(TlsClientConfig(client_config)))
    }
}

impl Default for NameServerConfigGroup {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for NameServerConfigGroup {
    type Target = Vec<NameServerConfig>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for NameServerConfigGroup {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<NameServerConfig>> for NameServerConfigGroup {
    fn from(configs: Vec<NameServerConfig>) -> Self {
        #[cfg(not(feature = "dns-over-rustls"))]
        {
            NameServerConfigGroup(configs)
        }
        #[cfg(feature = "dns-over-rustls")]
        {
            NameServerConfigGroup(configs, None)
        }
    }
}

/// The lookup ip strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde-config", derive(Serialize, Deserialize))]
pub enum LookupIpStrategy {
    /// Only query for A (Ipv4) records
    Ipv4Only,
    /// Only query for AAAA (Ipv6) records
    Ipv6Only,
    /// Query for A and AAAA in parallel
    Ipv4AndIpv6,
    /// Query for Ipv6 if that fails, query for Ipv4
    Ipv6thenIpv4,
    /// Query for Ipv4 if that fails, query for Ipv6 (default)
    Ipv4thenIpv6,
}

impl Default for LookupIpStrategy {
    /// Returns [`LookupIpStrategy::Ipv4AndIpv6`] as the default.
    fn default() -> Self {
        LookupIpStrategy::Ipv4thenIpv6
    }
}

/// Configuration for the Resolver
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde-config",
    derive(Serialize, Deserialize),
    serde(default)
)]
#[allow(dead_code)] // TODO: remove after all params are supported
pub struct ResolverOpts {
    /// Sets the number of dots that must appear (unless it's a final dot representing the root)
    ///  that must appear before a query is assumed to include the TLD. The default is one, which
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
    /// Optional minimum TTL for positive responses.
    ///
    /// If this is set, any positive responses with a TTL lower than this value will have a TTL of
    /// `positive_min_ttl` instead. Otherwise, this will default to 0 seconds.
    pub positive_min_ttl: Option<Duration>,
    /// Optional minimum TTL for negative (`NXDOMAIN`) responses.
    ///
    /// If this is set, any positive responses with a TTL lower than this value will have a TTL of
    /// `negative_min_ttl` instead. Otherwise, this will default to 0 seconds.
    pub negative_min_ttl: Option<Duration>,
    /// Optional maximum TTL for positive responses.
    ///
    /// If this is set, any positive responses with a TTL higher than this value will have a TTL of
    /// `positive_max_ttl` instead. Otherwise, this will default to [`MAX_TTL`] seconds.
    ///
    /// [`MAX_TTL`]: ../dns_lru/const.MAX_TTL.html
    pub positive_max_ttl: Option<Duration>,
    /// Optional maximum TTL for negative (`NXDOMAIN`) responses.
    ///
    /// If this is set, any positive responses with a TTL higher than this value will have a TTL of
    /// `negative_max_ttl` instead. Otherwise, this will default to [`MAX_TTL`] seconds.
    ///
    /// [`MAX_TTL`]: ../dns_lru/const.MAX_TTL.html
    pub negative_max_ttl: Option<Duration>,
    /// Default is to distrust negative responses from upstream nameservers
    ///
    /// Currently only SERVFAIL responses are continued on, this may be expanded to include NXDOMAIN or NoError/Empty responses
    pub distrust_nx_responses: bool,
    /// Concurrent requests where more than one Nameserver is registered, the default is 2
    ///
    /// 0 or 1 will configure this to execute all requests serially
    pub num_concurrent_reqs: usize,
}

impl Default for ResolverOpts {
    /// Default values for the Resolver configuration.
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
            positive_min_ttl: None,
            negative_min_ttl: None,
            positive_max_ttl: None,
            negative_max_ttl: None,
            distrust_nx_responses: true,
            num_concurrent_reqs: 2,
        }
    }
}
