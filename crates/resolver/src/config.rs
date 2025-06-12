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
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(any(feature = "__https", feature = "__h3"))]
use crate::proto::http::DEFAULT_DNS_QUERY_PATH;
use crate::proto::rr::Name;
#[cfg(feature = "__tls")]
use crate::proto::rustls::client_config;
use crate::proto::xfer::Protocol;

/// Configuration for the upstream nameservers to use for resolution
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ResolverConfig {
    // base search domain
    #[cfg_attr(feature = "serde", serde(default))]
    domain: Option<Name>,
    // search domains
    #[cfg_attr(feature = "serde", serde(default))]
    search: Vec<Name>,
    // nameservers to use for resolution.
    name_servers: NameServerConfigGroup,
}

impl ResolverConfig {
    /// Creates a default configuration, using `8.8.8.8`, `8.8.4.4` and `2001:4860:4860::8888`,
    /// `2001:4860:4860::8844` (thank you, Google).
    ///
    /// Please see Google's [privacy
    /// statement](https://developers.google.com/speed/public-dns/privacy) for important information
    /// about what they track, many ISP's track similar information in DNS. To use the system
    /// configuration see: `Resolver::from_system_conf`.
    ///
    /// NameServerConfigGroups can be combined to use a set of different providers, see
    /// `NameServerConfigGroup` and `ResolverConfig::from_parts`
    pub fn google() -> Self {
        Self {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: NameServerConfigGroup::google(),
        }
    }

    /// Creates a default configuration, using `8.8.8.8`, `8.8.4.4` and `2001:4860:4860::8888`,
    /// `2001:4860:4860::8844` (thank you, Google). This limits the registered connections to just
    /// TLS lookups
    ///
    /// Please see Google's [privacy
    /// statement](https://developers.google.com/speed/public-dns/privacy) for important information
    /// about what they track, many ISP's track similar information in DNS. To use the system
    /// configuration see: `Resolver::from_system_conf`.
    ///
    /// NameServerConfigGroups can be combined to use a set of different providers, see
    /// `NameServerConfigGroup` and `ResolverConfig::from_parts`
    #[cfg(feature = "__tls")]
    pub fn google_tls() -> Self {
        Self {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: NameServerConfigGroup::google_tls(),
        }
    }

    /// Creates a default configuration, using `8.8.8.8`, `8.8.4.4` and `2001:4860:4860::8888`,
    /// `2001:4860:4860::8844` (thank you, Google). This limits the registered connections to just
    /// HTTPS lookups
    ///
    /// Please see Google's [privacy
    /// statement](https://developers.google.com/speed/public-dns/privacy) for important information
    /// about what they track, many ISP's track similar information in DNS. To use the system
    /// configuration see: `Resolver::from_system_conf`.
    ///
    /// NameServerConfigGroups can be combined to use a set of different providers, see
    /// `NameServerConfigGroup` and `ResolverConfig::from_parts`
    #[cfg(feature = "__https")]
    pub fn google_https() -> Self {
        Self {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: NameServerConfigGroup::google_https(),
        }
    }

    /// Creates a default configuration, using `8.8.8.8`, `8.8.4.4` and `2001:4860:4860::8888`,
    /// `2001:4860:4860::8844` (thank you, Google). This limits the registered connections to just
    /// HTTP/3 lookups
    ///
    /// Please see Google's [privacy
    /// statement](https://developers.google.com/speed/public-dns/privacy) for important information
    /// about what they track, many ISP's track similar information in DNS. To use the system
    /// configuration see: `Resolver::from_system_conf`.
    ///
    /// NameServerConfigGroups can be combined to use a set of different providers, see
    /// `NameServerConfigGroup` and `ResolverConfig::from_parts`
    #[cfg(feature = "__h3")]
    pub fn google_h3() -> Self {
        Self {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: NameServerConfigGroup::google_h3(),
        }
    }

    /// Creates a default configuration, using `1.1.1.1`, `1.0.0.1` and `2606:4700:4700::1111`, `2606:4700:4700::1001` (thank you, Cloudflare).
    ///
    /// Please see: <https://www.cloudflare.com/dns/>
    ///
    /// NameServerConfigGroups can be combined to use a set of different providers, see `NameServerConfigGroup` and `ResolverConfig::from_parts`
    pub fn cloudflare() -> Self {
        Self {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: NameServerConfigGroup::cloudflare(),
        }
    }

    /// Creates a configuration, using `1.1.1.1`, `1.0.0.1` and `2606:4700:4700::1111`, `2606:4700:4700::1001` (thank you, Cloudflare). This limits the registered connections to just TLS lookups
    ///
    /// Please see: <https://www.cloudflare.com/dns/>
    ///
    /// NameServerConfigGroups can be combined to use a set of different providers, see `NameServerConfigGroup` and `ResolverConfig::from_parts`
    #[cfg(feature = "__tls")]
    pub fn cloudflare_tls() -> Self {
        Self {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: NameServerConfigGroup::cloudflare_tls(),
        }
    }

    /// Creates a configuration, using `1.1.1.1`, `1.0.0.1` and `2606:4700:4700::1111`, `2606:4700:4700::1001` (thank you, Cloudflare). This limits the registered connections to just HTTPS lookups
    ///
    /// Please see: <https://www.cloudflare.com/dns/>
    ///
    /// NameServerConfigGroups can be combined to use a set of different providers, see `NameServerConfigGroup` and `ResolverConfig::from_parts`
    #[cfg(feature = "__https")]
    pub fn cloudflare_https() -> Self {
        Self {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: NameServerConfigGroup::cloudflare_https(),
        }
    }

    /// Creates a configuration, using `9.9.9.9`, `149.112.112.112` and `2620:fe::fe`, `2620:fe::fe:9`, the "secure" variants of the quad9 settings (thank you, Quad9).
    ///
    /// Please see: <https://www.quad9.net/faq/>
    ///
    /// NameServerConfigGroups can be combined to use a set of different providers, see `NameServerConfigGroup` and `ResolverConfig::from_parts`
    pub fn quad9() -> Self {
        Self {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: NameServerConfigGroup::quad9(),
        }
    }

    /// Creates a configuration, using `9.9.9.9`, `149.112.112.112` and `2620:fe::fe`, `2620:fe::fe:9`, the "secure" variants of the quad9 settings. This limits the registered connections to just TLS lookups
    ///
    /// Please see: <https://www.quad9.net/faq/>
    ///
    /// NameServerConfigGroups can be combined to use a set of different providers, see `NameServerConfigGroup` and `ResolverConfig::from_parts`
    #[cfg(feature = "__tls")]
    pub fn quad9_tls() -> Self {
        Self {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: NameServerConfigGroup::quad9_tls(),
        }
    }

    /// Creates a configuration, using `9.9.9.9`, `149.112.112.112` and `2620:fe::fe`, `2620:fe::fe:9`, the "secure" variants of the quad9 settings. This limits the registered connections to just HTTPS lookups
    ///
    /// Please see: <https://www.quad9.net/faq/>
    ///
    /// NameServerConfigGroups can be combined to use a set of different providers, see `NameServerConfigGroup` and `ResolverConfig::from_parts`
    #[cfg(feature = "__https")]
    pub fn quad9_https() -> Self {
        Self {
            // TODO: this should get the hostname and use the basename as the default
            domain: None,
            search: vec![],
            name_servers: NameServerConfigGroup::quad9_https(),
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
        Self {
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
}

/// A set of name_servers to associate with a [`ResolverConfig`].
#[derive(Clone, Debug)]
pub struct NameServerConfigGroup {
    servers: Vec<NameServerConfig>,
}

impl NameServerConfigGroup {
    /// Creates a new `NameServiceConfigGroup` with the specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            servers: Vec::with_capacity(capacity),
        }
    }

    /// Returns the inner vec of configs
    pub fn into_inner(self) -> Vec<NameServerConfig> {
        self.servers
    }

    /// Configure a NameServer address and port
    ///
    /// This will create UDP and TCP connections, using the same port.
    pub fn from_ips_clear(ips: &[IpAddr], port: u16, trust_negative_responses: bool) -> Self {
        let mut name_servers = Self::with_capacity(2 * ips.len());

        for ip in ips {
            let socket_addr = SocketAddr::new(*ip, port);
            let udp = NameServerConfig {
                socket_addr,
                protocol: ProtocolConfig::Udp,
                trust_negative_responses,
                bind_addr: None,
            };
            let tcp = NameServerConfig {
                socket_addr,
                protocol: ProtocolConfig::Tcp,
                trust_negative_responses,
                bind_addr: None,
            };

            name_servers.push(udp);
            name_servers.push(tcp);
        }

        name_servers
    }

    #[cfg(any(feature = "__tls", feature = "__https"))]
    fn from_ips_encrypted(
        ips: &[IpAddr],
        port: u16,
        protocol: ProtocolConfig,
        trust_negative_responses: bool,
    ) -> Self {
        let mut name_servers = Self::with_capacity(ips.len());

        for ip in ips {
            let config = NameServerConfig {
                socket_addr: SocketAddr::new(*ip, port),
                protocol: protocol.clone(),
                trust_negative_responses,
                bind_addr: None,
            };

            name_servers.push(config);
        }

        name_servers
    }

    /// Configure a NameServer address and port for DNS-over-TLS
    ///
    /// This will create a TLS connections.
    #[cfg(feature = "__tls")]
    pub fn from_ips_tls(
        ips: &[IpAddr],
        port: u16,
        server_name: Arc<str>,
        trust_negative_responses: bool,
    ) -> Self {
        Self::from_ips_encrypted(
            ips,
            port,
            ProtocolConfig::Tls { server_name },
            trust_negative_responses,
        )
    }

    /// Configure a NameServer address and port for DNS-over-HTTPS
    ///
    /// This will create a HTTPS connections.
    #[cfg(feature = "__https")]
    pub fn from_ips_https(
        ips: &[IpAddr],
        port: u16,
        server_name: Arc<str>,
        trust_negative_responses: bool,
    ) -> Self {
        Self::from_ips_encrypted(
            ips,
            port,
            ProtocolConfig::Https {
                server_name,
                path: Arc::from(DEFAULT_DNS_QUERY_PATH),
            },
            trust_negative_responses,
        )
    }

    /// Configure a NameServer address and port for DNS-over-QUIC
    ///
    /// This will create a QUIC connections.
    #[cfg(feature = "__quic")]
    pub fn from_ips_quic(
        ips: &[IpAddr],
        port: u16,
        server_name: Arc<str>,
        trust_negative_responses: bool,
    ) -> Self {
        Self::from_ips_encrypted(
            ips,
            port,
            ProtocolConfig::Quic { server_name },
            trust_negative_responses,
        )
    }

    /// Configure a NameServer address and port for DNS-over-HTTP/3
    ///
    /// This will create a HTTP/3 connection.
    #[cfg(feature = "__h3")]
    pub fn from_ips_h3(
        ips: &[IpAddr],
        port: u16,
        server_name: Arc<str>,
        trust_negative_responses: bool,
    ) -> Self {
        Self::from_ips_encrypted(
            ips,
            port,
            ProtocolConfig::H3 {
                server_name,
                path: Arc::from(DEFAULT_DNS_QUERY_PATH),
                disable_grease: false,
            },
            trust_negative_responses,
        )
    }

    /// Creates a default configuration, using `8.8.8.8`, `8.8.4.4` and `2001:4860:4860::8888`,
    /// `2001:4860:4860::8844` (thank you, Google).
    ///
    /// Please see Google's [privacy
    /// statement](https://developers.google.com/speed/public-dns/privacy) for important information
    /// about what they track, many ISP's track similar information in DNS. To use the system
    /// configuration see: `Resolver::from_system_conf`.
    pub fn google() -> Self {
        Self::from_ips_clear(GOOGLE_IPS, 53, true)
    }

    /// Creates a default configuration, using `8.8.8.8`, `8.8.4.4` and `2001:4860:4860::8888`,
    /// `2001:4860:4860::8844` (thank you, Google). This limits the registered connections to just
    /// TLS lookups
    ///
    /// Please see Google's [privacy
    /// statement](https://developers.google.com/speed/public-dns/privacy) for important information
    /// about what they track, many ISP's track similar information in DNS. To use the system
    /// configuration see: `Resolver::from_system_conf`.
    #[cfg(feature = "__tls")]
    pub fn google_tls() -> Self {
        Self::from_ips_tls(GOOGLE_IPS, 853, Arc::from("dns.google"), true)
    }

    /// Creates a default configuration, using `8.8.8.8`, `8.8.4.4` and `2001:4860:4860::8888`,
    /// `2001:4860:4860::8844` (thank you, Google). This limits the registered connections to just
    /// HTTPS lookups
    ///
    /// Please see Google's [privacy
    /// statement](https://developers.google.com/speed/public-dns/privacy) for important information
    /// about what they track, many ISP's track similar information in DNS. To use the system
    /// configuration see: `Resolver::from_system_conf`.
    #[cfg(feature = "__https")]
    pub fn google_https() -> Self {
        Self::from_ips_https(GOOGLE_IPS, 443, Arc::from("dns.google"), true)
    }

    /// Creates a default configuration, using `8.8.8.8`, `8.8.4.4` and `2001:4860:4860::8888`,
    /// `2001:4860:4860::8844` (thank you, Google). This limits the registered connections to just
    /// HTTP/3 lookups
    ///
    /// Please see Google's [privacy
    /// statement](https://developers.google.com/speed/public-dns/privacy) for important information
    /// about what they track, many ISP's track similar information in DNS. To use the system
    /// configuration see: `Resolver::from_system_conf`.
    #[cfg(feature = "__h3")]
    pub fn google_h3() -> Self {
        Self::from_ips_h3(GOOGLE_IPS, 443, Arc::from("dns.google"), true)
    }

    /// Creates a default configuration, using `1.1.1.1`, `1.0.0.1` and `2606:4700:4700::1111`, `2606:4700:4700::1001` (thank you, Cloudflare).
    ///
    /// Please see: <https://www.cloudflare.com/dns/>
    pub fn cloudflare() -> Self {
        Self::from_ips_clear(CLOUDFLARE_IPS, 53, true)
    }

    /// Creates a configuration, using `1.1.1.1`, `1.0.0.1` and `2606:4700:4700::1111`, `2606:4700:4700::1001` (thank you, Cloudflare). This limits the registered connections to just TLS lookups
    ///
    /// Please see: <https://www.cloudflare.com/dns/>
    #[cfg(feature = "__tls")]
    pub fn cloudflare_tls() -> Self {
        Self::from_ips_tls(CLOUDFLARE_IPS, 853, Arc::from("cloudflare-dns.com"), true)
    }

    /// Creates a configuration, using `1.1.1.1`, `1.0.0.1` and `2606:4700:4700::1111`, `2606:4700:4700::1001` (thank you, Cloudflare). This limits the registered connections to just HTTPS lookups
    ///
    /// Please see: <https://www.cloudflare.com/dns/>
    #[cfg(feature = "__https")]
    pub fn cloudflare_https() -> Self {
        Self::from_ips_https(CLOUDFLARE_IPS, 443, Arc::from("cloudflare-dns.com"), true)
    }

    /// Creates a configuration, using `9.9.9.9`, `149.112.112.112` and `2620:fe::fe`, `2620:fe::fe:9`, the "secure" variants of the quad9 settings (thank you, Quad9).
    ///
    /// Please see: <https://www.quad9.net/faq/>
    pub fn quad9() -> Self {
        Self::from_ips_clear(QUAD9_IPS, 53, true)
    }

    /// Creates a configuration, using `9.9.9.9`, `149.112.112.112` and `2620:fe::fe`, `2620:fe::fe:9`, the "secure" variants of the quad9 settings. This limits the registered connections to just TLS lookups
    ///
    /// Please see: <https://www.quad9.net/faq/>
    #[cfg(feature = "__tls")]
    pub fn quad9_tls() -> Self {
        Self::from_ips_tls(QUAD9_IPS, 853, Arc::from("dns.quad9.net"), true)
    }

    /// Creates a configuration, using `9.9.9.9`, `149.112.112.112` and `2620:fe::fe`, `2620:fe::fe:9`, the "secure" variants of the quad9 settings. This limits the registered connections to just HTTPS lookups
    ///
    /// Please see: <https://www.quad9.net/faq/>
    #[cfg(feature = "__https")]
    pub fn quad9_https() -> Self {
        Self::from_ips_https(QUAD9_IPS, 443, Arc::from("dns.quad9.net"), true)
    }

    /// Merges this set of [`NameServerConfig`]s with the other
    ///
    /// ```
    /// use std::net::{SocketAddr, Ipv4Addr};
    /// use hickory_resolver::config::NameServerConfigGroup;
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
        self.append(&mut other);
    }

    /// Append nameservers to a NameServerConfigGroup.
    pub fn append_ips(
        &mut self,
        nameserver_ips: impl Iterator<Item = IpAddr>,
        trust_negative_response: bool,
    ) {
        for ip in nameserver_ips {
            for proto in [ProtocolConfig::Udp, ProtocolConfig::Tcp] {
                let mut config = NameServerConfig::new(SocketAddr::from((ip, 53)), proto);
                config.trust_negative_responses = trust_negative_response;
                self.push(config);
            }
        }
    }

    /// Sets the client address (IP and port) to connect from on all name servers.
    pub fn with_bind_addr(mut self, bind_addr: Option<SocketAddr>) -> Self {
        for server in &mut self.servers {
            server.bind_addr = bind_addr;
        }
        self
    }
}

#[cfg(feature = "serde")]
impl Serialize for NameServerConfigGroup {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.servers.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for NameServerConfigGroup {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::deserialize(deserializer).map(|servers| Self { servers })
    }
}

impl Deref for NameServerConfigGroup {
    type Target = Vec<NameServerConfig>;
    fn deref(&self) -> &Self::Target {
        &self.servers
    }
}

impl DerefMut for NameServerConfigGroup {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.servers
    }
}

impl From<Vec<NameServerConfig>> for NameServerConfigGroup {
    fn from(servers: Vec<NameServerConfig>) -> Self {
        Self { servers }
    }
}

impl Default for NameServerConfigGroup {
    fn default() -> Self {
        Self::with_capacity(2)
    }
}

/// Configuration for the NameServer
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(deny_unknown_fields)
)]
pub struct NameServerConfig {
    /// The address which the DNS NameServer is registered at.
    pub socket_addr: SocketAddr,
    /// The protocol to use when communicating with the NameServer.
    pub protocol: ProtocolConfig,
    /// Whether to trust `NXDOMAIN` responses from upstream nameservers.
    ///
    /// When this is `true`, and an empty `NXDOMAIN` response or `NOERROR`
    /// with an empty answers set is received, the
    /// query will not be retried against other configured name servers if
    /// the response has the Authoritative flag set.
    ///
    /// (On a response with any other error
    /// response code, the query will still be retried regardless of this
    /// configuration setting.)
    ///
    /// Defaults to false.
    #[cfg_attr(feature = "serde", serde(default))]
    pub trust_negative_responses: bool,
    /// The client address (IP and port) to use for connecting to the server.
    pub bind_addr: Option<SocketAddr>,
}

impl NameServerConfig {
    /// Constructs a Nameserver configuration with some basic defaults
    pub fn new(socket_addr: SocketAddr, protocol: ProtocolConfig) -> Self {
        Self {
            socket_addr,
            protocol,
            trust_negative_responses: true,
            bind_addr: None,
        }
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
    pub(crate) fn to_protocol(&self) -> Protocol {
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
    #[cfg_attr(feature = "serde", serde(default = "default_timeout"))]
    pub timeout: Duration,
    /// Number of retries after lookup failure before giving up. Defaults to 2
    #[cfg_attr(feature = "serde", serde(default = "default_attempts"))]
    pub attempts: usize,
    /// Validate the names in the response, not implemented don't really see the point unless you need to support
    ///  badly configured DNS
    #[cfg_attr(feature = "serde", serde(default = "default_check_names"))]
    pub check_names: bool,
    /// Enable edns, for larger records
    pub edns0: bool,
    /// Use DNSSEC to validate the request
    pub validate: bool,
    /// The ip_strategy for the Resolver to use when lookup Ipv4 or Ipv6 addresses
    pub ip_strategy: LookupIpStrategy,
    /// Cache size is in number of records (some records can be large)
    #[cfg_attr(feature = "serde", serde(default = "default_cache_size"))]
    pub cache_size: usize,
    /// Check /etc/hosts file before dns requery (only works for unix like OS)
    pub use_hosts_file: ResolveHosts,
    /// Optional minimum TTL for positive responses.
    ///
    /// If this is set, any positive responses with a TTL lower than this value will have a TTL of
    /// `positive_min_ttl` instead. Otherwise, this will default to 0 seconds.
    pub positive_min_ttl: Option<Duration>,
    /// Optional minimum TTL for negative (`NXDOMAIN`) responses.
    ///
    /// If this is set, any negative responses with a TTL lower than this value will have a TTL of
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
    /// If this is set, any negative responses with a TTL higher than this value will have a TTL of
    /// `negative_max_ttl` instead. Otherwise, this will default to [`MAX_TTL`] seconds.
    ///
    /// [`MAX_TTL`]: ../dns_lru/const.MAX_TTL.html
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
    /// Optional configuration for the TLS client.
    ///
    /// The correct ALPN for the corresponding protocol is automatically
    /// inserted if none was specified.
    #[cfg(feature = "__tls")]
    #[cfg_attr(feature = "serde", serde(skip, default = "client_config"))]
    pub tls_config: rustls::ClientConfig,
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
            check_names: default_check_names(),
            edns0: false,
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
            #[cfg(feature = "__tls")]
            tls_config: client_config(),
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

fn default_check_names() -> bool {
    true
}

fn default_cache_size() -> usize {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
    /// Returns [`LookupIpStrategy::Ipv4thenIpv6`] as the default.
    fn default() -> Self {
        Self::Ipv4thenIpv6
    }
}

/// The strategy for establishing the query order of name servers in a pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum ServerOrderingStrategy {
    /// Servers are ordered based on collected query statistics. The ordering
    /// may vary over time.
    QueryStatistics,
    /// The order provided to the resolver is used. The ordering does not vary
    /// over time.
    UserProvidedOrder,
    /// The order of servers is rotated in a round-robin fashion. This is useful for
    /// load balancing and ensuring that all servers are used evenly.
    RoundRobin,
}

impl Default for ServerOrderingStrategy {
    /// Returns [`ServerOrderingStrategy::QueryStatistics`] as the default.
    fn default() -> Self {
        Self::QueryStatistics
    }
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

/// IP addresses for Google Public DNS
pub const GOOGLE_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)),
];

/// IP addresses for Cloudflare's 1.1.1.1 DNS service
pub const CLOUDFLARE_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
];

/// IP address for the Quad9 DNS service
pub const QUAD9_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
    IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)),
    IpAddr::V6(Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe)),
    IpAddr::V6(Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0x00fe, 0x0009)),
];

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
        assert_eq!(code.check_names, json.check_names);
        assert_eq!(code.edns0, json.edns0);
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
