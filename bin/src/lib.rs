// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Configuration module for the server binary, `named`.

pub mod dnssec;

use std::fs::File;
use std::io::Read;
use std::net::{AddrParseError, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use cfg_if::cfg_if;
use ipnet::IpNet;
use serde::{self, Deserialize};

use hickory_proto::error::ProtoResult;
use hickory_proto::rr::Name;
use hickory_server::authority::ZoneType;
#[cfg(feature = "dnssec")]
use hickory_server::dnssec::NxProofKind;
use hickory_server::error::ConfigResult;
use hickory_server::store::StoreConfigContainer;

static DEFAULT_PATH: &str = "/var/named"; // TODO what about windows (do I care? ;)
static DEFAULT_PORT: u16 = 53;
static DEFAULT_TLS_PORT: u16 = 853;
static DEFAULT_HTTPS_PORT: u16 = 443;
static DEFAULT_QUIC_PORT: u16 = 853; // https://www.ietf.org/archive/id/draft-ietf-dprive-dnsoquic-11.html#name-reservation-of-dedicated-po
static DEFAULT_H3_PORT: u16 = 443;
static DEFAULT_TCP_REQUEST_TIMEOUT: u64 = 5;

/// Server configuration
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The list of IPv4 addresses to listen on
    #[serde(default)]
    listen_addrs_ipv4: Vec<String>,
    /// This list of IPv6 addresses to listen on
    #[serde(default)]
    listen_addrs_ipv6: Vec<String>,
    /// Port on which to listen (associated to all IPs)
    listen_port: Option<u16>,
    /// Secure port to listen on
    tls_listen_port: Option<u16>,
    /// HTTPS port to listen on
    https_listen_port: Option<u16>,
    /// QUIC port to listen on
    quic_listen_port: Option<u16>,
    /// HTTP/3 port to listen on
    h3_listen_port: Option<u16>,
    /// Disable TCP protocol
    disable_tcp: Option<bool>,
    /// Disable UDP protocol
    disable_udp: Option<bool>,
    /// Disable TLS protocol
    disable_tls: Option<bool>,
    /// Disable HTTPS protocol
    disable_https: Option<bool>,
    /// Disable QUIC protocol
    disable_quic: Option<bool>,
    /// Timeout associated to a request before it is closed.
    tcp_request_timeout: Option<u64>,
    /// Level at which to log, default is INFO
    log_level: Option<String>,
    /// Base configuration directory, i.e. root path for zones
    directory: Option<String>,
    /// List of configurations for zones
    #[serde(default)]
    zones: Vec<ZoneConfig>,
    /// Certificate to associate to TLS connections (currently the same is used for HTTPS and TLS)
    #[cfg(feature = "dns-over-tls")]
    tls_cert: Option<dnssec::TlsCertConfig>,
    /// The HTTP endpoint where the DNS-over-HTTPS server provides service. Applicable
    /// to both HTTP/2 and HTTP/3 servers. Typically `/dns-query`.
    #[cfg(any(feature = "dns-over-https-rustls", feature = "dns-over-h3"))]
    http_endpoint: Option<String>,
    /// Networks denied to access the server
    #[serde(default)]
    deny_networks: Vec<IpNet>,
    /// Networks allowed to access the server
    #[serde(default)]
    allow_networks: Vec<IpNet>,
}

impl Config {
    /// read a Config file from the file specified at path.
    pub fn read_config(path: &Path) -> ConfigResult<Self> {
        let mut file = File::open(path)?;
        let mut toml = String::new();
        file.read_to_string(&mut toml)?;
        Self::from_toml(&toml)
    }

    /// Read a [`Config`] from the given TOML string.
    pub fn from_toml(toml: &str) -> ConfigResult<Self> {
        Ok(toml::from_str(toml)?)
    }

    /// set of listening ipv4 addresses (for TCP and UDP)
    pub fn listen_addrs_ipv4(&self) -> Result<Vec<Ipv4Addr>, AddrParseError> {
        self.listen_addrs_ipv4.iter().map(|s| s.parse()).collect()
    }

    /// set of listening ipv6 addresses (for TCP and UDP)
    pub fn listen_addrs_ipv6(&self) -> Result<Vec<Ipv6Addr>, AddrParseError> {
        self.listen_addrs_ipv6.iter().map(|s| s.parse()).collect()
    }

    /// port on which to listen for connections on specified addresses
    pub fn listen_port(&self) -> u16 {
        self.listen_port.unwrap_or(DEFAULT_PORT)
    }

    /// port on which to listen for TLS connections
    pub fn tls_listen_port(&self) -> u16 {
        self.tls_listen_port.unwrap_or(DEFAULT_TLS_PORT)
    }

    /// port on which to listen for HTTPS connections
    pub fn https_listen_port(&self) -> u16 {
        self.https_listen_port.unwrap_or(DEFAULT_HTTPS_PORT)
    }

    /// port on which to listen for QUIC connections
    pub fn quic_listen_port(&self) -> u16 {
        self.quic_listen_port.unwrap_or(DEFAULT_QUIC_PORT)
    }

    /// port on which to listen for HTTP/3 connections
    pub fn h3_listen_port(&self) -> u16 {
        self.h3_listen_port.unwrap_or(DEFAULT_H3_PORT)
    }

    /// get if TCP protocol should be disabled
    pub fn disable_tcp(&self) -> bool {
        self.disable_tcp.unwrap_or_default()
    }

    /// get if UDP protocol should be disabled
    pub fn disable_udp(&self) -> bool {
        self.disable_udp.unwrap_or_default()
    }

    /// get if TLS protocol should be disabled
    pub fn disable_tls(&self) -> bool {
        self.disable_tls.unwrap_or_default()
    }

    /// get if HTTPS protocol should be disabled
    pub fn disable_https(&self) -> bool {
        self.disable_https.unwrap_or_default()
    }

    /// get if QUIC protocol should be disabled
    pub fn disable_quic(&self) -> bool {
        self.disable_quic.unwrap_or_default()
    }

    /// default timeout for all TCP connections before forcibly shutdown
    pub fn tcp_request_timeout(&self) -> Duration {
        Duration::from_secs(
            self.tcp_request_timeout
                .unwrap_or(DEFAULT_TCP_REQUEST_TIMEOUT),
        )
    }

    /// specify the log level which should be used, ["Trace", "Debug", "Info", "Warn", "Error"]
    pub fn log_level(&self) -> tracing::Level {
        if let Some(ref level_str) = self.log_level {
            tracing::Level::from_str(level_str).unwrap_or(tracing::Level::INFO)
        } else {
            tracing::Level::INFO
        }
    }

    /// the path for all zone configurations, defaults to `/var/named`
    pub fn directory(&self) -> &Path {
        self.directory
            .as_ref()
            .map_or(Path::new(DEFAULT_PATH), Path::new)
    }

    /// the set of zones which should be loaded
    pub fn zones(&self) -> &[ZoneConfig] {
        &self.zones
    }

    /// the tls certificate to use for accepting tls connections
    pub fn tls_cert(&self) -> Option<&dnssec::TlsCertConfig> {
        cfg_if! {
            if #[cfg(feature = "dns-over-tls")] {
                self.tls_cert.as_ref()
            } else {
                None
            }
        }
    }

    /// the HTTP endpoint from where requests are received
    #[cfg(any(feature = "dns-over-https-rustls", feature = "dns-over-h3"))]
    pub fn http_endpoint(&self) -> &str {
        self.http_endpoint
            .as_deref()
            .unwrap_or(hickory_proto::http::DEFAULT_DNS_QUERY_PATH)
    }

    /// get the networks denied access to this server
    pub fn deny_networks(&self) -> &[IpNet] {
        &self.deny_networks
    }

    /// get the networks allowed to connect to this server
    pub fn allow_networks(&self) -> &[IpNet] {
        &self.allow_networks
    }
}

/// Configuration for a zone
#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct ZoneConfig {
    /// name of the zone
    pub zone: String, // TODO: make Domain::Name decodable
    /// type of the zone
    pub zone_type: ZoneType,
    /// location of the file (short for StoreConfig::FileConfig{zone_file_path})
    pub file: Option<String>,
    /// Deprecated allow_update, this is a Store option
    pub allow_update: Option<bool>,
    /// Allow AXFR (TODO: need auth)
    pub allow_axfr: Option<bool>,
    /// Enable DnsSec TODO: should this move to StoreConfig?
    pub enable_dnssec: Option<bool>,
    /// Keys for use by the zone
    #[serde(default)]
    pub keys: Vec<dnssec::KeyConfig>,
    /// Store configurations, TODO: allow chained Stores
    #[serde(default)]
    pub stores: Option<StoreConfigContainer>,
    /// The kind of non-existence proof provided by the nameserver
    #[cfg(feature = "dnssec")]
    pub nx_proof_kind: Option<NxProofKind>,
}

impl ZoneConfig {
    /// Return a new zone configuration
    ///
    /// # Arguments
    ///
    /// * `zone` - name of a zone, e.g. example.com
    /// * `zone_type` - Type of zone, e.g. Primary, Secondary, etc.
    /// * `file` - relative to Config base path, to the zone file
    /// * `allow_update` - enable dynamic updates
    /// * `allow_axfr` - enable AXFR transfers
    /// * `enable_dnssec` - enable signing of the zone for DNSSEC
    /// * `keys` - list of private and public keys used to sign a zone
    /// * `nx_proof_kind` - the kind of non-existence proof provided by the nameserver
    #[cfg_attr(feature = "dnssec", allow(clippy::too_many_arguments))]
    pub fn new(
        zone: String,
        zone_type: ZoneType,
        file: String,
        allow_update: Option<bool>,
        allow_axfr: Option<bool>,
        enable_dnssec: Option<bool>,
        keys: Vec<dnssec::KeyConfig>,
        #[cfg(feature = "dnssec")] nx_proof_kind: Option<NxProofKind>,
    ) -> Self {
        Self {
            zone,
            zone_type,
            file: Some(file),
            allow_update,
            allow_axfr,
            enable_dnssec,
            keys,
            stores: None,
            #[cfg(feature = "dnssec")]
            nx_proof_kind,
        }
    }

    // TODO this is a little ugly for the parse, b/c there is no terminal char
    /// returns the name of the Zone, i.e. the `example.com` of `www.example.com.`
    pub fn zone(&self) -> ProtoResult<Name> {
        Name::parse(&self.zone, Some(&Name::new()))
    }

    /// the type of the zone
    pub fn zone_type(&self) -> ZoneType {
        self.zone_type
    }

    /// path to the zone file, i.e. the base set of original records in the zone
    ///
    /// this is ony used on first load, if dynamic update is enabled for the zone, then the journal
    /// file is the actual source of truth for the zone.
    pub fn file(&self) -> PathBuf {
        // TODO: Option on PathBuf
        PathBuf::from(self.file.as_ref().expect("file was none"))
    }

    /// enable dynamic updates for the zone (see SIG0 and the registered keys)
    pub fn is_update_allowed(&self) -> bool {
        self.allow_update.unwrap_or(false)
    }

    /// enable AXFR transfers
    pub fn is_axfr_allowed(&self) -> bool {
        self.allow_axfr.unwrap_or(false)
    }

    /// declare that this zone should be signed, see keys for configuration of the keys for signing
    pub fn is_dnssec_enabled(&self) -> bool {
        cfg_if! {
            if #[cfg(feature = "dnssec")] {
                self.enable_dnssec.unwrap_or(false)
            } else {
                false
            }
        }
    }

    /// the configuration for the keys used for auth and/or dnssec zone signing.
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    pub fn keys(&self) -> &[dnssec::KeyConfig] {
        &self.keys
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "recursor")]
    #[test]
    fn example_recursor_config() {
        toml::from_str::<super::Config>(include_str!(
            "../../tests/test-data/test_configs/example_recursor.toml"
        ))
        .unwrap();
    }
}
