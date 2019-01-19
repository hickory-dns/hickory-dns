// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Configuration module for the server binary, `named`.

use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use log;
use toml;

use proto::error::ProtoResult;
#[cfg(feature = "dnssec")]
use trust_dns::error::*;
#[cfg(feature = "dnssec")]
use trust_dns::rr::dnssec::{Algorithm, KeyFormat};
use trust_dns::rr::Name;

use authority::ZoneType;
use error::{ConfigError, ConfigResult};
use store;

static DEFAULT_PATH: &'static str = "/var/named"; // TODO what about windows (do I care? ;)
static DEFAULT_PORT: u16 = 53;
static DEFAULT_TLS_PORT: u16 = 853;
static DEFAULT_HTTPS_PORT: u16 = 443;
static DEFAULT_TCP_REQUEST_TIMEOUT: u64 = 5;

/// Server configuration
#[derive(Deserialize, Debug)]
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
    tls_cert: Option<TlsCertConfig>,
}

impl Config {
    /// read a Config file from the file specified at path.
    pub fn read_config(path: &Path) -> ConfigResult<Config> {
        let mut file: File = File::open(path)?;
        let mut toml: String = String::new();
        file.read_to_string(&mut toml)?;
        toml.parse()
    }

    /// set of listening ipv4 addresses (for TCP and UDP)
    pub fn get_listen_addrs_ipv4(&self) -> Vec<Ipv4Addr> {
        self.listen_addrs_ipv4
            .iter()
            .map(|s| s.parse().unwrap())
            .collect()
    }

    /// set of listening ipv6 addresses (for TCP and UDP)
    pub fn get_listen_addrs_ipv6(&self) -> Vec<Ipv6Addr> {
        self.listen_addrs_ipv6
            .iter()
            .map(|s| s.parse().unwrap())
            .collect()
    }

    /// port on which to listen for connections on specified addresses
    pub fn get_listen_port(&self) -> u16 {
        self.listen_port.unwrap_or(DEFAULT_PORT)
    }

    /// port on which to listen for TLS connections
    pub fn get_tls_listen_port(&self) -> u16 {
        self.tls_listen_port.unwrap_or(DEFAULT_TLS_PORT)
    }

    /// port on which to listen for HTTPS connections
    pub fn get_https_listen_port(&self) -> u16 {
        self.https_listen_port.unwrap_or(DEFAULT_HTTPS_PORT)
    }

    /// default timeout for all TCP connections before forceably shutdown
    pub fn get_tcp_request_timeout(&self) -> Duration {
        Duration::from_secs(
            self.tcp_request_timeout
                .unwrap_or(DEFAULT_TCP_REQUEST_TIMEOUT),
        )
    }

    /// specify the log level which should be used, ["Trace", "Debug", "Info", "Warn", "Error"]
    pub fn get_log_level(&self) -> log::Level {
        if let Some(ref level_str) = self.log_level {
            match level_str as &str {
                "Trace" => log::Level::Trace,
                "Debug" => log::Level::Debug,
                "Info" => log::Level::Info,
                "Warn" => log::Level::Warn,
                "Error" => log::Level::Error,
                _ => log::Level::Info,
            }
        } else {
            log::Level::Info
        }
    }

    /// the path for all zone configurations, defaults to `/var/named`
    pub fn get_directory(&self) -> &Path {
        self.directory
            .as_ref()
            .map_or(Path::new(DEFAULT_PATH), |s| Path::new(s))
    }

    /// the set of zones which should be loaded
    pub fn get_zones(&self) -> &[ZoneConfig] {
        &self.zones
    }

    /// the tls certificate to use for accepting tls connections
    pub fn get_tls_cert(&self) -> Option<&TlsCertConfig> {
        self.tls_cert.as_ref()
    }
}

impl FromStr for Config {
    type Err = ConfigError;

    fn from_str(toml: &str) -> ConfigResult<Config> {
        toml::de::from_str(toml).map_err(Into::into)
    }
}

/// Configuration for a zone
#[derive(Deserialize, PartialEq, Debug)]
pub struct ZoneConfig {
    zone: String, // TODO: make Domain::Name decodable
    zone_type: ZoneType,
    file: Option<String>,
    allow_update: Option<bool>,
    allow_axfr: Option<bool>,
    enable_dnssec: Option<bool>,
    #[serde(default)]
    keys: Vec<KeyConfig>,
    store: Option<store::Config>,
}

impl ZoneConfig {
    /// Return a new zone configuration
    ///
    /// # Arguments
    ///
    /// * `zone` - name of a zone, e.g. example.com
    /// * `zone_type` - Type of zone, e.g. Master
    /// * `file` - relative to Config base path, to the zone file
    /// * `allow_update` - enable dynamic updates
    /// * `allow_axfr` - enable AXFR transfers
    /// * `enable_dnssec` - enable signing of the zone for DNSSec
    /// * `keys` - list of private and public keys used to sign a zone
    pub fn new(
        zone: String,
        zone_type: ZoneType,
        file: String,
        allow_update: Option<bool>,
        allow_axfr: Option<bool>,
        enable_dnssec: Option<bool>,
        keys: Vec<KeyConfig>,
    ) -> Self {
        ZoneConfig {
            zone,
            zone_type,
            file: Some(file),
            allow_update,
            allow_axfr,
            enable_dnssec,
            keys,
            store: None,
        }
    }

    // TODO this is a little ugly for the parse, b/c there is no terminal char
    /// retuns the name of the Zone, i.e. the `example.com` of `www.example.com.`
    pub fn get_zone(&self) -> ProtoResult<Name> {
        Name::parse(&self.zone, Some(&Name::new()))
    }

    /// the type of the zone
    pub fn get_zone_type(&self) -> ZoneType {
        self.zone_type
    }

    /// path to the zone file, i.e. the base set of original records in the zone
    ///
    /// this is ony used on first load, if dynamic update is enabled for the zone, then the journal
    /// file is the actual source of truth for the zone.
    pub fn get_file(&self) -> PathBuf {
        // FIXME: Option on PathBuf
        PathBuf::from(self.file.as_ref().unwrap())
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
        self.enable_dnssec.unwrap_or(false)
    }

    /// the configuration for the keys used for auth and/or dnssec zone signing.
    pub fn get_keys(&self) -> &[KeyConfig] {
        &self.keys
    }
}

/// Key pair configuration for DNSSec keys for signing a zone
#[cfg(feature = "dnssec")]
#[derive(Deserialize, PartialEq, Debug)]
pub struct KeyConfig {
    key_path: String,
    password: Option<String>,
    algorithm: String,
    signer_name: Option<String>,
    is_zone_signing_key: Option<bool>,
    is_zone_update_auth: Option<bool>,
}

#[cfg(feature = "dnssec")]
impl KeyConfig {
    /// Return a new KeyConfig
    ///
    /// # Arguments
    ///
    /// * `key_path` - file path to the key
    /// * `password` - password to use to read the key
    /// * `algorithm` - the type of key stored, see `Algorithm`
    /// * `signer_name` - the name to use when signing records, e.g. ns.example.com
    /// * `is_zone_signing_key` - specify that this key should be used for signing a zone
    /// * `is_zone_update_auth` - specifies that this key can be used for dynamic updates in the zone
    pub fn new(
        key_path: String,
        password: Option<String>,
        algorithm: Algorithm,
        signer_name: String,
        is_zone_signing_key: bool,
        is_zone_update_auth: bool,
    ) -> Self {
        KeyConfig {
            key_path,
            password,
            algorithm: algorithm.to_str().to_string(),
            signer_name: Some(signer_name),
            is_zone_signing_key: Some(is_zone_signing_key),
            is_zone_update_auth: Some(is_zone_update_auth),
        }
    }

    /// path to the key file, either relative to the zone file, or a explicit from the root.
    pub fn key_path(&self) -> &Path {
        Path::new(&self.key_path)
    }

    /// Converts key into
    pub fn format(&self) -> ParseResult<KeyFormat> {
        let extension = self.key_path().extension().ok_or_else(|| {
            ParseErrorKind::Msg(format!(
                "file lacks extension, e.g. '.pk8': {:?}",
                self.key_path()
            ))
        })?;

        match extension.to_str() {
            Some("der") => Ok(KeyFormat::Der),
            Some("key") => Ok(KeyFormat::Pem), // TODO: deprecate this...
            Some("pem") => Ok(KeyFormat::Pem),
            Some("pk8") => Ok(KeyFormat::Pkcs8),
            e => Err(ParseErrorKind::Msg(format!(
                "extension not understood, '{:?}': {:?}",
                e,
                self.key_path()
            )).into()),
        }
    }

    /// Returns the password used to read the key
    pub fn password(&self) -> Option<&str> {
        self.password.as_ref().map(|s| s.as_str())
    }

    /// algorithm for for the key, see `Algorithm` for supported algorithms.
    pub fn algorithm(&self) -> ParseResult<Algorithm> {
        match self.algorithm.as_str() {
            "RSASHA1" => Ok(Algorithm::RSASHA1),
            "RSASHA256" => Ok(Algorithm::RSASHA256),
            "RSASHA1-NSEC3-SHA1" => Ok(Algorithm::RSASHA1NSEC3SHA1),
            "RSASHA512" => Ok(Algorithm::RSASHA512),
            "ECDSAP256SHA256" => Ok(Algorithm::ECDSAP256SHA256),
            "ECDSAP384SHA384" => Ok(Algorithm::ECDSAP384SHA384),
            "ED25519" => Ok(Algorithm::ED25519),
            s => Err(format!("unrecognized string {}", s).into()),
        }
    }

    /// the signer name for the key, this defaults to the $ORIGIN aka zone name.
    pub fn signer_name(&self) -> ParseResult<Option<Name>> {
        if let Some(signer_name) = self.signer_name.as_ref() {
            let name = Name::parse(signer_name, None)?;
            return Ok(Some(name));
        }

        Ok(None)
    }

    /// specifies that this key should be used to sign the zone
    ///
    /// The public key for this must be trusted by a resolver to work. The key must have a private
    /// portion associated with it. It will be registered as a DNSKEY in the zone.
    pub fn is_zone_signing_key(&self) -> bool {
        self.is_zone_signing_key.unwrap_or(false)
    }

    /// this is at least a public_key, and can be used for SIG0 dynamic updates.
    ///
    /// it will be registered as a KEY record in the zone.
    pub fn is_zone_update_auth(&self) -> bool {
        self.is_zone_update_auth.unwrap_or(false)
    }
}

#[cfg(not(feature = "dnssec"))]
#[allow(missing_docs)]
#[derive(Deserialize, PartialEq, Debug)]
pub struct KeyConfig {}

/// Certificate format of the file being read
#[derive(Deserialize, PartialEq, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum CertType {
    /// Pkcs12 formatted certifcates and private key (requries OpenSSL)
    Pkcs12,
    /// PEM formatted Certificate chain
    Pem,
}

impl Default for CertType {
    fn default() -> Self {
        CertType::Pkcs12
    }
}

/// Format of the private key file to read
#[derive(Deserialize, PartialEq, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum PrivateKeyType {
    /// PKCS8 formatted key file, allows for a password (requires Rustls)
    Pkcs8,
    /// DER formatted key, raw and unencrypted
    Der,
}

impl Default for PrivateKeyType {
    fn default() -> Self {
        PrivateKeyType::Der
    }
}

/// Configuration for a TLS certificate
#[derive(Deserialize, PartialEq, Debug)]
pub struct TlsCertConfig {
    path: String,
    cert_type: Option<CertType>,
    password: Option<String>,
    private_key: Option<String>,
    private_key_type: Option<PrivateKeyType>,
}

impl TlsCertConfig {
    /// path to the pkcs12 der formated certificate file
    pub fn get_path(&self) -> &Path {
        Path::new(&self.path)
    }

    /// Returns the format type of the certificate file
    pub fn get_cert_type(&self) -> CertType {
        self.cert_type.unwrap_or_default()
    }

    /// optional password for open the pkcs12, none assumes no password
    pub fn get_password(&self) -> Option<&str> {
        self.password.as_ref().map(|s| s.as_str())
    }

    /// returns the path to the private key, as associated with the certificate
    pub fn get_private_key(&self) -> Option<&Path> {
        self.private_key.as_ref().map(|s| s.as_str()).map(Path::new)
    }

    /// returns the path to the private key
    pub fn get_private_key_type(&self) -> PrivateKeyType {
        self.private_key_type.unwrap_or_default()
    }
}
