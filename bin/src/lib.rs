// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Configuration module for the server binary, `named`.

#[cfg(feature = "__dnssec")]
pub mod dnssec;

#[cfg(feature = "__tls")]
use std::{ffi::OsStr, fs};
use std::{
    fmt,
    fs::File,
    io::Read,
    net::{AddrParseError, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use cfg_if::cfg_if;
use ipnet::IpNet;
#[cfg(feature = "__tls")]
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::ResolvesServerCert,
    sign::{CertifiedKey, SingleCertAndKey},
};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{self, Deserialize, Deserializer};

#[cfg(feature = "__tls")]
use hickory_proto::rustls::default_provider;
use hickory_proto::{ProtoError, rr::Name};
#[cfg(feature = "__dnssec")]
use hickory_server::authority::DnssecAuthority;
#[cfg(feature = "__dnssec")]
use hickory_server::dnssec::NxProofKind;
#[cfg(feature = "blocklist")]
use hickory_server::store::blocklist::BlocklistAuthority;
#[cfg(feature = "blocklist")]
use hickory_server::store::blocklist::BlocklistConfig;
use hickory_server::store::file::FileConfig;
#[cfg(feature = "resolver")]
use hickory_server::store::forwarder::ForwardAuthority;
#[cfg(feature = "resolver")]
use hickory_server::store::forwarder::ForwardConfig;
#[cfg(feature = "recursor")]
use hickory_server::store::recursor::RecursiveAuthority;
#[cfg(feature = "recursor")]
use hickory_server::store::recursor::RecursiveConfig;
#[cfg(feature = "sqlite")]
use hickory_server::store::sqlite::{SqliteAuthority, SqliteConfig};
use hickory_server::{
    ConfigError,
    authority::{AuthorityObject, ZoneType},
    store::file::FileAuthority,
};
use tracing::{debug, info, warn};

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
    /// User to run the server as.
    ///
    /// Only supported on Unix-like platforms. If the real or effective UID of the hickory process
    /// is root, we will attempt to change to this user (or to nobody if no user is specified here.)
    pub user: Option<String>,
    /// Group to run the server as.
    ///
    /// Only supported on Unix-like platforms. If the real or effective UID of the hickory process
    /// is root, we will attempt to change to this group (or to nobody if no group is specified here.)
    pub group: Option<String>,
    /// List of configurations for zones
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_file")]
    zones: Vec<ZoneConfig>,
    /// Certificate to associate to TLS connections (currently the same is used for HTTPS and TLS)
    #[cfg(feature = "__tls")]
    tls_cert: Option<TlsCertConfig>,
    /// The HTTP endpoint where the DNS-over-HTTPS server provides service. Applicable
    /// to both HTTP/2 and HTTP/3 servers. Typically `/dns-query`.
    #[cfg(any(feature = "__https", feature = "__h3"))]
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
    pub fn read_config(path: &Path) -> Result<Self, ConfigError> {
        let mut file = File::open(path)?;
        let mut toml = String::new();
        file.read_to_string(&mut toml)?;
        Self::from_toml(&toml)
    }

    /// Read a [`Config`] from the given TOML string.
    pub fn from_toml(toml: &str) -> Result<Self, ConfigError> {
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
        if let Some(level_str) = &self.log_level {
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
    pub fn tls_cert(&self) -> Option<&TlsCertConfig> {
        cfg_if! {
            if #[cfg(feature = "__tls")] {
                self.tls_cert.as_ref()
            } else {
                None
            }
        }
    }

    /// the HTTP endpoint from where requests are received
    #[cfg(any(feature = "__https", feature = "__h3"))]
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

#[derive(Deserialize, Debug)]
struct ZoneConfigWithFile {
    file: Option<PathBuf>,
    #[serde(flatten)]
    config: ZoneConfig,
}

fn deserialize_with_file<'de, D>(deserializer: D) -> Result<Vec<ZoneConfig>, D::Error>
where
    D: Deserializer<'de>,
    D::Error: serde::de::Error,
{
    Vec::<ZoneConfigWithFile>::deserialize(deserializer)?
        .into_iter()
        .map(|ZoneConfigWithFile { file, mut config }| match file {
            Some(file) => match &mut config.zone_type_config {
                ZoneTypeConfig::Primary(server_config)
                | ZoneTypeConfig::Secondary(server_config) => {
                    if server_config
                        .stores
                        .iter()
                        .any(|store| matches!(store, ServerStoreConfig::File(_)))
                    {
                        Err(<D::Error as serde::de::Error>::custom(
                            "having `file` and `[zones.store]` item with type `file` is ambiguous",
                        ))
                    } else {
                        let store = ServerStoreConfig::File(FileConfig {
                            zone_file_path: file,
                        });

                        if server_config.stores.len() == 1
                            && matches!(&server_config.stores[0], ServerStoreConfig::Default)
                        {
                            server_config.stores[0] = store;
                        } else {
                            server_config.stores.push(store);
                        }
                        Ok(config)
                    }
                }
                _ => Err(<D::Error as serde::de::Error>::custom(
                    "cannot use `file` on a zone that is not primary or secondary",
                )),
            },

            _ => Ok(config),
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Configuration for a zone
#[derive(Deserialize, Debug)]
pub struct ZoneConfig {
    /// name of the zone
    pub zone: String, // TODO: make Domain::Name decodable
    /// type of the zone
    #[serde(flatten)]
    pub zone_type_config: ZoneTypeConfig,
}

impl ZoneConfig {
    #[warn(clippy::wildcard_enum_match_arm)] // make sure all cases are handled despite of non_exhaustive
    pub async fn load(&self, zone_dir: &Path) -> Result<Vec<Arc<dyn AuthorityObject>>, String> {
        debug!("loading zone with config: {self:#?}");

        let zone_name = self
            .zone()
            .map_err(|err| format!("failed to read zone name: {err}"))?;
        let zone_type = self.zone_type();

        // load the zone and insert any configured authorities in the catalog.

        let mut authorities: Vec<Arc<dyn AuthorityObject>> = vec![];

        #[cfg(feature = "blocklist")]
        let handle_blocklist_store = |config| {
            let zone_name = zone_name.clone();

            async move {
                Result::<Arc<dyn AuthorityObject>, String>::Ok(Arc::new(
                    BlocklistAuthority::try_from_config(
                        zone_name.clone(),
                        zone_type,
                        config,
                        Some(zone_dir),
                    )
                    .await?,
                ))
            }
        };

        match &self.zone_type_config {
            ZoneTypeConfig::Primary(server_config) | ZoneTypeConfig::Secondary(server_config) => {
                debug!(
                    "loading authorities for {zone_name} with stores {:?}",
                    server_config.stores
                );

                let is_axfr_allowed = server_config.is_axfr_allowed();
                for store in &server_config.stores {
                    let authority: Arc<dyn AuthorityObject> = match store {
                        #[cfg(feature = "sqlite")]
                        ServerStoreConfig::Sqlite(config) => {
                            #[cfg_attr(not(feature = "__dnssec"), allow(unused_mut))]
                            let mut authority = SqliteAuthority::try_from_config(
                                zone_name.clone(),
                                zone_type,
                                is_axfr_allowed,
                                server_config.is_dnssec_enabled(),
                                Some(zone_dir),
                                config,
                                #[cfg(feature = "__dnssec")]
                                server_config.nx_proof_kind.clone(),
                            )
                            .await?;

                            #[cfg(feature = "__dnssec")]
                            server_config.load_keys(&mut authority, &zone_name).await?;
                            Arc::new(authority)
                        }

                        ServerStoreConfig::File(config) => {
                            #[cfg_attr(not(feature = "__dnssec"), allow(unused_mut))]
                            let mut authority = FileAuthority::try_from_config(
                                zone_name.clone(),
                                zone_type,
                                is_axfr_allowed,
                                Some(zone_dir),
                                config,
                                #[cfg(feature = "__dnssec")]
                                server_config.nx_proof_kind.clone(),
                            )?;

                            #[cfg(feature = "__dnssec")]
                            server_config.load_keys(&mut authority, &zone_name).await?;
                            Arc::new(authority)
                        }
                        _ => return empty_stores_error(),
                    };

                    authorities.push(authority);
                }
            }
            ZoneTypeConfig::External { stores } => {
                debug!(
                    "loading authorities for {zone_name} with stores {:?}",
                    stores
                );

                #[cfg_attr(
                    not(any(feature = "blocklist", feature = "resolver")),
                    allow(unreachable_code, unused_variables, clippy::never_loop)
                )]
                for store in stores {
                    let authority: Arc<dyn AuthorityObject> = match store {
                        #[cfg(feature = "blocklist")]
                        ExternalStoreConfig::Blocklist(config) => {
                            handle_blocklist_store(config).await?
                        }
                        #[cfg(feature = "resolver")]
                        ExternalStoreConfig::Forward(config) => {
                            let forwarder = ForwardAuthority::try_from_config(
                                zone_name.clone(),
                                zone_type,
                                config,
                            )?;

                            Arc::new(forwarder)
                        }
                        #[cfg(feature = "recursor")]
                        ExternalStoreConfig::Recursor(config) => {
                            let recursor = RecursiveAuthority::try_from_config(
                                zone_name.clone(),
                                zone_type,
                                config,
                                Some(zone_dir),
                            )
                            .await?;

                            Arc::new(recursor)
                        }
                        _ => return empty_stores_error(),
                    };

                    authorities.push(authority);
                }
            }
        }

        info!("zone successfully loaded: {}", self.zone()?);
        Ok(authorities)
    }

    // TODO this is a little ugly for the parse, b/c there is no terminal char
    /// returns the name of the Zone, i.e. the `example.com` of `www.example.com.`
    pub fn zone(&self) -> Result<Name, ProtoError> {
        Name::parse(&self.zone, Some(&Name::new()))
    }

    /// the type of the zone
    pub fn zone_type(&self) -> ZoneType {
        match &self.zone_type_config {
            ZoneTypeConfig::Primary { .. } => ZoneType::Primary,
            ZoneTypeConfig::Secondary { .. } => ZoneType::Secondary,
            ZoneTypeConfig::External { .. } => ZoneType::External,
        }
    }
}

fn empty_stores_error<T>() -> Result<T, String> {
    Result::Err("empty [[zones.stores]] in config".to_owned())
}

#[derive(Deserialize, Debug)]
#[serde(tag = "zone_type")]
#[serde(deny_unknown_fields)]
/// Enumeration over each zone type's configuration.
pub enum ZoneTypeConfig {
    Primary(ServerZoneConfig),
    Secondary(ServerZoneConfig),
    External {
        /// Store configurations.  Note: we specify a default handler to get a Vec containing a
        /// StoreConfig::Default, which is used for authoritative file-based zones and legacy sqlite
        /// configurations. #[serde(default)] cannot be used, because it will invoke Default for Vec,
        /// i.e., an empty Vec and we cannot implement Default for StoreConfig and return a Vec.  The
        /// custom visitor is used to handle map (single store) or sequence (chained store) configurations.
        #[serde(default = "store_config_default")]
        #[serde(deserialize_with = "store_config_visitor")]
        stores: Vec<ExternalStoreConfig>,
    },
}

impl ZoneTypeConfig {
    pub fn as_server(&self) -> Option<&ServerZoneConfig> {
        match self {
            Self::Primary(c) | Self::Secondary(c) => Some(c),
            _ => None,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ServerZoneConfig {
    /// Allow AXFR (TODO: need auth)
    pub allow_axfr: Option<bool>,
    /// Keys for use by the zone
    #[cfg(feature = "__dnssec")]
    #[serde(default)]
    pub keys: Vec<dnssec::KeyConfig>,
    /// The kind of non-existence proof provided by the nameserver
    #[cfg(feature = "__dnssec")]
    pub nx_proof_kind: Option<NxProofKind>,
    /// Store configurations.  Note: we specify a default handler to get a Vec containing a
    /// StoreConfig::Default, which is used for authoritative file-based zones and legacy sqlite
    /// configurations. #[serde(default)] cannot be used, because it will invoke Default for Vec,
    /// i.e., an empty Vec and we cannot implement Default for StoreConfig and return a Vec.  The
    /// custom visitor is used to handle map (single store) or sequence (chained store) configurations.
    #[serde(default = "store_config_default")]
    #[serde(deserialize_with = "store_config_visitor")]
    pub stores: Vec<ServerStoreConfig>,
}

impl ServerZoneConfig {
    #[cfg(feature = "__dnssec")]
    async fn load_keys(
        &self,
        authority: &mut impl DnssecAuthority<Lookup = impl Send + Sync + Sized + 'static>,
        zone_name: &Name,
    ) -> Result<(), String> {
        if !self.is_dnssec_enabled() {
            return Ok(());
        }

        for key_config in &self.keys {
            key_config.load(authority, zone_name.clone()).await?;
        }

        info!("signing zone: {zone_name}");
        authority
            .secure_zone()
            .await
            .map_err(|err| format!("failed to sign zone {zone_name}: {err}"))?;

        Ok(())
    }

    /// path to the zone file, i.e. the base set of original records in the zone
    ///
    /// this is only used on first load, if dynamic update is enabled for the zone, then the journal
    /// file is the actual source of truth for the zone.
    pub fn file(&self) -> Option<&Path> {
        self.stores.iter().find_map(|store| match store {
            ServerStoreConfig::File(file_config) => Some(&*file_config.zone_file_path),
            #[cfg(feature = "sqlite")]
            ServerStoreConfig::Sqlite(sqlite_config) => Some(&*sqlite_config.zone_file_path),
            ServerStoreConfig::Default => None,
        })
    }

    /// enable AXFR transfers
    pub fn is_axfr_allowed(&self) -> bool {
        self.allow_axfr.unwrap_or(false)
    }

    /// declare that this zone should be signed, see keys for configuration of the keys for signing
    pub fn is_dnssec_enabled(&self) -> bool {
        cfg_if! {
            if #[cfg(feature = "__dnssec")] {
                !self.keys.is_empty()
            } else {
                false
            }
        }
    }
}

/// Enumeration over store types for secondary nameservers.
#[derive(Deserialize, Debug, Default)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ServerStoreConfig {
    /// File based configuration
    File(FileConfig),
    /// Sqlite based configuration file
    #[cfg(feature = "sqlite")]
    Sqlite(SqliteConfig),
    /// This is used by the configuration processing code to represent a deprecated or main-block config without an associated store.
    #[default]
    Default,
}

/// Enumeration over store types for external nameservers.
#[allow(clippy::large_enum_variant)]
#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
#[non_exhaustive]
pub enum ExternalStoreConfig {
    /// Blocklist configuration
    #[cfg(feature = "blocklist")]
    Blocklist(BlocklistConfig),
    /// Forwarding Resolver
    #[cfg(feature = "resolver")]
    Forward(ForwardConfig),
    /// Recursive Resolver
    #[cfg(feature = "recursor")]
    Recursor(Box<RecursiveConfig>),
    /// This is used by the configuration processing code to represent a deprecated or main-block config without an associated store.
    #[default]
    Default,
}

/// Create a default value for serde for store config enums.
fn store_config_default<S: Default>() -> Vec<S> {
    vec![Default::default()]
}

/// Custom serde visitor that can deserialize a map (single configuration store, expressed as a TOML
/// table) or sequence (chained configuration stores, expressed as a TOML array of tables.)
/// This is used instead of an untagged enum because serde cannot provide variant-specific error
/// messages when using an untagged enum.
fn store_config_visitor<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct MapOrSequence<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for MapOrSequence<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("map or sequence")
        }

        fn visit_seq<S>(self, seq: S) -> Result<Vec<T>, S::Error>
        where
            S: SeqAccess<'de>,
        {
            Deserialize::deserialize(de::value::SeqAccessDeserializer::new(seq))
        }

        fn visit_map<M>(self, map: M) -> Result<Vec<T>, M::Error>
        where
            M: MapAccess<'de>,
        {
            match Deserialize::deserialize(de::value::MapAccessDeserializer::new(map)) {
                Ok(seq) => Ok(vec![seq]),
                Err(e) => Err(e),
            }
        }
    }

    deserializer.deserialize_any(MapOrSequence::<T>(Default::default()))
}

/// Configuration for a TLS certificate
#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct TlsCertConfig {
    pub path: PathBuf,
    pub endpoint_name: Option<String>,
    pub private_key: PathBuf,
}

#[cfg(feature = "__tls")]
impl TlsCertConfig {
    /// Load a Certificate from the path (with rustls)
    pub fn load(&self, zone_dir: &Path) -> Result<Arc<dyn ResolvesServerCert>, String> {
        if self.path.extension().and_then(OsStr::to_str) != Some("pem") {
            return Err(format!(
                "unsupported certificate file format (expected `.pem` extension): {}",
                self.path.display()
            ));
        }

        let cert_path = zone_dir.join(&self.path);
        info!(
            "loading TLS PEM certificate chain from: {}",
            cert_path.display()
        );

        let cert_chain = CertificateDer::pem_file_iter(&cert_path)
            .map_err(|e| {
                format!(
                    "failed to read cert chain from {}: {e}",
                    cert_path.display()
                )
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                format!(
                    "failed to parse cert chain from {}: {e}",
                    cert_path.display()
                )
            })?;

        let key_extension = self.private_key.extension();
        let key = if key_extension.is_some_and(|ext| ext == "pem") {
            let key_path = zone_dir.join(&self.private_key);
            info!("loading TLS PKCS8 key from PEM: {}", key_path.display());
            PrivateKeyDer::from_pem_file(&key_path)
                .map_err(|e| format!("failed to read key from {}: {e}", key_path.display()))?
        } else if key_extension.is_some_and(|ext| ext == "der" || ext == "key") {
            let key_path = zone_dir.join(&self.private_key);
            info!("loading TLS PKCS8 key from DER: {}", key_path.display());

            let buf =
                fs::read(&key_path).map_err(|e| format!("error reading key from file: {e}"))?;
            PrivateKeyDer::try_from(buf).map_err(|e| format!("error parsing key DER: {e}"))?
        } else {
            return Err(format!(
                "unsupported private key file format (expected `.pem` or `.der` extension): {}",
                self.private_key.display()
            ));
        };

        let certified_key = CertifiedKey::from_der(cert_chain, key, &default_provider())
            .map_err(|err| format!("failed to read certificate and keys: {err:?}"))?;

        Ok(Arc::new(SingleCertAndKey::from(certified_key)))
    }
}

#[cfg(all(test, any(feature = "resolver", feature = "recursor")))]
mod tests {
    use super::*;

    #[cfg(feature = "recursor")]
    #[test]
    fn example_recursor_config() {
        toml::from_str::<Config>(include_str!(
            "../../tests/test-data/test_configs/example_recursor.toml"
        ))
        .unwrap();
    }

    #[cfg(feature = "resolver")]
    #[test]
    fn single_store_config_error_message() {
        match toml::from_str::<Config>(
            r#"[[zones]]
               zone = "."
               zone_type = "External"

               [zones.stores]
               ype = "forward""#,
        ) {
            Ok(val) => panic!("expected error value; got ok: {val:?}"),
            Err(e) => assert!(e.to_string().contains("missing field `type`")),
        }
    }

    #[cfg(feature = "resolver")]
    #[test]
    fn chained_store_config_error_message() {
        match toml::from_str::<Config>(
            r#"[[zones]]
               zone = "."
               zone_type = "External"

               [[zones.stores]]
               type = "forward"

               [[zones.stores.name_servers]]
               socket_addr = "8.8.8.8:53"
               protocol = "udp"
               trust_negative_responses = false

               [[zones.stores]]
               type = "forward"

               [[zones.stores.name_servers]]
               socket_addr = "1.1.1.1:53"
               rotocol = "udp"
               trust_negative_responses = false"#,
        ) {
            Ok(val) => panic!("expected error value; got ok: {val:?}"),
            Err(e) => assert!(dbg!(e).to_string().contains("unknown field `rotocol`")),
        }
    }

    #[cfg(feature = "resolver")]
    #[test]
    fn file_store_zone_file_path() {
        match toml::from_str::<Config>(
            r#"[[zones]]
               zone = "localhost"
               zone_type = "Primary"

               [zones.stores]
               type = "file"
               zone_file_path = "default/localhost.zone""#,
        ) {
            Ok(val) => {
                let ZoneTypeConfig::Primary(config) = &val.zones[0].zone_type_config else {
                    panic!("expected primary zone type");
                };

                assert_eq!(config.stores.len(), 1);
                assert!(matches!(
                        &config.stores[0],
                    ServerStoreConfig::File(FileConfig { zone_file_path }) if zone_file_path == Path::new("default/localhost.zone"),
                ));
            }
            Err(e) => panic!("expected successful parse: {e:?}"),
        }
    }
}
