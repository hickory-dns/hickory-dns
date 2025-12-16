// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Configuration module for the server binary, `hickory-dns`.

#[cfg(feature = "__tls")]
use std::ffi::OsStr;
#[cfg(feature = "prometheus-metrics")]
use std::net::SocketAddr;
use std::{
    fmt, fs, io,
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[cfg(feature = "sqlite")]
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
use thiserror::Error;
use tracing::{debug, info};

#[cfg(feature = "__dnssec")]
use crate::dnssec;
#[cfg(feature = "__https")]
use hickory_net::http::DEFAULT_DNS_QUERY_PATH;
#[cfg(feature = "__tls")]
use hickory_net::rustls::default_provider;
use hickory_proto::{ProtoError, rr::Name, serialize::txt::ParseError};
#[cfg(feature = "recursor")]
use hickory_resolver::recursor::RecursiveConfig;
#[cfg(feature = "__dnssec")]
use hickory_server::dnssec::NxProofKind;
#[cfg(any(feature = "recursor", feature = "sqlite"))]
use hickory_server::net::runtime::TokioRuntimeProvider;
#[cfg(feature = "blocklist")]
use hickory_server::store::blocklist::{BlocklistConfig, BlocklistZoneHandler};
#[cfg(feature = "resolver")]
use hickory_server::store::forwarder::{ForwardConfig, ForwardZoneHandler};
#[cfg(feature = "recursor")]
use hickory_server::store::recursor::RecursiveZoneHandler;
#[cfg(feature = "sqlite")]
use hickory_server::store::sqlite::{SqliteConfig, SqliteZoneHandler};
use hickory_server::{
    store::file::{FileConfig, FileZoneHandler},
    zone_handler::{AxfrPolicy, ZoneHandler, ZoneType},
};

#[cfg(test)]
mod tests;

/// Server configuration
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// The list of IPv4 addresses to listen on
    #[serde(default)]
    pub(crate) listen_addrs_ipv4: Vec<Ipv4Addr>,
    /// This list of IPv6 addresses to listen on
    #[serde(default)]
    pub(crate) listen_addrs_ipv6: Vec<Ipv6Addr>,
    /// Port on which to listen (associated to all IPs)
    #[serde(default = "default_port")]
    pub(crate) listen_port: u16,
    /// Secure port to listen on
    #[cfg(feature = "__tls")]
    #[serde(default = "default_tls_port")]
    pub(crate) tls_listen_port: u16,
    /// HTTPS port to listen on
    #[cfg(feature = "__https")]
    #[serde(default = "default_https_port")]
    pub(crate) https_listen_port: u16,
    /// QUIC port to listen on
    #[cfg(feature = "__quic")]
    #[serde(default = "default_tls_port")]
    pub(crate) quic_listen_port: u16,
    /// Prometheus listen address
    #[cfg(feature = "prometheus-metrics")]
    pub(crate) prometheus_listen_addr: Option<SocketAddr>,
    /// Disable TCP protocol
    #[serde(default)]
    pub(crate) disable_tcp: bool,
    /// Disable UDP protocol
    #[serde(default)]
    pub(crate) disable_udp: bool,
    /// Disable TLS protocol
    #[cfg(feature = "__tls")]
    #[serde(default)]
    pub(crate) disable_tls: bool,
    /// Disable HTTPS protocol
    #[cfg(feature = "__https")]
    #[serde(default)]
    pub(crate) disable_https: bool,
    /// Disable QUIC protocol
    #[cfg(feature = "__quic")]
    #[serde(default)]
    pub(crate) disable_quic: bool,
    /// Disable Prometheus metrics
    #[cfg(feature = "prometheus-metrics")]
    #[serde(default)]
    pub(crate) disable_prometheus: bool,
    /// Timeout associated to a request before it is closed.
    #[serde(
        deserialize_with = "parse_request_timeout",
        default = "default_request_timeout"
    )]
    pub(crate) tcp_request_timeout: Duration,
    /// Whether to respect the SSLKEYLOGFILE environment variable.
    ///
    /// This should only be enabled WITH CARE! When enabled, and the SSLKEYLOGFILE environment
    /// variable is set, TLS session keys will be logged to the filepath specified by the
    /// environment variable value.
    ///
    /// This is principally useful for decrypting captured packet data with tools like Wireshark.
    #[cfg(feature = "__tls")]
    #[serde(default)]
    pub(crate) ssl_keylog_enabled: bool,
    /// Base configuration directory, i.e. root path for zones
    #[serde(default = "default_directory")]
    pub(crate) directory: PathBuf,
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
    pub(crate) zones: Vec<ZoneConfig>,
    /// Certificate to associate to TLS connections (currently the same is used for HTTPS and TLS)
    #[cfg(feature = "__tls")]
    pub(crate) tls_cert: Option<TlsCertConfig>,
    /// The HTTP endpoint where the DNS-over-HTTPS server provides service. Applicable
    /// to both HTTP/2 and HTTP/3 servers. Typically `/dns-query`.
    #[cfg(feature = "__https")]
    #[serde(default = "default_http_endpoint")]
    pub(crate) http_endpoint: String,
    /// Networks denied to access the server
    #[serde(default)]
    pub(crate) deny_networks: Vec<IpNet>,
    /// Networks allowed to access the server
    #[serde(default)]
    pub(crate) allow_networks: Vec<IpNet>,
}

impl Config {
    /// read a Config file from the file specified at path.
    pub(crate) fn read_config(path: &Path) -> Result<Self, ConfigError> {
        Self::from_toml(&fs::read_to_string(path)?)
    }

    /// Read a [`Config`] from the given TOML string.
    fn from_toml(toml: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(toml)?)
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
    D::Error: de::Error,
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
                        Err(<D::Error as de::Error>::custom(
                            "having `file` and `[zones.store]` item with type `file` is ambiguous",
                        ))
                    } else {
                        let store = ServerStoreConfig::File(FileConfig { zone_path: file });

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
                _ => Err(<D::Error as de::Error>::custom(
                    "cannot use `file` on a zone that is not primary or secondary",
                )),
            },

            _ => Ok(config),
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Configuration for a zone
#[derive(Deserialize, Debug)]
pub(crate) struct ZoneConfig {
    /// name of the zone
    pub zone: String, // TODO: make Domain::Name decodable
    /// type of the zone
    #[serde(flatten)]
    pub zone_type_config: ZoneTypeConfig,
}

impl ZoneConfig {
    pub(crate) async fn load(
        self,
        zone_dir: &Path,
    ) -> Result<Vec<Arc<dyn ZoneHandler>>, ProtoError> {
        debug!("loading zone with config: {self:#?}");

        let zone_name = self
            .zone()
            .map_err(|err| format!("failed to read zone name: {err}"))?;
        let zone_type = self.zone_type();

        // load the zone and insert any configured zone handlers in the catalog.

        let mut handlers: Vec<Arc<dyn ZoneHandler>> = vec![];
        match self.zone_type_config {
            ZoneTypeConfig::Primary(server_config) | ZoneTypeConfig::Secondary(server_config) => {
                debug!(
                    "loading zone handlers for {zone_name} with stores {:?}",
                    server_config.stores
                );

                let axfr_policy = server_config.axfr_policy();
                for store in &server_config.stores {
                    let handler: Arc<dyn ZoneHandler> = match store {
                        #[cfg(feature = "sqlite")]
                        ServerStoreConfig::Sqlite(config) => {
                            #[cfg_attr(not(feature = "__dnssec"), allow(unused_mut))]
                            let mut handler =
                                SqliteZoneHandler::<TokioRuntimeProvider>::try_from_config(
                                    zone_name.clone(),
                                    zone_type,
                                    axfr_policy,
                                    server_config.is_dnssec_enabled(),
                                    Some(zone_dir),
                                    config,
                                    #[cfg(feature = "__dnssec")]
                                    server_config.nx_proof_kind.clone(),
                                )
                                .await?;

                            #[cfg(feature = "__dnssec")]
                            dnssec::load_keys(&mut handler, &zone_name, &server_config.keys)
                                .await?;
                            Arc::new(handler)
                        }

                        ServerStoreConfig::File(config) => {
                            #[cfg_attr(not(feature = "__dnssec"), allow(unused_mut))]
                            let mut handler = FileZoneHandler::try_from_config(
                                zone_name.clone(),
                                zone_type,
                                axfr_policy,
                                Some(zone_dir),
                                config,
                                #[cfg(feature = "__dnssec")]
                                server_config.nx_proof_kind.clone(),
                            )?;

                            #[cfg(feature = "__dnssec")]
                            dnssec::load_keys(&mut handler, &zone_name, &server_config.keys)
                                .await?;
                            Arc::new(handler)
                        }
                        _ => return Err(ProtoError::from(EMPTY_STORES)),
                    };

                    handlers.push(handler);
                }
            }
            ZoneTypeConfig::External { stores } => {
                debug!(
                    "loading zone handlers for {zone_name} with stores {:?}",
                    stores
                );

                #[cfg_attr(
                    not(any(feature = "blocklist", feature = "resolver")),
                    allow(unreachable_code, unused_variables, clippy::never_loop)
                )]
                for store in stores {
                    let handler: Arc<dyn ZoneHandler> = match store {
                        #[cfg(feature = "blocklist")]
                        ExternalStoreConfig::Blocklist(config) => {
                            Arc::new(BlocklistZoneHandler::try_from_config(
                                zone_name.clone(),
                                config,
                                Some(zone_dir),
                            )?)
                        }
                        #[cfg(feature = "resolver")]
                        ExternalStoreConfig::Forward(config) => {
                            let forwarder = ForwardZoneHandler::builder_tokio(config)
                                .with_origin(zone_name.clone())
                                .build()?;

                            Arc::new(forwarder)
                        }
                        #[cfg(feature = "recursor")]
                        ExternalStoreConfig::Recursor(config) => {
                            let recursor = RecursiveZoneHandler::try_from_config(
                                zone_name.clone(),
                                zone_type,
                                &config,
                                Some(zone_dir),
                                TokioRuntimeProvider::default(),
                            )
                            .await?;

                            Arc::new(recursor)
                        }
                        _ => return Err(ProtoError::from(EMPTY_STORES)),
                    };

                    handlers.push(handler);
                }
            }
        }

        info!("zone successfully loaded: {zone_name}");
        Ok(handlers)
    }

    // TODO this is a little ugly for the parse, b/c there is no terminal char
    /// returns the name of the Zone, i.e. the `example.com` of `www.example.com.`
    pub(crate) fn zone(&self) -> Result<Name, ProtoError> {
        Name::parse(&self.zone, Some(&Name::new()))
    }

    /// the type of the zone
    fn zone_type(&self) -> ZoneType {
        match &self.zone_type_config {
            ZoneTypeConfig::Primary { .. } => ZoneType::Primary,
            ZoneTypeConfig::Secondary { .. } => ZoneType::Secondary,
            ZoneTypeConfig::External { .. } => ZoneType::External,
        }
    }
}

const EMPTY_STORES: &str = "empty [[zones.stores]] in config";

#[derive(Deserialize, Debug)]
#[serde(tag = "zone_type")]
#[serde(deny_unknown_fields)]
/// Enumeration over each zone type's configuration.
pub(crate) enum ZoneTypeConfig {
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
    #[cfg(test)]
    fn as_server(&self) -> Option<&ServerZoneConfig> {
        match self {
            Self::Primary(c) | Self::Secondary(c) => Some(c),
            _ => None,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerZoneConfig {
    /// A policy used to determine whether AXFR requests are allowed
    ///
    /// By default, all AXFR requests are rejected
    #[serde(default)]
    pub axfr_policy: AxfrPolicy,
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
    /// path to the zone file, i.e. the base set of original records in the zone
    ///
    /// this is only used on first load, if dynamic update is enabled for the zone, then the journal
    /// file is the actual source of truth for the zone.
    #[cfg(test)]
    fn file(&self) -> Option<&Path> {
        self.stores.iter().find_map(|store| match store {
            ServerStoreConfig::File(file_config) => Some(&*file_config.zone_path),
            #[cfg(feature = "sqlite")]
            ServerStoreConfig::Sqlite(sqlite_config) => Some(&*sqlite_config.zone_path),
            ServerStoreConfig::Default => None,
        })
    }

    /// Return a policy that can be used to determine how AXFR requests should be handled.
    fn axfr_policy(&self) -> AxfrPolicy {
        self.axfr_policy
    }

    /// declare that this zone should be signed, see keys for configuration of the keys for signing
    #[cfg(feature = "sqlite")]
    fn is_dnssec_enabled(&self) -> bool {
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
pub(crate) enum ServerStoreConfig {
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
pub(crate) enum ExternalStoreConfig {
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
    struct MapOrSequence<T>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for MapOrSequence<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
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

    deserializer.deserialize_any(MapOrSequence::<T>(PhantomData))
}

/// Configuration for a TLS certificate
#[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub(crate) struct TlsCertConfig {
    pub(crate) path: PathBuf,
    pub(crate) endpoint_name: Option<String>,
    pub(crate) private_key: PathBuf,
}

#[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
impl TlsCertConfig {
    /// Load a Certificate from the path (with rustls)
    pub(crate) fn load(&self, zone_dir: &Path) -> Result<Arc<dyn ResolvesServerCert>, String> {
        if let Some(endpoint_name) = &self.endpoint_name {
            info!("loading TLS cert for {endpoint_name} from {:?}", self.path);
        } else {
            info!("loading TLS cert from {:?}", self.path);
        }

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

/// The error kind for errors that get returned in the crate
#[derive(Debug, Error)]
#[non_exhaustive]
pub(crate) enum ConfigError {
    // foreign
    /// An error got returned from IO
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// An error occurred while decoding toml data
    #[error("toml decode error: {0}")]
    TomlDecode(#[from] toml::de::Error),

    /// An error occurred while parsing a zone file
    #[error("failed to parse the zone file: {0}")]
    ZoneParse(#[from] ParseError),
}

fn parse_request_timeout<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    Ok(Duration::from_secs(u64::deserialize(deserializer)?))
}

fn default_request_timeout() -> Duration {
    Duration::from_secs(5)
}

#[cfg(feature = "__https")]
fn default_http_endpoint() -> String {
    DEFAULT_DNS_QUERY_PATH.to_string()
}

fn default_directory() -> PathBuf {
    PathBuf::from("/var/named") // TODO what about windows (do I care? ;)
}

fn default_port() -> u16 {
    53
}

#[cfg(any(feature = "__tls", feature = "__quic"))]
fn default_tls_port() -> u16 {
    853
}

#[cfg(feature = "__https")]
fn default_https_port() -> u16 {
    443
}
