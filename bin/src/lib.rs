mod config;
pub use config::{
    Config, ConfigError, ExternalStoreConfig, ServerStoreConfig, ServerZoneConfig, TlsCertConfig,
    ZoneConfig, ZoneTypeConfig,
};

#[cfg(feature = "__dnssec")]
pub mod dnssec;

#[cfg(feature = "prometheus-metrics")]
mod prometheus_server;
#[cfg(feature = "prometheus-metrics")]
pub use prometheus_server::PrometheusServer;
