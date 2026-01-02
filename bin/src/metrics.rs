// Copyright 2015-2026 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Metrics related to the hickory-dns server binary

use metrics::{Counter, Unit, counter, describe_counter, describe_gauge, gauge};

#[cfg(feature = "resolver")]
use crate::config::ExternalStoreConfig;
use crate::config::{Config, ServerStoreConfig, ServerZoneConfig, ZoneConfig, ZoneTypeConfig};

pub(super) struct ConfigMetrics {
    #[cfg(feature = "resolver")]
    zones_forwarder: Counter,
    zones_file_primary: Counter,
    zones_file_secondary: Counter,
    #[cfg(feature = "sqlite")]
    zones_sqlite_primary: Counter,
    #[cfg(feature = "sqlite")]
    zones_sqlite_secondary: Counter,
}

impl ConfigMetrics {
    pub(super) fn new(config: &Config) -> Self {
        let hickory_build_info =
            gauge!("hickory_build_info", "version" => env!("CARGO_PKG_VERSION"));
        describe_gauge!(
            "hickory_build_info",
            Unit::Count,
            "A metric with a constant '1' labeled by the version from which Hickory DNS was built."
        );
        hickory_build_info.set(1);

        #[cfg(feature = "__tls")]
        let disable_tls = config.disable_tls;
        #[cfg(not(feature = "__tls"))]
        let disable_tls = false;
        #[cfg(feature = "__https")]
        let disable_https = config.disable_https;
        #[cfg(not(feature = "__https"))]
        let disable_https = false;
        #[cfg(feature = "__quic")]
        let disable_quic = config.disable_quic;
        #[cfg(not(feature = "__quic"))]
        let disable_quic = false;

        let hickory_config_info = gauge!("hickory_config_info",
            "directory" => config.directory.to_string_lossy().to_string(),
            "disable_udp" => config.disable_udp.to_string(),
            "disable_tcp" => config.disable_tcp.to_string(),
            "disable_tls" => disable_tls.to_string(),
            "disable_https" => disable_https.to_string(),
            "disable_quic" => disable_quic.to_string(),
            "allow_networks" => config.allow_networks.len().to_string(),
            "deny_networks" => config.deny_networks.len().to_string(),
            "zones" => config.zones.len().to_string()
        );
        describe_gauge!(
            "hickory_config_info",
            Unit::Count,
            "Hickory DNS configuration metadata."
        );
        hickory_config_info.set(1);

        let zones_total_name = "hickory_zones_total";
        let zones_file_primary = counter!(zones_total_name, "store" => "file", "role" => "primary");
        let zones_file_secondary =
            counter!(zones_total_name, "store" => "file", "role" => "secondary");

        describe_counter!(
            zones_total_name,
            Unit::Count,
            "Number of DNS zones in stores."
        );

        #[cfg(feature = "resolver")]
        let zones_forwarder = counter!(zones_total_name, "store" => "forwarder");

        #[cfg(feature = "sqlite")]
        let (zones_sqlite_primary, zones_sqlite_secondary) = {
            let zones_primary_sqlite =
                counter!(zones_total_name, "store" => "sqlite", "role" => "primary");
            let zones_secondary_sqlite =
                counter!(zones_total_name, "store" => "sqlite", "role" => "secondary");
            (zones_primary_sqlite, zones_secondary_sqlite)
        };

        Self {
            #[cfg(feature = "resolver")]
            zones_forwarder,
            #[cfg(feature = "sqlite")]
            zones_sqlite_primary,
            zones_file_primary,
            #[cfg(feature = "sqlite")]
            zones_sqlite_secondary,
            zones_file_secondary,
        }
    }

    pub(super) fn increment_zone_metrics(&self, zone: &ZoneConfig) {
        match &zone.zone_type_config {
            ZoneTypeConfig::Primary(server_config) => self.increment_stores(server_config, true),
            ZoneTypeConfig::Secondary(server_config) => self.increment_stores(server_config, false),
            #[cfg_attr(not(feature = "resolver"), allow(unused_variables))]
            ZoneTypeConfig::External { stores } =>
            {
                #[cfg(feature = "resolver")]
                for store in stores {
                    if let ExternalStoreConfig::Forward(_) = store {
                        self.zones_forwarder.increment(1)
                    }
                }
            }
        }
    }

    fn increment_stores(&self, server_config: &ServerZoneConfig, primary: bool) {
        for store in &server_config.stores {
            if matches!(store, ServerStoreConfig::File(_)) {
                if primary {
                    self.zones_file_primary.increment(1)
                } else {
                    self.zones_file_secondary.increment(1)
                }
            }
            #[cfg(feature = "sqlite")]
            if matches!(store, ServerStoreConfig::Sqlite(_)) {
                if primary {
                    self.zones_sqlite_primary.increment(1)
                } else {
                    self.zones_sqlite_secondary.increment(1)
                }
            };
        }
    }
}
