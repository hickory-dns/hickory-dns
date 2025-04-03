// Copyright 2015-2025 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashMap;
use std::net::*;
use std::thread;
use std::time::Duration;
use test_support::subscribe;

use prometheus_parse::{Scrape, Value};
use tokio::runtime::Runtime;

use crate::server_harness::{ServerProtocol, SocketPorts, named_test_harness};

#[test]
fn test_prometheus_endpoint_startup() {
    subscribe();

    named_test_harness("example_forwarder.toml", |socket_ports| {
        let io_loop = Runtime::new().unwrap();

        let metrics = &io_loop.block_on(fetch_parse_check_metrics(socket_ports));
        let none = HashMap::new();

        // check process metrics
        verify_metric(metrics, "process_cpu_seconds_total", &none, None);
        verify_metric(metrics, "process_max_fds", &none, None);
        verify_metric(metrics, "process_open_fds", &none, None);
        verify_metric(metrics, "process_resident_memory_bytes", &none, None);
        verify_metric(metrics, "process_start_time_seconds", &none, None);
        verify_metric(metrics, "process_virtual_memory_bytes", &none, None);

        #[cfg(not(windows))]
        {
            verify_metric(metrics, "process_virtual_memory_max_bytes", &none, None);
            verify_metric(metrics, "process_threads", &none, None);
        }

        // check config metrics
        let info = HashMap::from([("version", hickory_server::version())]);
        let config_info = HashMap::from([
            ("directory", "/var/named"),
            ("disable_https", "false"),
            ("disable_quic", "false"),
            ("disable_tcp", "false"),
            ("disable_tls", "false"),
            ("disable_udp", "false"),
            ("allow_networks", "0"), // move to separate counter hickory_config_allow_networks_total ?
            ("deny_networks", "0"), // move to separate counter hickory_config_deny_networks_total ?
            ("zones", "6"),         // redundant ?
        ]);
        verify_metric(metrics, "hickory_info", &info, Some(1f64));
        verify_metric(metrics, "hickory_config_info", &config_info, Some(1f64));

        let store_forwarder = HashMap::from([("store", "forwarder")]);
        verify_metric(metrics, "hickory_zones_total", &store_forwarder, Some(1f64));

        let store_file_primary = HashMap::from([("store", "file"), ("role", "primary")]);
        let store_file_secondary = HashMap::from([("store", "file"), ("role", "secondary")]);
        verify_metric(
            metrics,
            "hickory_zones_total",
            &store_file_primary,
            Some(5f64),
        );
        verify_metric(
            metrics,
            "hickory_zones_total",
            &store_file_secondary,
            Some(0f64),
        );

        #[cfg(feature = "sqlite")]
        {
            let store_sqlite_primary = HashMap::from([("store", "sqlite"), ("role", "primary")]);
            let store_sqlite_secondary =
                HashMap::from([("store", "sqlite"), ("role", "secondary")]);
            verify_metric(
                metrics,
                "hickory_zones_total",
                &store_sqlite_primary,
                Some(0f64),
            );
            verify_metric(
                metrics,
                "hickory_zones_total",
                &store_sqlite_secondary,
                Some(0f64),
            );
        }

        // check store metrics
        // forwarder store only has QueryStoreMetrics
        // sqlite store not initialized within example_forwarder.toml
        let store_file = HashMap::from([("store", "file")]);
        verify_metric(
            metrics,
            "hickory_zone_records_total",
            &store_file,
            Some(14f64),
        );

        let store_file_success = HashMap::from([("store", "file"), ("success", "true")]);
        let store_file_failed = HashMap::from([("store", "file"), ("success", "false")]);

        let store_forwarder_success = HashMap::from([("store", "forwarder"), ("success", "true")]);
        let store_forwarder_failed = HashMap::from([("store", "forwarder"), ("success", "false")]);

        verify_metric(
            metrics,
            "hickory_zone_record_lookups_total",
            &store_file_success,
            Some(0f64),
        );
        verify_metric(
            metrics,
            "hickory_zone_record_lookups_total",
            &store_file_failed,
            Some(0f64),
        );
        verify_metric(
            metrics,
            "hickory_zone_record_lookups_total",
            &store_forwarder_success,
            Some(0f64),
        );
        verify_metric(
            metrics,
            "hickory_zone_record_lookups_total",
            &store_forwarder_failed,
            Some(0f64),
        );

        // sqlite store is not configured within example_forwarder.toml
        // therefore StoreMetrics for sqlite are not initialized

        // currently this feature returns is NotImpl, only functional with sqlite && dnssec feature
        // empty metrics available for file store as they are part of PersistentStoreMetrics
        // migrate to Option within PersistentStoreMetrics ?
        #[cfg(feature = "__dnssec")]
        {
            let mut store_file_dynamic_added = store_file.clone();
            store_file_dynamic_added.insert("operation", "added");
            let mut store_file_dynamic_deleted = store_file.clone();
            store_file_dynamic_deleted.insert("operation", "deleted");
            let mut store_file_dynamic_updated = store_file.clone();
            store_file_dynamic_updated.insert("operation", "updated");

            verify_metric(
                metrics,
                "hickory_zone_records_dynamically_modified_total",
                &store_file_dynamic_added,
                Some(0f64),
            );
            verify_metric(
                metrics,
                "hickory_zone_records_dynamically_modified_total",
                &store_file_dynamic_deleted,
                Some(0f64),
            );
            verify_metric(
                metrics,
                "hickory_zone_records_dynamically_modified_total",
                &store_file_dynamic_updated,
                Some(0f64),
            );
        }
    })
}

async fn fetch_parse_check_metrics(socket_ports: SocketPorts) -> Scrape {
    let prometheus_port = socket_ports.get_v4(ServerProtocol::PrometheusMetrics);
    let addr = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        prometheus_port.expect("no prometheus_port"),
    ));

    // the collect interval for process metrics is set to 250ms
    // wait to avoid missing the process metrics
    thread::sleep(Duration::from_millis(300));

    // fetch from metrics from server
    let body = reqwest::get(format!("http://{}:{}/", addr.ip(), addr.port()))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let lines: Vec<_> = body.lines().map(|s| Ok(s.to_owned())).collect();
    let scrape = Scrape::parse(lines.into_iter()).unwrap();

    test_metrics_description_present(scrape.clone());
    scrape
}

fn test_metrics_description_present(scrape: Scrape) {
    let missing: Vec<String> = scrape
        .samples
        .into_iter()
        .filter_map(|s| {
            if !scrape.docs.contains_key(&s.metric) {
                Some(s.metric)
            } else {
                None
            }
        })
        .collect();

    assert_eq!(
        Vec::<String>::new(),
        missing,
        "due to missing metric descriptions"
    );
}

fn verify_metric(metrics: &Scrape, name: &str, labels: &HashMap<&str, &str>, value: Option<f64>) {
    let named: Vec<_> = metrics
        .samples
        .iter()
        .filter(|s| s.metric == name)
        .collect();

    assert!(!named.is_empty(), "failed locating metric: {}", name);

    let labeled: Vec<_> = named
        .iter()
        .filter(|s| {
            labels.len()
                == labels
                    .clone()
                    .into_iter()
                    .filter(|(k, v)| {
                        let label = s.labels.get(k);
                        label.is_some() && label.unwrap() == *v
                    })
                    .count()
        })
        .collect();

    assert_eq!(
        labeled.len(),
        1,
        "locating metric: {}, labels: {:?}",
        name,
        labels
    );

    if let Some(value) = value {
        labeled.iter().for_each(|s| match s.value {
            Value::Counter(v) | Value::Gauge(v) | Value::Untyped(v) => {
                println!(
                    "checking metric: {}, labels: {}, value: {}",
                    s.metric, s.labels, v
                );
                assert_eq!(
                    v, value,
                    "checking metric: {}, labels: {}, value: {}",
                    s.metric, s.labels, v
                )
            }
            Value::Histogram(_) | Value::Summary(_) => {
                panic!("metric type check not supported")
            }
        })
    }
}
