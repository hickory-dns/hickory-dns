// Copyright 2015-2025 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::*;
use std::str::FromStr;
use std::time::Duration;
use test_support::subscribe;

use hickory_client::client::{Client, ClientHandle};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::tcp::TcpClientStream;
use hickory_proto::xfer::Protocol;
use prometheus_parse::{Scrape, Value};
use tokio::runtime::Runtime;

use crate::server_harness::{ServerProtocol, SocketPorts, named_test_harness};

#[test]
fn test_prometheus_endpoint_startup() {
    subscribe();

    named_test_harness("example_forwarder.toml", |socket_ports| {
        let io_loop = Runtime::new().unwrap();
        let metrics = &io_loop.block_on(fetch_parse_check_metrics(&socket_ports));

        // check process metrics
        verify_metric(metrics, "process_cpu_seconds_total", &[], None);
        verify_metric(metrics, "process_max_fds", &[], None);
        verify_metric(metrics, "process_open_fds", &[], None);
        verify_metric(metrics, "process_resident_memory_bytes", &[], None);
        verify_metric(metrics, "process_start_time_seconds", &[], None);
        verify_metric(metrics, "process_virtual_memory_bytes", &[], None);

        #[cfg(not(windows))]
        {
            verify_metric(metrics, "process_virtual_memory_max_bytes", &[], None);
            verify_metric(metrics, "process_threads", &[], None);
        }

        // check config metrics
        let info = [("version", hickory_server::version())];
        let config_info = [
            ("directory", "/var/named"),
            ("disable_https", "false"),
            ("disable_quic", "false"),
            ("disable_tcp", "false"),
            ("disable_tls", "false"),
            ("disable_udp", "false"),
            ("allow_networks", "0"), // move to separate counter hickory_config_allow_networks_total ?
            ("deny_networks", "0"), // move to separate counter hickory_config_deny_networks_total ?
            ("zones", "6"),         // redundant ?
        ];
        verify_metric(metrics, "hickory_info", &info, Some(1f64));
        verify_metric(metrics, "hickory_config_info", &config_info, Some(1f64));

        let store_forwarder = [("store", "forwarder")];
        verify_metric(metrics, "hickory_zones_total", &store_forwarder, Some(1f64));

        let store_file_primary = [("store", "file"), ("role", "primary")];
        let store_file_secondary = [("store", "file"), ("role", "secondary")];
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
            let store_sqlite_primary = [("store", "sqlite"), ("role", "primary")];
            let store_sqlite_secondary = [("store", "sqlite"), ("role", "secondary")];
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
        let store_file = [("store", "file")];
        verify_metric(
            metrics,
            "hickory_zone_records_total",
            &store_file,
            Some(14f64),
        );

        verify_metric(
            metrics,
            "hickory_zone_record_lookups_total",
            &STORE_FILE_SUCCESS,
            Some(0f64),
        );
        verify_metric(
            metrics,
            "hickory_zone_record_lookups_total",
            &STORE_FILE_FAILED,
            Some(0f64),
        );
        verify_metric(
            metrics,
            "hickory_zone_record_lookups_total",
            &STORE_FORWARDER_SUCCESS,
            Some(0f64),
        );
        verify_metric(
            metrics,
            "hickory_zone_record_lookups_total",
            &STORE_FORWARDER_FAILED,
            Some(0f64),
        );

        // sqlite store is not configured within example_forwarder.toml
        // therefore StoreMetrics for sqlite are not initialized

        // currently this feature returns is NotImpl, only functional with sqlite && dnssec feature
        // empty metrics available for file store as they are part of PersistentStoreMetrics
        // migrate to Option within PersistentStoreMetrics ?
        #[cfg(feature = "__dnssec")]
        {
            let store_file_dynamic_added = [("store", "file"), ("operation", "added")];
            let store_file_dynamic_deleted = [("store", "file"), ("operation", "deleted")];
            let store_file_dynamic_updated = [("store", "file"), ("operation", "updated")];

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

#[test]
fn test_request_response() {
    subscribe();

    named_test_harness("example_forwarder.toml", |socket_ports| {
        let io_loop = Runtime::new().unwrap();
        let metrics = &io_loop.block_on(async {
            let mut client = create_local_client(&socket_ports).await;
            let response = client
                .query(
                    Name::from_str("localhost.").unwrap(),
                    DNSClass::IN,
                    RecordType::A,
                )
                .await
                .unwrap();

            if let RData::A(addr) = response.answers()[0].data() {
                assert_eq!(*addr, A::new(127, 0, 0, 1));
            };

            fetch_parse_check_metrics(&socket_ports).await
        });

        // check request
        let request_operations = ["notify", "query", "status", "unknown", "update"];
        request_operations.iter().for_each(|op| {
            let value = if *op == "query" { 1f64 } else { 0f64 };
            let op = [("operation", *op)];
            verify_metric(
                metrics,
                "hickory_request_operations_total",
                &op,
                Some(value),
            )
        });

        let flags = ["aa", "ad", "cd", "ra", "rd", "tc"];
        flags.iter().for_each(|flag| {
            let value = if *flag == "rd" { 1f64 } else { 0f64 };
            let flag = [("flag", *flag)];
            verify_metric(metrics, "hickory_request_flags_total", &flag, Some(value))
        });

        let protocols = ["tcp", "udp"];
        protocols.iter().for_each(|proto| {
            let value = if *proto == "tcp" { 1f64 } else { 0f64 };
            let proto = [("protocol", *proto)];
            verify_metric(
                metrics,
                "hickory_request_protocols_total",
                &proto,
                Some(value),
            )
        });

        // check response
        let response_codes = vec![
            "bad_alg",
            "bad_cookie",
            "bad_key",
            "bad_mode",
            "bad_name",
            "bad_sig",
            "bad_time",
            "bad_trunc",
            "bad_vers",
            "form_error",
            "no_error",
            "not_auth",
            "not_imp",
            "not_zone",
            "nx_domain",
            "nx_rrset",
            "refused",
            "serv_fail",
            "unknown",
            "yx_domain",
            "yx_rrset",
        ];
        response_codes.iter().for_each(|code| {
            let value = if *code == "no_error" { 1f64 } else { 0f64 };
            let code = [("code", *code)];
            verify_metric(metrics, "hickory_response_codes_total", &code, Some(value))
        });

        flags.iter().for_each(|flag| {
            let value = if ["aa", "rd"].contains(flag) {
                1f64
            } else {
                0f64
            };
            let flag = [("flag", *flag)];
            verify_metric(metrics, "hickory_response_flags_total", &flag, Some(value))
        });

        // check store lookups
        verify_metric(
            metrics,
            "hickory_zone_record_lookups_total",
            &STORE_FILE_SUCCESS,
            Some(1f64),
        );
        verify_metric(
            metrics,
            "hickory_zone_record_lookups_total",
            &STORE_FILE_FAILED,
            Some(0f64),
        );
        verify_metric(
            metrics,
            "hickory_zone_record_lookups_total",
            &STORE_FORWARDER_SUCCESS,
            Some(0f64),
        );
        verify_metric(
            metrics,
            "hickory_zone_record_lookups_total",
            &STORE_FORWARDER_FAILED,
            Some(0f64),
        );
    })
}

async fn create_local_client(socket_ports: &SocketPorts) -> Client {
    let dns_port = socket_ports.get_v4(ServerProtocol::Dns(Protocol::Tcp));
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, dns_port.expect("no dns tcp port")));

    let (stream, sender) = TcpClientStream::new(addr, None, None, TokioRuntimeProvider::new());
    let client = Client::new(stream, sender, None);
    let (client, bg) = client.await.expect("connection failed");
    tokio::spawn(bg);
    client
}

async fn fetch_parse_check_metrics(socket_ports: &SocketPorts) -> Scrape {
    let prometheus_port = socket_ports.get_v4(ServerProtocol::PrometheusMetrics);
    let addr = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        prometheus_port.expect("no prometheus_port"),
    ));

    // the collect interval for process metrics is set to 1000ms
    // wait to avoid missing the process metrics
    tokio::time::sleep(Duration::from_millis(1000)).await;

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

fn verify_metric(metrics: &Scrape, name: &str, labels: &[(&str, &str)], value: Option<f64>) {
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
                    .iter()
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

const STORE_FILE_SUCCESS: [(&str, &str); 2] = [("store", "file"), ("success", "true")];
const STORE_FILE_FAILED: [(&str, &str); 2] = [("store", "file"), ("success", "false")];
const STORE_FORWARDER_SUCCESS: [(&str, &str); 2] = [("store", "forwarder"), ("success", "true")];
const STORE_FORWARDER_FAILED: [(&str, &str); 2] = [("store", "forwarder"), ("success", "false")];
