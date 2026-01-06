// Copyright 2015-2025 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[cfg(any(
    all(feature = "__dnssec", feature = "sqlite"),
    all(feature = "__tls", feature = "recursor", feature = "metrics")
))]
use std::fs;
#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
use std::{env, path::Path};
use std::{
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use prometheus_parse::{Scrape, Value};
#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
use rustls_pki_types::PrivatePkcs8KeyDer;
use tokio::time::sleep;

use crate::server_harness::{ServerProtocol, SocketPorts, TestServer};
#[cfg(feature = "blocklist")]
use hickory_net::NetError;
#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
use hickory_net::dnssec::DnssecDnsHandle;
use hickory_net::{
    client::{Client, ClientHandle},
    runtime::TokioRuntimeProvider,
    tcp::TcpClientStream,
    xfer::Protocol,
};
#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
use hickory_proto::dnssec::{
    Algorithm, SigSigner, SigningKey, TrustAnchors, crypto::RsaSigningKey, rdata::DNSKEY,
};
#[cfg(feature = "blocklist")]
use hickory_proto::op::DnsResponse;
#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
use hickory_proto::rr::Record;
use hickory_proto::{
    op::MessageSigner,
    rr::{
        DNSClass, Name, RData, RecordType,
        rdata::{A, name::PTR},
    },
};
#[cfg(all(feature = "__tls", feature = "recursor", feature = "metrics"))]
use hickory_resolver::metrics::opportunistic_encryption::{
    PROBE_ATTEMPTS_TOTAL, PROBE_BUDGET_TOTAL, PROBE_DURATION_SECONDS, PROBE_ERRORS_TOTAL,
    PROBE_SUCCESSES_TOTAL, PROBE_TIMEOUTS_TOTAL,
};
use test_support::subscribe;

use hickory_dns::metrics::{BUILD_INFO, CONFIG_INFO, ZONES_TOTAL};
#[cfg(all(feature = "recursor", feature = "__dnssec", feature = "metrics"))]
use hickory_resolver::metrics::recursor::{
    BOGUS_ANSWERS_TOTAL, INDETERMINATE_ANSWERS_TOTAL, INSECURE_ANSWERS_TOTAL, SECURE_ANSWERS_TOTAL,
};
#[cfg(feature = "recursor")]
use hickory_resolver::metrics::recursor::{
    CACHE_HIT_DURATION, CACHE_HIT_TOTAL, CACHE_MISS_DURATION, CACHE_MISS_TOTAL,
    OUTGOING_QUERIES_TOTAL,
};
#[cfg(feature = "blocklist")]
use hickory_server::metrics::blocklist;
use hickory_server::metrics::{
    REQUEST_DNS_CLASSES_TOTAL, REQUEST_FLAGS_TOTAL, REQUEST_OPERATIONS_TOTAL,
    REQUEST_PROTOCOLS_TOTAL, REQUEST_RECORD_TYPES_TOTAL, RESPONSE_CODES_TOTAL,
    RESPONSE_DNS_CLASSES_TOTAL, RESPONSE_FLAGS_TOTAL, RESPONSE_RECORD_TYPES_TOTAL,
    ZONE_LOOKUPS_TOTAL, ZONE_RECORDS_MODIFIED_TOTAL, ZONE_RECORDS_TOTAL,
};

#[tokio::test]
async fn test_prometheus_endpoint_startup() {
    subscribe();

    let server = TestServer::start("example_forwarder.toml");
    let metrics = &fetch_parse_check_metrics(&server.ports).await;

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
        ("deny_networks", "0"),  // move to separate counter hickory_config_deny_networks_total ?
        ("zones", "6"),          // redundant ?
    ];
    verify_metric(metrics, BUILD_INFO, &info, Some(1f64));
    verify_metric(metrics, CONFIG_INFO, &config_info, Some(1f64));

    let store_forwarder = [("store", "forwarder")];
    verify_metric(metrics, ZONES_TOTAL, &store_forwarder, Some(1f64));

    let store_file_primary = [("store", "file"), ("role", "primary")];
    let store_file_secondary = [("store", "file"), ("role", "secondary")];
    verify_metric(metrics, ZONES_TOTAL, &store_file_primary, Some(4f64));
    verify_metric(metrics, ZONES_TOTAL, &store_file_secondary, Some(1f64));

    #[cfg(feature = "sqlite")]
    {
        let store_sqlite_primary = [("store", "sqlite"), ("role", "primary")];
        let store_sqlite_secondary = [("store", "sqlite"), ("role", "secondary")];
        verify_metric(metrics, ZONES_TOTAL, &store_sqlite_primary, Some(0f64));
        verify_metric(metrics, ZONES_TOTAL, &store_sqlite_secondary, Some(0f64));
    }

    // check store metrics
    // forwarder store only has QueryStoreMetrics
    // sqlite store not initialized within example_forwarder.toml
    let store_file = [("store", "file")];
    verify_metric(metrics, ZONE_RECORDS_TOTAL, &store_file, Some(14f64));

    // check zone lookup metrics
    verify_metric(
        metrics,
        ZONE_LOOKUPS_TOTAL,
        &AUTHORITATIVE_PRIMARY_FILE_SUCCESS,
        Some(0f64),
    );
    verify_metric(
        metrics,
        ZONE_LOOKUPS_TOTAL,
        &AUTHORITATIVE_PRIMARY_FILE_FAILED,
        Some(0f64),
    );
    verify_metric(
        metrics,
        ZONE_LOOKUPS_TOTAL,
        &EXTERNAL_FORWARDED_FORWARDER_SUCCESS,
        Some(0f64),
    );
    verify_metric(
        metrics,
        ZONE_LOOKUPS_TOTAL,
        &EXTERNAL_FORWARDED_FORWARDER_FAILED,
        Some(0f64),
    );

    // sqlite store is not configured within example_forwarder.toml
    // therefore StoreMetrics for sqlite are not initialized

    // currently this feature returns is NotImpl, only functional with sqlite && dnssec feature
    // empty metrics available for file store as they are part of PersistentStoreMetrics
    // migrate to Option within PersistentStoreMetrics ?
    #[cfg(feature = "__dnssec")]
    {
        let store_file_added = [("store", "file"), ("operation", "added")];
        let store_file_deleted = [("store", "file"), ("operation", "deleted")];
        let store_file_updated = [("store", "file"), ("operation", "updated")];

        verify_metric(
            metrics,
            ZONE_RECORDS_MODIFIED_TOTAL,
            &store_file_added,
            Some(0f64),
        );
        verify_metric(
            metrics,
            ZONE_RECORDS_MODIFIED_TOTAL,
            &store_file_deleted,
            Some(0f64),
        );
        verify_metric(
            metrics,
            ZONE_RECORDS_MODIFIED_TOTAL,
            &store_file_updated,
            Some(0f64),
        );
    }

    verify_all_histograms_have_buckets(metrics);
}

#[tokio::test]
async fn test_request_response() {
    subscribe();

    let server = TestServer::start("example_forwarder.toml");
    let metrics = {
        let mut client = create_local_client(&server.ports, None).await;
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

        let response = client
            .query(
                Name::from_str("1.0.0.127.in-addr.arpa").unwrap(),
                DNSClass::IN,
                RecordType::PTR,
            )
            .await
            .unwrap();

        if let RData::PTR(ptr) = response.answers()[0].data() {
            assert_eq!(*ptr, PTR("localhost.".parse().unwrap()));
        };

        &fetch_parse_check_metrics(&server.ports).await
    };

    // check request
    let request_operations = ["notify", "query", "status", "unknown", "update"];
    request_operations.iter().for_each(|op| {
        let value = if *op == "query" { 2f64 } else { 0f64 };
        let op = [("operation", *op)];
        verify_metric(metrics, REQUEST_OPERATIONS_TOTAL, &op, Some(value))
    });

    let flags = ["aa", "ad", "cd", "ra", "rd", "tc"];
    flags.iter().for_each(|flag| {
        let value = if *flag == "rd" { 2f64 } else { 0f64 };
        let flag = [("flag", *flag)];
        verify_metric(metrics, REQUEST_FLAGS_TOTAL, &flag, Some(value))
    });

    let protocols = ["tcp", "udp"];
    protocols.iter().for_each(|proto| {
        let value = if *proto == "tcp" { 2f64 } else { 0f64 };
        let proto = [("protocol", *proto)];
        verify_metric(metrics, REQUEST_PROTOCOLS_TOTAL, &proto, Some(value))
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
        let value = if *code == "no_error" { 2f64 } else { 0f64 };
        let code = [("code", *code)];
        verify_metric(metrics, RESPONSE_CODES_TOTAL, &code, Some(value))
    });

    flags.iter().for_each(|flag| {
        let value = if ["aa", "rd"].contains(flag) {
            2f64
        } else {
            0f64
        };
        let flag = [("flag", *flag)];
        verify_metric(metrics, RESPONSE_FLAGS_TOTAL, &flag, Some(value))
    });

    // check zone lookup metrics
    verify_metric(
        metrics,
        ZONE_LOOKUPS_TOTAL,
        &AUTHORITATIVE_PRIMARY_FILE_SUCCESS,
        Some(1f64),
    );
    verify_metric(
        metrics,
        ZONE_LOOKUPS_TOTAL,
        &[
            ("type", "authoritative"),
            ("role", "secondary"),
            ("zone_handler", "file"),
            ("success", "true"),
        ],
        Some(1f64),
    );
    verify_metric(
        metrics,
        ZONE_LOOKUPS_TOTAL,
        &AUTHORITATIVE_PRIMARY_FILE_FAILED,
        Some(0f64),
    );
    verify_metric(
        metrics,
        ZONE_LOOKUPS_TOTAL,
        &EXTERNAL_FORWARDED_FORWARDER_SUCCESS,
        Some(0f64),
    );
    verify_metric(
        metrics,
        ZONE_LOOKUPS_TOTAL,
        &EXTERNAL_FORWARDED_FORWARDER_FAILED,
        Some(0f64),
    );

    let record_types = [
        "a",
        "aaaa",
        "aname",
        "any",
        "axfr",
        "caa",
        "cdnskey",
        "cds",
        "cert",
        "cname",
        "csync",
        "dnskey",
        "ds",
        "hinfo",
        "https",
        "ixfr",
        "key",
        "mx",
        "naptr",
        "ns",
        "nsec",
        "nsec3",
        "nsec3param",
        "null",
        "openpgpkey",
        "opt",
        "ptr",
        "rrsig",
        "sig",
        "soa",
        "srv",
        "sshfp",
        "svcb",
        "tlsa",
        "tsig",
        "txt",
        "unknown",
        "zero",
    ];
    record_types.iter().for_each(|r#type| {
        let value = if ["a", "ptr"].contains(r#type) {
            1f64
        } else {
            0f64
        };
        let r#type = [("type", *r#type)];
        for metric in [REQUEST_RECORD_TYPES_TOTAL, RESPONSE_RECORD_TYPES_TOTAL] {
            verify_metric(metrics, metric, &r#type, Some(value))
        }
    });

    let dns_classes = ["in", "ch", "hs", "none", "any", "unknown"];
    dns_classes.iter().for_each(|class| {
        let value = if *class == "in" { 2f64 } else { 0f64 };
        let class = [("class", *class)];
        for metric in [REQUEST_DNS_CLASSES_TOTAL, RESPONSE_DNS_CLASSES_TOTAL] {
            verify_metric(metrics, metric, &class, Some(value))
        }
    });

    verify_all_histograms_have_buckets(metrics);
}

#[tokio::test]
#[cfg(all(feature = "blocklist", feature = "metrics"))]
async fn test_blocklist_metrics() {
    subscribe();

    let server = TestServer::start("chained_blocklist.toml");
    let metrics = {
        let mut client = create_local_client(&server.ports, None).await;
        let response = retry_client_lookup(
            &mut client,
            Name::from_str("example.com.").unwrap(),
            DNSClass::IN,
            RecordType::A,
        )
        .await
        .unwrap();

        let RData::A(addr) = response.answers()[0].data() else {
            panic!("expected A record response");
        };
        assert_eq!(*addr, A::new(192, 0, 2, 1));

        // com. should be in the cache already and isn't on the test blocklists.
        let response = retry_client_lookup(
            &mut client,
            Name::from_str("com.").unwrap(),
            DNSClass::IN,
            RecordType::NS,
        )
        .await
        .unwrap();

        let RData::NS(_addr) = response.answers()[0].data() else {
            panic!("expected NS record response");
        };

        &fetch_parse_check_metrics(&server.ports).await
    };

    verify_metric(metrics, blocklist::ENTRIES_TOTAL, &[], Some(6.0));
    verify_metric(metrics, blocklist::BLOCKED_QUERIES_TOTAL, &[], Some(1.0));
    verify_metric(metrics, blocklist::QUERIES_TOTAL, &[], Some(2.0));
    verify_metric(metrics, blocklist::HITS_TOTAL, &[], Some(1.0));

    verify_all_histograms_have_buckets(metrics);
}

#[tokio::test]
#[cfg(all(feature = "blocklist", feature = "metrics"))]
async fn test_consulting_blocklist_metrics() {
    subscribe();

    let server = TestServer::start("consulting_blocklist.toml");
    let metrics = {
        let mut client = create_local_client(&server.ports, None).await;
        let response = retry_client_lookup(
            &mut client,
            Name::from_str("example.com.").unwrap(),
            DNSClass::IN,
            RecordType::A,
        )
        .await
        .unwrap();

        let RData::A(addr) = response.answers()[0].data() else {
            panic!("expected A record response");
        };
        assert!(*addr != A::new(192, 0, 2, 1));

        let response = retry_client_lookup(
            &mut client,
            Name::from_str("com.").unwrap(),
            DNSClass::IN,
            RecordType::NS,
        )
        .await
        .unwrap();

        let RData::NS(_addr) = response.answers()[0].data() else {
            panic!("expected NS record response");
        };

        &fetch_parse_check_metrics(&server.ports).await
    };

    verify_metric(metrics, blocklist::ENTRIES_TOTAL, &[], Some(6.0));
    verify_metric(metrics, blocklist::LOGGED_QUERIES_TOTAL, &[], Some(1.0));
    verify_metric(metrics, blocklist::QUERIES_TOTAL, &[], Some(2.0));
    verify_metric(metrics, blocklist::HITS_TOTAL, &[], Some(1.0));

    verify_all_histograms_have_buckets(metrics);
}

#[tokio::test]
#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
async fn test_updates() {
    subscribe();

    let server = TestServer::start("dnssec_with_update_2.toml");
    let metrics = {
        let rsa_key = include_bytes!("../../../tests/test-data/test_configs/dnssec/rsa_2048.pk8");
        let verify_algo = Algorithm::RSASHA256;
        let verify_key =
            RsaSigningKey::from_pkcs8(&PrivatePkcs8KeyDer::from(rsa_key.to_vec()), verify_algo)
                .unwrap();
        let mut trust_anchor = TrustAnchors::empty();
        trust_anchor.insert(&verify_key.to_public_key().unwrap());

        let origin: Name = Name::parse("example.com.", None).unwrap();

        let update_algo = Algorithm::RSASHA512;
        let update_key =
            RsaSigningKey::from_pkcs8(&PrivatePkcs8KeyDer::from(rsa_key.to_vec()), update_algo)
                .unwrap();
        let signer = SigSigner::dnssec(
            DNSKEY::from_key(&update_key.to_public_key().unwrap()),
            Box::new(update_key),
            origin.clone(),
            time::Duration::weeks(1).try_into().unwrap(),
        );

        let client = create_local_client(&server.ports, Some(Arc::new(signer))).await;
        let mut client = DnssecDnsHandle::with_trust_anchor(client, Arc::new(trust_anchor));

        let rrset_create = Record::from_rdata(
            Name::from_str("zzz.example.com").unwrap(),
            3600,
            RData::A(A::from(Ipv4Addr::LOCALHOST)),
        );
        client.create(rrset_create, origin.clone()).await.unwrap();

        let record_update = Record::from_rdata(
            Name::from_str("zzz.example.com").unwrap(),
            1800,
            RData::A(A::from(Ipv4Addr::LOCALHOST)),
        );
        client
            .append(record_update, origin.clone(), true)
            .await
            .unwrap();

        let rrset_delete = Record::from_rdata(
            Name::from_str("zzz.example.com").unwrap(),
            3600,
            RData::A(A::from(Ipv4Addr::LOCALHOST)),
        );
        client
            .delete_rrset(rrset_delete, origin.clone())
            .await
            .unwrap();

        &fetch_parse_check_metrics(&server.ports).await
    };

    verify_metric(
        metrics,
        REQUEST_OPERATIONS_TOTAL,
        &[("operation", "update")],
        Some(3f64),
    );
    // check updates lookups
    verify_metric(
        metrics,
        ZONE_RECORDS_MODIFIED_TOTAL,
        &[("store", "sqlite"), ("operation", "added")],
        Some(1f64),
    );
    verify_metric(
        metrics,
        ZONE_RECORDS_MODIFIED_TOTAL,
        &[("store", "sqlite"), ("operation", "deleted")],
        Some(1f64),
    );
    verify_metric(
        metrics,
        ZONE_RECORDS_MODIFIED_TOTAL,
        &[("store", "sqlite"), ("operation", "updated")],
        Some(1f64),
    );

    verify_all_histograms_have_buckets(metrics);

    // Clean up database.
    drop(server);
    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    let server_path = Path::new(&server_path);
    let database =
        server_path.join("tests/test-data/test_configs/example.com_dnssec_update_2.jrnl");
    fs::remove_file(&database).expect("failed to cleanup after test");
}

#[tokio::test]
#[cfg(all(feature = "__tls", feature = "recursor", feature = "metrics"))]
async fn test_opp_enc_metrics() {
    subscribe();

    // Note: we use 'example_recursor_opportunistic_enc_2' here to have a distinct state file
    // path to not conflict with the `named_rfc_9539_tests.rs` smoke test.
    let server = TestServer::start("example_recursor_opportunistic_enc_2.toml");
    let metrics = &{
        let mut client = create_local_client(&server.ports, None).await;

        // Note: this query is handled by a zone file, and not exercising the recursor.
        // We make the query principally to have a mechanism to wait until the server
        // finishes initialization.
        let response = client
            .query(
                Name::from_str("localhost.").unwrap(),
                DNSClass::IN,
                RecordType::A,
            )
            .await
            .unwrap();
        let RData::A(addr) = response.answers()[0].data() else {
            panic!("expected A record response");
        };
        assert_eq!(*addr, A::new(127, 0, 0, 1));

        fetch_parse_check_metrics(&server.ports).await
    };

    let tls_protocol = [("protocol", "tls")];
    // Note: we use `None` as the expected value for the following metrics because the probes
    // are attempted as background tasks, and we can't reliably predict their state as an
    // external observer. We only care that the metrics are present.
    verify_metric(metrics, PROBE_ATTEMPTS_TOTAL, &tls_protocol, None);
    verify_metric(metrics, PROBE_ERRORS_TOTAL, &tls_protocol, None);
    verify_metric(metrics, PROBE_TIMEOUTS_TOTAL, &tls_protocol, None);
    verify_metric(metrics, PROBE_SUCCESSES_TOTAL, &tls_protocol, None);
    verify_metric(metrics, PROBE_DURATION_SECONDS, &tls_protocol, None);
    // Note: unlike the other metrics, the budget is unlabelled and shared by all protocols.
    verify_metric(metrics, PROBE_BUDGET_TOTAL, &[], None);

    verify_all_histograms_have_buckets(metrics);

    drop(server);
    fs::remove_file("metrics_opp_enc_state.toml").expect("failed to cleanup after test");
}

#[tokio::test]
#[cfg(all(feature = "recursor", feature = "metrics"))]
async fn test_recursor_metrics() {
    subscribe();

    let server = TestServer::start("example_recursor.toml");
    let metrics = &{
        let mut client = create_local_client(&server.ports, None).await;

        for _ in 0..2 {
            let _ = client
                .query(
                    Name::from_str("example.com.").unwrap(),
                    DNSClass::IN,
                    RecordType::A,
                )
                .await;
        }

        fetch_parse_check_metrics(&server.ports).await
    };

    verify_metric(metrics, CACHE_MISS_TOTAL, &[], Some(1.0));
    verify_metric(metrics, CACHE_HIT_TOTAL, &[], Some(1.0));
    verify_metric(metrics, OUTGOING_QUERIES_TOTAL, &[], Some(3.0));

    // Query processing time is not predictable, so we use `None` here and
    // only verify the metrics exist, not what values the buckets contain.
    verify_metric(metrics, CACHE_HIT_DURATION, &[], None);
    verify_metric(metrics, CACHE_MISS_DURATION, &[], None);

    verify_all_histograms_have_buckets(metrics);
}

#[tokio::test]
#[cfg(all(feature = "recursor", feature = "__dnssec", feature = "metrics"))]
async fn test_recursor_dnssec_metrics() {
    subscribe();

    let server = TestServer::start("example_recursor_dnssec.toml");
    let metrics = &{
        let mut client = create_local_client(&server.ports, None).await;

        for _ in 0..2 {
            let _ = client
                .query(
                    Name::from_str("example.com.").unwrap(),
                    DNSClass::IN,
                    RecordType::A,
                )
                .await;
        }

        fetch_parse_check_metrics(&server.ports).await
    };

    verify_metric(metrics, CACHE_MISS_TOTAL, &[], Some(6.0));
    verify_metric(metrics, CACHE_HIT_TOTAL, &[], Some(2.0));
    verify_metric(metrics, OUTGOING_QUERIES_TOTAL, &[], Some(8.0));

    // Query processing time is not predictable, so we use `None` here and
    // only verify the metrics exist, not what values the buckets contain.
    verify_metric(metrics, CACHE_HIT_DURATION, &[], None);
    verify_metric(metrics, CACHE_MISS_DURATION, &[], None);

    // When validating DNSSEC, we should also see DNSSEC-specific metrics.
    verify_metric(metrics, SECURE_ANSWERS_TOTAL, &[], Some(3.0));
    verify_metric(metrics, INSECURE_ANSWERS_TOTAL, &[], Some(0.0));
    verify_metric(metrics, BOGUS_ANSWERS_TOTAL, &[], Some(0.0));
    verify_metric(metrics, INDETERMINATE_ANSWERS_TOTAL, &[], Some(0.0));

    verify_all_histograms_have_buckets(metrics);
}

async fn create_local_client(
    socket_ports: &SocketPorts,
    signer: Option<Arc<dyn MessageSigner>>,
) -> Client<TokioRuntimeProvider> {
    let dns_port = socket_ports.get_v4(ServerProtocol::Dns(Protocol::Tcp));
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, dns_port.expect("no dns tcp port")));

    let (future, sender) = TcpClientStream::new(addr, None, None, TokioRuntimeProvider::new());
    let (client, bg) = Client::new(future.await.expect("connection failed"), sender, signer);
    tokio::spawn(bg);
    client
}

async fn fetch_parse_check_metrics(socket_ports: &SocketPorts) -> Scrape {
    let prometheus_port = socket_ports.get_v4(ServerProtocol::PrometheusMetrics);
    let addr = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        prometheus_port.expect("no prometheus_port"),
    ));

    // the collect interval for process metrics is set to 1s
    // wait to avoid missing the process metrics
    sleep(Duration::from_secs(1)).await;

    // fetch from metrics from server
    let body = reqwest::get(format!("http://{}:{}/", addr.ip(), addr.port()))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let lines = body.lines().map(|s| Ok(s.to_owned())).collect::<Vec<_>>();
    let scrape = Scrape::parse(lines.into_iter()).unwrap();

    test_metrics_description_present(scrape.clone());
    scrape
}

fn test_metrics_description_present(scrape: Scrape) {
    let missing = scrape
        .samples
        .into_iter()
        .filter_map(|s| {
            let metric_name = &s.metric;

            // Check if metric has direct documentation, or for histogram sub-metrics,
            // if the base metric has documentation.
            if scrape.docs.contains_key(metric_name)
                || metric_name
                    .strip_suffix("_sum")
                    .is_some_and(|base_metric| scrape.docs.contains_key(base_metric))
                || metric_name
                    .strip_suffix("_count")
                    .is_some_and(|base_metric| scrape.docs.contains_key(base_metric))
            {
                return None;
            }

            Some(s.metric)
        })
        .collect::<Vec<String>>();

    assert_eq!(
        Vec::<String>::new(),
        missing,
        "due to missing metric descriptions"
    );
}

fn verify_metric(metrics: &Scrape, name: &str, labels: &[(&str, &str)], value: Option<f64>) {
    let named = metrics
        .samples
        .iter()
        .filter(|s| s.metric == name)
        .collect::<Vec<_>>();

    assert!(!named.is_empty(), "failed locating metric: {name}");

    let labeled = named
        .iter()
        .filter(|s| {
            labels.len()
                == labels
                    .iter()
                    .filter(|(k, v)| {
                        let Some(val) = s.labels.get(k) else {
                            return false;
                        };
                        val == *v
                    })
                    .count()
        })
        .collect::<Vec<_>>();

    assert_eq!(
        labeled.len(),
        1,
        "locating metric: {name}, labels: {labels:?}"
    );

    let Some(value) = value else { return };

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

/// Assert that all `hickory_` histograms are "true" histograms, not summaries.
///
/// By default, the `metrics` facade used by Hickory library crates creates
/// histograms as summaries. In order to get true histograms with discrete
/// buckets that can be aggregated we need to use `metrics-exporter-prometheus`
/// functionality from this `bin` crate to configure buckets.
///
/// Since it would be easy to forget doing this after adding a new histogram
/// to a library crate this test exists as a backstop.
fn verify_all_histograms_have_buckets(metrics: &Scrape) {
    let summaries = metrics
        .samples
        .iter()
        .filter_map(|sample| {
            // Skip metrics that aren't our own.
            if !sample.metric.starts_with("hickory_") {
                return None;
            }
            // Collect up metric names that are reporting Summary values.
            match &sample.value {
                Value::Summary(_) => Some(sample.metric.as_str()),
                _ => None,
            }
        })
        .count();

    // If this assertion is failing you need to update `PrometheusServer::new()` for
    // your new metric.
    assert_eq!(
        summaries, 0,
        "found {summaries} histogram metrics missing bucket configuration, exported as summaries",
    )
}

#[cfg(feature = "blocklist")]
async fn retry_client_lookup(
    client: &mut Client<TokioRuntimeProvider>,
    name: Name,
    class: DNSClass,
    rtype: RecordType,
) -> Result<DnsResponse, NetError> {
    let mut i = 0;
    loop {
        return match client.query(name.clone(), class, rtype).await {
            Ok(res) => Ok(res),
            Err(NetError::Timeout) if i < LOOKUP_RETRIES => {
                i += 1;
                sleep(Duration::from_secs(2)).await;
                continue;
            }
            Err(e) => Err(e),
        };
    }
}

const AUTHORITATIVE_PRIMARY_FILE_SUCCESS: [(&str, &str); 4] = [
    ("type", "authoritative"),
    ("role", "primary"),
    ("zone_handler", "file"),
    ("success", "true"),
];
const AUTHORITATIVE_PRIMARY_FILE_FAILED: [(&str, &str); 4] = [
    ("type", "authoritative"),
    ("role", "primary"),
    ("zone_handler", "file"),
    ("success", "false"),
];
const EXTERNAL_FORWARDED_FORWARDER_SUCCESS: [(&str, &str); 4] = [
    ("type", "external"),
    ("role", "forwarded"),
    ("zone_handler", "forwarder"),
    ("success", "true"),
];
const EXTERNAL_FORWARDED_FORWARDER_FAILED: [(&str, &str); 4] = [
    ("type", "external"),
    ("role", "forwarded"),
    ("zone_handler", "forwarder"),
    ("success", "false"),
];
#[cfg(feature = "blocklist")]
const LOOKUP_RETRIES: usize = 5;
