#![cfg(feature = "__dnssec")]
#![cfg(not(windows))]

use std::env;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use tokio::runtime::Runtime;

use crate::server_harness::{named_test_harness, query_a, query_all_dnssec};
use hickory_client::client::Client;
use hickory_dns::dnssec::key_from_file;
use hickory_proto::dnssec::{Algorithm, DnssecDnsHandle, TrustAnchor};
use hickory_proto::runtime::{RuntimeProvider, TokioRuntimeProvider, TokioTime};
use hickory_proto::tcp::TcpClientStream;
use hickory_proto::xfer::{DnsExchangeBackground, DnsMultiplexer, Protocol};
use test_support::subscribe;

#[cfg(feature = "__dnssec")]
fn confg_toml() -> &'static str {
    "all_supported_dnssec.toml"
}

fn trust_anchor(public_key_path: &Path, algorithm: Algorithm) -> Arc<TrustAnchor> {
    let key_pair = key_from_file(public_key_path, algorithm).unwrap();
    let public_key = key_pair.to_public_key().unwrap();
    let mut trust_anchor = TrustAnchor::new();

    trust_anchor.insert_trust_anchor(&public_key);
    Arc::new(trust_anchor)
}

#[allow(clippy::type_complexity)]
async fn standard_tcp_conn<P: RuntimeProvider>(
    port: u16,
    provider: P,
) -> (
    Client,
    DnsExchangeBackground<DnsMultiplexer<TcpClientStream<P::Tcp>>, TokioTime>,
) {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let (stream, sender) = TcpClientStream::new(addr, None, None, provider);
    Client::new(stream, sender, None)
        .await
        .expect("new Client failed")
}

fn generic_test(config_toml: &str, key_path: &str, algorithm: Algorithm) {
    // TODO: look into the `test-log` crate for enabling logging during tests
    // use hickory_client::logger;
    // use tracing::LogLevel;

    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    let server_path = Path::new(&server_path);
    let provider = TokioRuntimeProvider::new();

    named_test_harness(config_toml, |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);

        // verify all records are present
        let client = standard_tcp_conn(tcp_port.expect("no tcp port"), provider.clone());
        let (client, bg) = io_loop.block_on(client);
        hickory_proto::runtime::spawn_bg(&io_loop, bg);
        query_all_dnssec(&mut io_loop, client, algorithm);

        // test that request with Dnssec client is successful, i.e. validates chain
        let trust_anchor = trust_anchor(&server_path.join(key_path), algorithm);
        let client = standard_tcp_conn(tcp_port.expect("no tcp port"), provider);
        let (client, bg) = io_loop.block_on(client);
        hickory_proto::runtime::spawn_bg(&io_loop, bg);
        let mut client = DnssecDnsHandle::with_trust_anchor(client, trust_anchor);

        query_a(&mut io_loop, &mut client);
    });
}

#[test]
#[cfg(feature = "__dnssec")]
fn test_rsa_sha256_pkcs8() {
    subscribe();
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/rsa_2048.pk8",
        Algorithm::RSASHA256,
    );
}

#[test]
#[cfg(feature = "__dnssec")]
fn test_rsa_sha512_pkcs8() {
    subscribe();
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/rsa_2048.pk8",
        Algorithm::RSASHA512,
    );
}

#[test]
#[cfg(feature = "__dnssec")]
fn test_ecdsa_p256_pkcs8() {
    subscribe();
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/ecdsa_p256.pk8",
        Algorithm::ECDSAP256SHA256,
    );
}

#[test]
#[cfg(feature = "__dnssec")]
fn test_ecdsa_p384_pkcs8() {
    subscribe();
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/ecdsa_p384.pk8",
        Algorithm::ECDSAP384SHA384,
    );
}

#[test]
#[cfg(feature = "__dnssec")]
fn test_ed25519() {
    subscribe();
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/ed25519.pk8",
        Algorithm::ED25519,
    );
}

#[test]
#[should_panic]
#[allow(deprecated)]
fn test_rsa_sha1_fails() {
    subscribe();
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/rsa_2048.pem",
        Algorithm::RSASHA1,
    );
}

#[cfg(feature = "__dnssec")]
#[cfg(feature = "sqlite")]
#[test]
fn test_dnssec_restart_with_update_journal() {
    subscribe();

    // TODO: make journal path configurable, it should be in target/tests/...
    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    let server_path = Path::new(&server_path);
    let journal = server_path.join("tests/test-data/test_configs/example.com_dnssec_update.jrnl");
    std::fs::remove_file(&journal).ok();

    generic_test(
        "dnssec_with_update.toml",
        "tests/test-data/test_configs/dnssec/rsa_2048.pk8",
        Algorithm::RSASHA256,
    );

    // after running the above test, the journal file should exist
    assert!(journal.exists());

    // and all dnssec tests should still pass
    generic_test(
        "dnssec_with_update.toml",
        "tests/test-data/test_configs/dnssec/rsa_2048.pk8",
        Algorithm::RSASHA256,
    );

    // and journal should still exist
    assert!(journal.exists());

    // cleanup...
    // TODO: fix journal path so that it doesn't leave the dir dirty... this might make windows an option after that
    std::fs::remove_file(&journal).expect("failed to cleanup after test");
}
