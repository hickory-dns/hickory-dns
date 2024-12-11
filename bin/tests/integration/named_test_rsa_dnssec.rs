#![cfg(feature = "dnssec")]
#![cfg(not(windows))]

use std::env;
use std::fs::File;
use std::io::Read;
use std::net::*;
use std::path::Path;
use std::sync::Arc;

use tokio::runtime::Runtime;

use crate::server_harness::{
    named_test_harness, query_a, query_all_dnssec_with_rfc6975, query_all_dnssec_wo_rfc6975,
};
use hickory_client::client::Client;
use hickory_proto::dnssec::{decode_key, Algorithm, KeyFormat, TrustAnchor};
use hickory_proto::runtime::{RuntimeProvider, TokioRuntimeProvider, TokioTime};
use hickory_proto::tcp::TcpClientStream;
use hickory_proto::xfer::{DnsExchangeBackground, DnsMultiplexer, Protocol};
use hickory_proto::DnssecDnsHandle;

#[cfg(feature = "dnssec-ring")]
fn confg_toml() -> &'static str {
    "all_supported_dnssec.toml"
}

fn trust_anchor(
    public_key_path: &Path,
    format: KeyFormat,
    algorithm: Algorithm,
) -> Arc<TrustAnchor> {
    let mut file = File::open(public_key_path).expect("key not found");
    let mut buf = Vec::<u8>::new();

    file.read_to_end(&mut buf).expect("could not read key");
    let key_pair = decode_key(&buf, algorithm, format).expect("could not decode key");

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

fn generic_test(config_toml: &str, key_path: &str, key_format: KeyFormat, algorithm: Algorithm) {
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
        query_all_dnssec_with_rfc6975(&mut io_loop, client, algorithm);
        let client = standard_tcp_conn(tcp_port.expect("no tcp port"), provider.clone());
        let (client, bg) = io_loop.block_on(client);
        hickory_proto::runtime::spawn_bg(&io_loop, bg);
        query_all_dnssec_wo_rfc6975(&mut io_loop, client, algorithm);

        // test that request with Dnssec client is successful, i.e. validates chain
        let trust_anchor = trust_anchor(&server_path.join(key_path), key_format, algorithm);
        let client = standard_tcp_conn(tcp_port.expect("no tcp port"), provider);
        let (client, bg) = io_loop.block_on(client);
        hickory_proto::runtime::spawn_bg(&io_loop, bg);
        let mut client = DnssecDnsHandle::with_trust_anchor(client, trust_anchor);

        query_a(&mut io_loop, &mut client);
    });
}

#[test]
#[cfg(feature = "dnssec-ring")]
fn test_rsa_sha256_pkcs8() {
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/rsa_2048.pk8",
        KeyFormat::Pkcs8,
        Algorithm::RSASHA256,
    );
}

#[test]
#[cfg(feature = "dnssec-ring")]
fn test_rsa_sha512_pkcs8() {
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/rsa_2048.pk8",
        KeyFormat::Pkcs8,
        Algorithm::RSASHA512,
    );
}

#[test]
#[cfg(feature = "dnssec-ring")]
fn test_ecdsa_p256_pkcs8() {
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/ecdsa_p256.pk8",
        KeyFormat::Pkcs8,
        Algorithm::ECDSAP256SHA256,
    );
}

#[test]
#[cfg(feature = "dnssec-ring")]
fn test_ecdsa_p384_pkcs8() {
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/ecdsa_p384.pk8",
        KeyFormat::Pkcs8,
        Algorithm::ECDSAP384SHA384,
    );
}

#[test]
#[cfg(feature = "dnssec-ring")]
fn test_ed25519() {
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/ed25519.pk8",
        KeyFormat::Pkcs8,
        Algorithm::ED25519,
    );
}

#[test]
#[should_panic]
#[allow(deprecated)]
fn test_rsa_sha1_fails() {
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/rsa_2048.pem",
        KeyFormat::Pem,
        Algorithm::RSASHA1,
    );
}

#[cfg(feature = "dnssec-ring")]
#[cfg(feature = "sqlite")]
#[test]
fn test_dnssec_restart_with_update_journal() {
    // TODO: make journal path configurable, it should be in target/tests/...
    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    let server_path = Path::new(&server_path);
    let journal = server_path.join("tests/test-data/test_configs/example.com_dnssec_update.jrnl");
    std::fs::remove_file(&journal).ok();

    generic_test(
        "dnssec_with_update.toml",
        "tests/test-data/test_configs/dnssec/rsa_2048.pk8",
        KeyFormat::Pkcs8,
        Algorithm::RSASHA256,
    );

    // after running the above test, the journal file should exist
    assert!(journal.exists());

    // and all dnssec tests should still pass
    generic_test(
        "dnssec_with_update.toml",
        "tests/test-data/test_configs/dnssec/rsa_2048.pk8",
        KeyFormat::Pkcs8,
        Algorithm::RSASHA256,
    );

    // and journal should still exist
    assert!(journal.exists());

    // cleanup...
    // TODO: fix journal path so that it doesn't leave the dir dirty... this might make windows an option after that
    std::fs::remove_file(&journal).expect("failed to cleanup after test");
}
