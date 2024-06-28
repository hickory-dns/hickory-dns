#![cfg(feature = "dnssec")]
#![cfg(not(windows))]

mod server_harness;

use std::env;
use std::fs::File;
use std::io::Read;
use std::net::*;
use std::path::Path;
use std::sync::Arc;

use hickory_server::server::Protocol;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::runtime::Runtime;

use hickory_client::client::{Signer, *};
use hickory_client::proto::tcp::TcpClientStream;
use hickory_client::proto::DnssecDnsHandle;
use hickory_proto::rr::dnssec::*;
use hickory_proto::xfer::{DnsExchangeBackground, DnsMultiplexer};
use hickory_proto::{iocompat::AsyncIoTokioAsStd, TokioTime};

use server_harness::*;

#[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
fn confg_toml() -> &'static str {
    "openssl_dnssec.toml"
}

#[cfg(all(feature = "dnssec-ring", not(feature = "dnssec-openssl")))]
fn confg_toml() -> &'static str {
    "ring_dnssec.toml"
}

#[cfg(all(feature = "dnssec-ring", feature = "dnssec-openssl"))]
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
    let key_pair = format
        .decode_key(&buf, Some("123456"), algorithm)
        .expect("could not decode key");

    let public_key = key_pair.to_public_key().unwrap();
    let mut trust_anchor = TrustAnchor::new();

    trust_anchor.insert_trust_anchor(&public_key);
    Arc::new(trust_anchor)
}

#[allow(clippy::type_complexity)]
async fn standard_tcp_conn(
    port: u16,
) -> (
    AsyncClient,
    DnsExchangeBackground<
        DnsMultiplexer<TcpClientStream<AsyncIoTokioAsStd<TokioTcpStream>>, Signer>,
        TokioTime,
    >,
) {
    let addr: SocketAddr = ("127.0.0.1", port)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
    AsyncClient::new(stream, sender, None)
        .await
        .expect("new AsyncClient failed")
}

fn generic_test(config_toml: &str, key_path: &str, key_format: KeyFormat, algorithm: Algorithm) {
    // TODO: look into the `test-log` crate for enabling logging during tests
    // use hickory_client::logger;
    // use tracing::LogLevel;

    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    let server_path = Path::new(&server_path);

    named_test_harness(config_toml, |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);

        // verify all records are present
        let client = standard_tcp_conn(tcp_port.expect("no tcp port"));
        let (client, bg) = io_loop.block_on(client);
        hickory_proto::spawn_bg(&io_loop, bg);
        query_all_dnssec_with_rfc6975(&mut io_loop, client, algorithm);
        let client = standard_tcp_conn(tcp_port.expect("no tcp port"));
        let (client, bg) = io_loop.block_on(client);
        hickory_proto::spawn_bg(&io_loop, bg);
        query_all_dnssec_wo_rfc6975(&mut io_loop, client, algorithm);

        // test that request with Dnssec client is successful, i.e. validates chain
        let trust_anchor = trust_anchor(&server_path.join(key_path), key_format, algorithm);
        let client = standard_tcp_conn(tcp_port.expect("no tcp port"));
        let (client, bg) = io_loop.block_on(client);
        hickory_proto::spawn_bg(&io_loop, bg);
        let mut client = DnssecDnsHandle::with_trust_anchor(client, trust_anchor);

        query_a(&mut io_loop, &mut client);
    });
}

#[test]
#[cfg(feature = "dnssec-openssl")]
fn test_rsa_sha256() {
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/rsa_2048.pem",
        KeyFormat::Pem,
        Algorithm::RSASHA256,
    );
}

#[test]
#[cfg(feature = "dnssec-openssl")]
fn test_rsa_sha512() {
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/rsa_2048.pem",
        KeyFormat::Pem,
        Algorithm::RSASHA512,
    );
}

#[test]
#[cfg(feature = "dnssec-openssl")]
fn test_ecdsa_p256() {
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/ecdsa_p256.pem",
        KeyFormat::Pem,
        Algorithm::ECDSAP256SHA256,
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
#[cfg(feature = "dnssec-openssl")]
fn test_ecdsa_p384() {
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/ecdsa_p384.pem",
        KeyFormat::Pem,
        Algorithm::ECDSAP384SHA384,
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

#[cfg(feature = "dnssec-openssl")]
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
        "tests/test-data/test_configs/dnssec/rsa_2048.pem",
        KeyFormat::Pem,
        Algorithm::RSASHA256,
    );

    // after running the above test, the journal file should exist
    assert!(journal.exists());

    // and all dnssec tests should still pass
    generic_test(
        "dnssec_with_update.toml",
        "tests/test-data/test_configs/dnssec/rsa_2048.pem",
        KeyFormat::Pem,
        Algorithm::RSASHA256,
    );

    // and journal should still exist
    assert!(journal.exists());

    // cleanup...
    // TODO: fix journal path so that it doesn't leave the dir dirty... this might make windows an option after that
    std::fs::remove_file(&journal).expect("failed to cleanup after test");
}

#[cfg(feature = "dnssec-openssl")]
#[cfg(feature = "sqlite")]
#[test]
fn test_dnssec_restart_with_update_journal_dep() {
    // TODO: make journal path configurable, it should be in target/tests/...
    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    let server_path = Path::new(&server_path);
    let journal = server_path.join("tests/test-data/test_configs/example.com.jrnl");
    std::fs::remove_file(&journal).ok();

    generic_test(
        "dnssec_with_update_deprecated.toml",
        "tests/test-data/test_configs/dnssec/rsa_2048.pem",
        KeyFormat::Pem,
        Algorithm::RSASHA256,
    );

    // after running the above test, the journal file should exist
    assert!(journal.exists());

    // and all dnssec tests should still pass
    generic_test(
        "dnssec_with_update_deprecated.toml",
        "tests/test-data/test_configs/dnssec/rsa_2048.pem",
        KeyFormat::Pem,
        Algorithm::RSASHA256,
    );

    // and journal should still exist
    assert!(journal.exists());

    // cleanup...
    // TODO: fix journal path so that it doesn't leave the dir dirty... this might make windows an option after that
    std::fs::remove_file(&journal).expect("failed to cleanup after test");
}
