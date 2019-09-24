#![cfg(feature = "dnssec")]
#![cfg(not(windows))]

extern crate futures;
#[macro_use]
extern crate log;
extern crate tokio;
extern crate tokio_tcp;
extern crate trust_dns;
extern crate trust_dns_proto;

mod server_harness;

use std::env;
use std::fs::File;
use std::io::*;
use std::net::*;
use std::path::Path;

use futures::Future;
use tokio::runtime::current_thread::Runtime;
use tokio_tcp::TcpStream as TokioTcpStream;

use trust_dns::client::*;
use trust_dns::proto::error::ProtoError;
use trust_dns::proto::tcp::{TcpClientConnect, TcpClientStream};
use trust_dns::proto::xfer::{
    DnsMultiplexer, DnsMultiplexerConnect, DnsMultiplexerSerialResponse, DnsResponse,
};
use trust_dns::rr::dnssec::*;

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

fn trust_anchor(public_key_path: &Path, format: KeyFormat, algorithm: Algorithm) -> TrustAnchor {
    let mut file = File::open(public_key_path).expect("key not found");
    let mut buf = Vec::<u8>::new();

    file.read_to_end(&mut buf).expect("could not read key");
    let key_pair = format
        .decode_key(&buf, Some("123456"), algorithm)
        .expect("could not decode key");

    let public_key = key_pair.to_public_key().unwrap();
    let mut trust_anchor = TrustAnchor::new();

    trust_anchor.insert_trust_anchor(&public_key);
    trust_anchor
}

#[allow(clippy::type_complexity)]
fn standard_conn(
    port: u16,
) -> (
    ClientFuture<
        DnsMultiplexerConnect<
            TcpClientConnect<TokioTcpStream>,
            TcpClientStream<TokioTcpStream>,
            Signer,
        >,
        DnsMultiplexer<TcpClientStream<TokioTcpStream>, Signer>,
        DnsMultiplexerSerialResponse,
    >,
    BasicClientHandle<impl Future<Output = Result<DnsResponse, ProtoError>>>,
) {
    let addr: SocketAddr = ("127.0.0.1", port)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let (stream, sender) = TcpClientStream::<TokioTcpStream>::new(addr);
    ClientFuture::new(stream, sender, None)
}

fn generic_test(config_toml: &str, key_path: &str, key_format: KeyFormat, algorithm: Algorithm) {
    // use trust_dns::logger;
    // use log::LogLevel;
    // logger::TrustDnsLogger::enable_logging(LogLevel::Debug);

    let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or_else(|_| ".".to_owned());
    let server_path = Path::new(&server_path);

    named_test_harness(config_toml, |port, _, _| {
        let mut io_loop = Runtime::new().unwrap();

        // verify all records are present
        let (bg, client) = standard_conn(port);
        io_loop.spawn(bg);
        query_all_dnssec_with_rfc6975(&mut io_loop, client, algorithm);
        let (bg, client) = standard_conn(port);
        io_loop.spawn(bg);
        query_all_dnssec_wo_rfc6975(&mut io_loop, client, algorithm);

        // test that request with Secure client is successful, i.e. validates chain
        let trust_anchor = trust_anchor(&server_path.join(key_path), key_format, algorithm);
        let (bg, client) = standard_conn(port);
        io_loop.spawn(bg);
        let mut client = SecureClientHandle::with_trust_anchor(client, trust_anchor);

        query_a(&mut io_loop, &mut client);
    });
}

#[test]
#[cfg(feature = "dnssec-openssl")]
fn test_rsa_sha256() {
    generic_test(
        confg_toml(),
        "tests/named_test_configs/dnssec/rsa_2048.pem",
        KeyFormat::Pem,
        Algorithm::RSASHA256,
    );
}

#[test]
#[cfg(feature = "dnssec-openssl")]
fn test_rsa_sha512() {
    generic_test(
        confg_toml(),
        "tests/named_test_configs/dnssec/rsa_2048.pem",
        KeyFormat::Pem,
        Algorithm::RSASHA512,
    );
}

#[test]
#[cfg(feature = "dnssec-openssl")]
fn test_ecdsa_p256() {
    generic_test(
        confg_toml(),
        "tests/named_test_configs/dnssec/ecdsa_p256.pem",
        KeyFormat::Pem,
        Algorithm::ECDSAP256SHA256,
    );
}

#[test]
#[cfg(feature = "dnssec-ring")]
fn test_ecdsa_p256_pkcs8() {
    generic_test(
        confg_toml(),
        "tests/named_test_configs/dnssec/ecdsa_p256.pk8",
        KeyFormat::Pkcs8,
        Algorithm::ECDSAP256SHA256,
    );
}

#[test]
#[cfg(feature = "dnssec-openssl")]
fn test_ecdsa_p384() {
    generic_test(
        confg_toml(),
        "tests/named_test_configs/dnssec/ecdsa_p384.pem",
        KeyFormat::Pem,
        Algorithm::ECDSAP384SHA384,
    );
}

#[test]
#[cfg(feature = "dnssec-ring")]
fn test_ecdsa_p384_pkcs8() {
    generic_test(
        confg_toml(),
        "tests/named_test_configs/dnssec/ecdsa_p384.pk8",
        KeyFormat::Pkcs8,
        Algorithm::ECDSAP384SHA384,
    );
}

#[test]
#[cfg(feature = "dnssec-ring")]
fn test_ed25519() {
    generic_test(
        confg_toml(),
        "tests/named_test_configs/dnssec/ed25519.pk8",
        KeyFormat::Pkcs8,
        Algorithm::ED25519,
    );
}

#[test]
#[should_panic]
fn test_rsa_sha1_fails() {
    generic_test(
        confg_toml(),
        "tests/named_test_configs/dnssec/rsa_2048.pem",
        KeyFormat::Pem,
        Algorithm::RSASHA1,
    );
}

#[cfg(feature = "dnssec-openssl")]
#[test]
fn test_dnssec_restart_with_update_journal() {
    // TODO: make journal path configurable, it should be in target/tests/...
    let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or_else(|_| ".".to_owned());
    let server_path = Path::new(&server_path);
    let journal = server_path.join("tests/named_test_configs/example.com_dnsec_update.jrnl");
    std::fs::remove_file(&journal).ok();

    generic_test(
        "dnssec_with_update.toml",
        "tests/named_test_configs/dnssec/rsa_2048.pem",
        KeyFormat::Pem,
        Algorithm::RSASHA256,
    );

    // after running the above test, the journal file should exist
    assert!(journal.exists());

    // and all dnssec tests should still pass
    generic_test(
        "dnssec_with_update.toml",
        "tests/named_test_configs/dnssec/rsa_2048.pem",
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
#[test]
fn test_dnssec_restart_with_update_journal_dep() {
    // TODO: make journal path configurable, it should be in target/tests/...
    let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or_else(|_| ".".to_owned());
    let server_path = Path::new(&server_path);
    let journal = server_path.join("tests/named_test_configs/example.com.jrnl");
    std::fs::remove_file(&journal).ok();

    generic_test(
        "dnssec_with_update_deprecated.toml",
        "tests/named_test_configs/dnssec/rsa_2048.pem",
        KeyFormat::Pem,
        Algorithm::RSASHA256,
    );

    // after running the above test, the journal file should exist
    assert!(journal.exists());

    // and all dnssec tests should still pass
    generic_test(
        "dnssec_with_update_deprecated.toml",
        "tests/named_test_configs/dnssec/rsa_2048.pem",
        KeyFormat::Pem,
        Algorithm::RSASHA256,
    );

    // and journal should still exist
    assert!(journal.exists());

    // cleanup...
    // TODO: fix journal path so that it doesn't leave the dir dirty... this might make windows an option after that
    std::fs::remove_file(&journal).expect("failed to cleanup after test");
}
