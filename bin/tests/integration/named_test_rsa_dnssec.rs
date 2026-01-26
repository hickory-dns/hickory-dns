#![cfg(feature = "__dnssec")]
#![cfg(not(windows))]

use std::env;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use crate::server_harness::{TestServer, query_a, query_all_dnssec};
use futures_util::TryStreamExt;
use hickory_dns::dnssec::key_from_file;
use hickory_net::DnsHandle;
use hickory_net::client::Client;
use hickory_net::dnssec::DnssecDnsHandle;
use hickory_net::runtime::{RuntimeProvider, TokioRuntimeProvider};
use hickory_net::tcp::TcpClientStream;
use hickory_net::xfer::{DnsExchangeBackground, DnsMultiplexer, Protocol};
use hickory_proto::{
    dnssec::{Algorithm, TrustAnchors},
    op::{DnsRequestOptions, Query},
    rr::RecordType,
};
use test_support::subscribe;

#[cfg(feature = "__dnssec")]
fn confg_toml() -> &'static str {
    "all_supported_dnssec.toml"
}

fn trust_anchor(public_key_path: &Path, algorithm: Algorithm) -> Arc<TrustAnchors> {
    let key_pair = key_from_file(public_key_path, algorithm).unwrap();
    let public_key = key_pair.to_public_key().unwrap();
    let mut trust_anchor = TrustAnchors::empty();

    trust_anchor.insert(&public_key);
    Arc::new(trust_anchor)
}

async fn standard_tcp_conn<P: RuntimeProvider>(
    port: u16,
    provider: P,
) -> (
    Client<P>,
    DnsExchangeBackground<DnsMultiplexer<TcpClientStream<P::Tcp>>, P::Timer>,
) {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider);
    Client::<P>::new(future.await.expect("new Client failed"), sender)
}

async fn generic_test(config_toml: &str, key_path: &str, algorithm: Algorithm) {
    // TODO: look into the `test-log` crate for enabling logging during tests
    // use hickory_net::client::logger;
    // use tracing::LogLevel;

    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    let server_path = Path::new(&server_path);
    let provider = TokioRuntimeProvider::new();

    let server = TestServer::start(config_toml);
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    // verify all records are present
    let (client, bg) = standard_tcp_conn(tcp_port.expect("no tcp port"), provider.clone()).await;
    tokio::spawn(bg);
    query_all_dnssec(client, algorithm).await;

    // test that request with Dnssec client is successful, i.e. validates chain
    let trust_anchor = trust_anchor(&server_path.join(key_path), algorithm);
    let (client, bg) = standard_tcp_conn(tcp_port.expect("no tcp port"), provider).await;
    tokio::spawn(bg);
    let mut client = DnssecDnsHandle::with_trust_anchor(client, trust_anchor);

    query_a(&mut client).await;
}

#[tokio::test]
#[cfg(feature = "__dnssec")]
async fn test_rsa_sha256_pkcs8() {
    subscribe();
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/rsa_2048.pk8",
        Algorithm::RSASHA256,
    )
    .await;
}

#[tokio::test]
#[cfg(feature = "__dnssec")]
async fn test_rsa_sha512_pkcs8() {
    subscribe();
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/rsa_2048.pk8",
        Algorithm::RSASHA512,
    )
    .await;
}

#[tokio::test]
#[cfg(feature = "__dnssec")]
async fn test_ecdsa_p256_pkcs8() {
    subscribe();
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/ecdsa_p256.pk8",
        Algorithm::ECDSAP256SHA256,
    )
    .await;
}

#[tokio::test]
#[cfg(feature = "__dnssec")]
async fn test_ecdsa_p384_pkcs8() {
    subscribe();
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/ecdsa_p384.pk8",
        Algorithm::ECDSAP384SHA384,
    )
    .await;
}

#[tokio::test]
#[cfg(feature = "__dnssec")]
async fn test_ed25519() {
    subscribe();
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/ed25519.pk8",
        Algorithm::ED25519,
    )
    .await;
}

#[tokio::test]
#[should_panic]
#[allow(deprecated)]
async fn test_rsa_sha1_fails() {
    subscribe();
    generic_test(
        confg_toml(),
        "tests/test-data/test_configs/dnssec/rsa_2048.pem",
        Algorithm::RSASHA1,
    )
    .await;
}

#[cfg(feature = "__dnssec")]
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_dnssec_restart_with_update_journal() {
    subscribe();

    // TODO: make journal path configurable, it should be in target/tests/...
    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    let server_path = Path::new(&server_path);
    let journal = server_path.join("tests/test-data/test_configs/example.com_dnssec_update.jrnl");
    let _ = std::fs::remove_file(&journal);

    generic_test(
        "dnssec_with_update.toml",
        "tests/test-data/test_configs/dnssec/rsa_2048.pk8",
        Algorithm::RSASHA256,
    )
    .await;

    // after running the above test, the journal file should exist
    assert!(journal.exists());

    // and all dnssec tests should still pass
    generic_test(
        "dnssec_with_update.toml",
        "tests/test-data/test_configs/dnssec/rsa_2048.pk8",
        Algorithm::RSASHA256,
    )
    .await;

    // and journal should still exist
    assert!(journal.exists());

    // cleanup...
    // TODO: fix journal path so that it doesn't leave the dir dirty... this might make windows an option after that
    std::fs::remove_file(&journal).expect("failed to cleanup after test");
}

#[cfg(feature = "__dnssec")]
#[tokio::test]
async fn test_rrsig_ttl() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start(confg_toml());
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let mut options = DnsRequestOptions::default();
    options.use_edns = true;
    options.edns_set_dnssec_ok = true;

    {
        let client = standard_tcp_conn(tcp_port.expect("no tcp port"), provider.clone());
        let (client, bg) = client.await;
        tokio::spawn(bg);

        // query www.example.com. expected ttl is 86400.
        let query = Query::query("www.example.com.".parse().unwrap(), RecordType::A);
        let response = client
            .lookup(query, options)
            .try_next()
            .await
            .unwrap()
            .expect("Expected an answer");

        // check the ttl of all answers, of which at least one must be of type A and one
        // of type RRSIG
        let expected_ttl = 86400;
        for answer in response.answers() {
            println!("{answer}");
            assert_eq!(answer.ttl(), expected_ttl);
        }
        assert!(
            response
                .answers()
                .iter()
                .any(|answer| answer.record_type() == RecordType::A)
        );
        assert!(
            response
                .answers()
                .iter()
                .any(|answer| answer.record_type() == RecordType::RRSIG)
        );
    }

    {
        let client = standard_tcp_conn(tcp_port.expect("no tcp port"), provider.clone());
        let (client, bg) = client.await;
        tokio::spawn(bg);

        // query shortlived.example.com. expected ttl is 900.
        let query = Query::query("shortlived.example.com.".parse().unwrap(), RecordType::A);
        let response = client
            .lookup(query, options)
            .try_next()
            .await
            .unwrap()
            .expect("Expected an answer");

        // check the ttl of all answers, of which at least one must be of type A and one
        // of type RRSIG
        let expected_ttl = 900;
        for answer in response.answers() {
            println!("{answer}");
            assert_eq!(answer.ttl(), expected_ttl);
        }
        assert!(
            response
                .answers()
                .iter()
                .any(|answer| answer.record_type() == RecordType::A)
        );
        assert!(
            response
                .answers()
                .iter()
                .any(|answer| answer.record_type() == RecordType::RRSIG)
        );
    }
}
