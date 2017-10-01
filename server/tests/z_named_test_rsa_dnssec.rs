extern crate futures;
extern crate log;
extern crate trust_dns;
extern crate tokio_core;
extern crate openssl;

mod server_harness;

use std::env;
use std::fs::File;
use std::path::Path;
use std::io::*;
use std::net::*;

use openssl::x509::X509;

use tokio_core::reactor::Core;

use trust_dns::client::*;
use trust_dns::tcp::TcpClientStream;
use trust_dns::tls::TlsClientStream;
use trust_dns::rr::dnssec::*;

use server_harness::*;


#[cfg(not(feature = "ring"))]
fn confg_toml() -> &'static str {
    "openssl_dnssec.toml"
}

#[cfg(feature = "ring")]
fn confg_toml() -> &'static str {
    "all_supported_dnssec.toml"
}

fn trust_anchor(public_key_path: &Path, format: KeyFormat, algorithm: Algorithm) -> TrustAnchor {
    let mut file = File::open(public_key_path).expect("key not found");
    let mut buf = Vec::<u8>::new();

    file.read_to_end(&mut buf).expect("could not read key");
    let key_pair = format.decode_key(&buf, Some("123456"), algorithm).expect(
        "could not decode key",
    );

    let public_key = key_pair.to_public_key().unwrap();
    let mut trust_anchor = TrustAnchor::new();

    trust_anchor.insert_trust_anchor(public_key);
    trust_anchor
}

fn standard_conn(port: u16, io_loop: &Core) -> BasicClientHandle {
    let addr: SocketAddr = ("127.0.0.1", port)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
    ClientFuture::new(stream, sender, &io_loop.handle(), None)
}

fn generic_test(key_path: &str, key_format: KeyFormat, algorithm: Algorithm) {
    // use trust_dns::logger;
    // use log::LogLevel;
    // logger::TrustDnsLogger::enable_logging(LogLevel::Debug);

    let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or(".".to_owned());
    let server_path = Path::new(&server_path);

    named_test_harness(confg_toml(), |port, _| {
        let mut io_loop = Core::new().unwrap();

        // verify all records are present
        let client = standard_conn(port, &io_loop);
        query_all_dnssec_with_rfc6975(&mut io_loop, client, algorithm);
        let client = standard_conn(port, &io_loop);
        query_all_dnssec_wo_rfc6975(&mut io_loop, client, algorithm);

        // test that request with Secure client is successful, i.e. validates chain
        let trust_anchor = trust_anchor(&server_path.join(key_path), key_format, algorithm);
        let client = standard_conn(port, &io_loop);
        let mut client = SecureClientHandle::with_trust_anchor(client, trust_anchor);

        query_a(&mut io_loop, &mut client);
    });
}

#[test]
fn test_rsa_sha256() {
    generic_test(
        "tests/named_test_configs/dnssec/rsa_2048.pem",
        KeyFormat::Pem,
        Algorithm::RSASHA256,
    );
}

#[test]
fn test_rsa_sha512() {
    generic_test(
        "tests/named_test_configs/dnssec/rsa_2048.pem",
        KeyFormat::Pem,
        Algorithm::RSASHA512,
    );
}

#[test]
#[cfg(feature = "ring")]
fn test_ed25519() {
    generic_test(
        "tests/named_test_configs/dnssec/ed25519.pk8",
        KeyFormat::Pkcs8,
        Algorithm::ED25519,
    );
}

#[test]
#[should_panic]
fn test_rsa_sha1_fails() {
    generic_test(
        "tests/named_test_configs/dnssec/rsa_2048.pem",
        KeyFormat::Pem,
        Algorithm::RSASHA1,
    );
}