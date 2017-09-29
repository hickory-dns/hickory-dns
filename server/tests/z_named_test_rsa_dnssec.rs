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

use server_harness::{named_test_harness, query};

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

#[test]
fn test_rsa() {
    use trust_dns::logger;
    use log::LogLevel;
    logger::TrustDnsLogger::enable_logging(LogLevel::Debug);

    let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or(".".to_owned());
    let server_path = Path::new(&server_path);

    named_test_harness("all_supported_dnssec.toml", |port, _| {
        let mut io_loop = Core::new().unwrap();
        let addr: SocketAddr = ("127.0.0.1", port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
        let client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

        let trust_anchor = trust_anchor(
            &server_path.join("tests/named_test_configs/dnssec/rsa_2048.pem"),
            KeyFormat::Pem,
            Algorithm::RSASHA256,
        );
        let mut client = SecureClientHandle::with_trust_anchor(client, trust_anchor);

        assert!(query(&mut io_loop, &mut client));

        // just tests that multiple queries work
        let addr: SocketAddr = ("127.0.0.1", port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

        assert!(query(&mut io_loop, &mut client));
    })
}

#[test]
fn test_ed25519() {
    use trust_dns::logger;
    use log::LogLevel;
    logger::TrustDnsLogger::enable_logging(LogLevel::Debug);

    let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or(".".to_owned());
    let server_path = Path::new(&server_path);

    named_test_harness("all_supported_dnssec.toml", |port, _| {
        let mut io_loop = Core::new().unwrap();
        let addr: SocketAddr = ("127.0.0.1", port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
        let client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

        let trust_anchor = trust_anchor(
            &server_path.join("tests/named_test_configs/dnssec/ed25519.pk8"),
            KeyFormat::Pkcs8,
            Algorithm::ED25519,
        );
        let mut client = SecureClientHandle::with_trust_anchor(client, trust_anchor);

        assert!(query(&mut io_loop, &mut client));

        // just tests that multiple queries work
        let addr: SocketAddr = ("127.0.0.1", port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

        assert!(query(&mut io_loop, &mut client));
    })
}
