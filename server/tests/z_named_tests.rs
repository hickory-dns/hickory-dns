extern crate log;
extern crate trust_dns;
extern crate tokio_core;
extern crate openssl;

mod server_harness;

use std::env;
use std::fs::File;
use std::io::*;
use std::net::*;

use openssl::x509::X509;

use tokio_core::reactor::Core;

use trust_dns::client::*;
use trust_dns::tcp::TcpClientStream;
use trust_dns::tls::TlsClientStream;

use server_harness::{named_test_harness, query};

#[test]
fn test_example_toml_startup() {
    use trust_dns::logger;
    use log::LogLevel;
    logger::TrustDnsLogger::enable_logging(LogLevel::Debug);

    named_test_harness("example.toml", |port, _| {
        let mut io_loop = Core::new().unwrap();
        let addr: SocketAddr = ("127.0.0.1", port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

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
fn test_ipv4_only_toml_startup() {
    named_test_harness("ipv4_only.toml", |port, _| {
        let mut io_loop = Core::new().unwrap();
        let addr: SocketAddr = ("127.0.0.1", port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

        // ipv4 should succeed
        assert!(query(&mut io_loop, &mut client));

        let addr: SocketAddr = ("::1", port).to_socket_addrs().unwrap().next().unwrap();
        let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

        // ipv6 should fail
        assert!(!query(&mut io_loop, &mut client));
    })
}

// TODO: this is commented out b/c at least on macOS, ipv4 will route properly to ipv6 only
//  listeners over the [::ffff:127.0.0.1] interface
//
// #[ignore]
// #[test]
// fn test_ipv6_only_toml_startup() {
//   named_test_harness("ipv6_only.toml", |port, _| {
//     let mut io_loop = Core::new().unwrap();
//     let addr: SocketAddr = ("127.0.0.1", port).to_socket_addrs().unwrap().next().unwrap();
//     let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
//     let client = ClientFuture::new(stream, sender, &io_loop.handle(), None);
//
//     // ipv4 should fail
//     assert!(!query(&mut io_loop, client));
//
//     let addr: SocketAddr = ("::1", port).to_socket_addrs().unwrap().next().unwrap();
//     let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
//     let client = ClientFuture::new(stream, sender, &io_loop.handle(), None);
//
//     // ipv6 should succeed
//     assert!(query(&mut io_loop, client));
//
//     assert!(true);
//   })
// }

#[ignore]
#[test]
fn test_ipv4_and_ipv6_toml_startup() {
    named_test_harness("ipv4_and_ipv6.toml", |port, _| {
        let mut io_loop = Core::new().unwrap();
        let addr: SocketAddr = ("127.0.0.1", port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

        // ipv4 should succeed
        assert!(query(&mut io_loop, &mut client));

        let addr: SocketAddr = ("::1", port).to_socket_addrs().unwrap().next().unwrap();
        let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

        // ipv6 should succeed
        assert!(query(&mut io_loop, &mut client));

        assert!(true);
    })
}

#[test]
fn test_example_tls_toml_startup() {
    named_test_harness("dns_over_tls.toml", move |_, tls_port| {
        let mut cert_der = vec![];
        let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or(".".to_owned());
        println!("using server src path: {}", server_path);

        File::open(&format!(
            "{}/tests/named_test_configs/sec/example.cert",
            server_path
        )).unwrap()
            .read_to_end(&mut cert_der)
            .unwrap();

        let mut io_loop = Core::new().unwrap();
        let addr: SocketAddr = ("127.0.0.1", tls_port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let mut tls_conn_builder = TlsClientStream::builder();
        let cert = to_trust_anchor(&cert_der);
        tls_conn_builder.add_ca(cert);
        let (stream, sender) =
            tls_conn_builder.build(addr, "ns.example.com".to_string(), &io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

        // ipv4 should succeed
        assert!(query(&mut io_loop, &mut client));

        let addr: SocketAddr = ("127.0.0.1", tls_port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let mut tls_conn_builder = TlsClientStream::builder();
        let cert = to_trust_anchor(&cert_der);
        tls_conn_builder.add_ca(cert);
        let (stream, sender) =
            tls_conn_builder.build(addr, "ns.example.com".to_string(), &io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

        // ipv6 should succeed
        assert!(query(&mut io_loop, &mut client));

        assert!(true);
    })
}

fn to_trust_anchor(cert_der: &[u8]) -> X509 {
    X509::from_der(&cert_der).unwrap()
}
