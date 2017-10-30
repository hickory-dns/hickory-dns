extern crate chrono;
extern crate futures;
extern crate log;
extern crate trust_dns;
extern crate tokio_core;
extern crate trust_dns_proto;
extern crate trust_dns_server;

#[cfg(feature = "tls")]
extern crate trust_dns_openssl;

mod server_harness;

use std::net::*;
use std::str::FromStr;

use tokio_core::reactor::Core;

use trust_dns::client::*;
use trust_dns::rr::*;
use trust_dns::tcp::TcpClientStream;

// TODO: Needed for when TLS tests are added back
// #[cfg(feature = "tls")]
// use trust_dns_openssl::TlsClientStreamBuilder;

use server_harness::{named_test_harness, query_a};

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

        query_a(&mut io_loop, &mut client);

        // just tests that multiple queries work
        let addr: SocketAddr = ("127.0.0.1", port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

        query_a(&mut io_loop, &mut client);
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
        query_a(&mut io_loop, &mut client);

        let addr: SocketAddr = ("::1", port).to_socket_addrs().unwrap().next().unwrap();
        let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

        // ipv6 should fail
        let message = io_loop.run(client.query(
            Name::from_str("www.example.com").unwrap(),
            DNSClass::IN,
            RecordType::AAAA,
        ));
        assert!(message.is_err());
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
        query_a(&mut io_loop, &mut client);

        let addr: SocketAddr = ("::1", port).to_socket_addrs().unwrap().next().unwrap();
        let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

        // ipv6 should succeed
        query_a(&mut io_loop, &mut client);

        assert!(true);
    })
}

#[cfg(feature = "bug")]
// https://github.com/bluejekyll/trust-dns/issues/255
#[cfg(feature = "tls")]
#[test]
fn test_example_tls_toml_startup() {
    use std::env;
    use std::fs::File;
    use std::io::*;
    use trust_dns_openssl::TlsClientStreamBuilder;

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
        let mut tls_conn_builder = TlsClientStreamBuilder::new();
        tls_conn_builder.add_ca_der(&cert_der).unwrap();
        let (stream, sender) =
            tls_conn_builder.build(addr, "ns.example.com".to_string(), &io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

        // ipv4 should succeed
        query_a(&mut io_loop, &mut client);

        let addr: SocketAddr = ("127.0.0.1", tls_port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let mut tls_conn_builder = TlsClientStreamBuilder::new();
        tls_conn_builder.add_ca_der(&cert_der).unwrap();
        let (stream, sender) =
            tls_conn_builder.build(addr, "ns.example.com".to_string(), &io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

        // ipv6 should succeed
        query_a(&mut io_loop, &mut client);

        assert!(true);
    })
}
