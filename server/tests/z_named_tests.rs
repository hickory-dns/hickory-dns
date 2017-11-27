// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

extern crate chrono;
extern crate futures;
extern crate log;
extern crate tokio_core;
extern crate trust_dns;
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
use trust_dns::op::ResponseCode;
use trust_dns::tcp::TcpClientStream;

// TODO: Needed for when TLS tests are added back
// #[cfg(feature = "tls")]
// use trust_dns_openssl::TlsClientStreamBuilder;

use server_harness::{named_test_harness, query_a};

#[test]
fn test_example_toml_startup() {
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

#[test]
fn test_nodata_where_name_exists() {
    named_test_harness("example.toml", |port, _| {
        let mut io_loop = Core::new().unwrap();
        let addr: SocketAddr = ("127.0.0.1", port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

        let msg = io_loop
            .run(client.query(
                Name::from_str("www.example.com.").unwrap(),
                DNSClass::IN,
                RecordType::SRV,
            ))
            .unwrap();
        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert!(msg.answers().is_empty());
        assert!(true);
    })
}

#[test]
fn test_nxdomain_where_no_name_exists() {
    named_test_harness("example.toml", |port, _| {
        let mut io_loop = Core::new().unwrap();
        let addr: SocketAddr = ("127.0.0.1", port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

        let msg = io_loop
            .run(client.query(
                Name::from_str("nxdomain.example.com.").unwrap(),
                DNSClass::IN,
                RecordType::SRV,
            ))
            .unwrap();
        assert_eq!(msg.response_code(), ResponseCode::NXDomain);
        assert!(msg.answers().is_empty());
        assert!(true);
    })
}

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
        )).expect("failed to open cert")
            .read_to_end(&mut cert_der)
            .expect("failed to read cert");

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
