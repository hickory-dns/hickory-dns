// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

extern crate chrono;
extern crate env_logger;
extern crate futures;
#[macro_use]
extern crate log;
extern crate tokio;
extern crate tokio_net;
extern crate trust_dns_client;
extern crate trust_dns_proto;
extern crate trust_dns_server;

#[cfg(feature = "dns-over-openssl")]
extern crate trust_dns_openssl;

mod server_harness;

use std::io::Write;
use std::net::*;
use std::str::FromStr;

use tokio::runtime::current_thread::Runtime;
use tokio_net::tcp::TcpStream as TokioTcpStream;
use tokio_net::udp::UdpSocket as TokioUdpSocket;

use trust_dns_client::client::*;
use trust_dns_client::op::ResponseCode;
use trust_dns_client::rr::*;
use trust_dns_client::tcp::TcpClientStream;
use trust_dns_client::udp::UdpClientStream;

// TODO: Needed for when TLS tests are added back
// #[cfg(feature = "dns-over-openssl")]
// use trust_dns_openssl::TlsClientStreamBuilder;

use server_harness::{named_test_harness, query_a};

#[test]
fn test_example_toml_startup() {
    named_test_harness("example.toml", |port, _, _| {
        let mut io_loop = Runtime::new().unwrap();
        let addr: SocketAddr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), port);
        let (stream, sender) = TcpClientStream::<TokioTcpStream>::new(addr);
        let (bg, mut client) = ClientFuture::new(Box::new(stream), sender, None);

        io_loop.spawn(bg);
        query_a(&mut io_loop, &mut client);

        // just tests that multiple queries work
        let addr: SocketAddr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), port);
        let (stream, sender) = TcpClientStream::<TokioTcpStream>::new(addr);
        let (bg, mut client) = ClientFuture::new(Box::new(stream), sender, None);

        io_loop.spawn(bg);
        query_a(&mut io_loop, &mut client);
    })
}

#[test]
fn test_ipv4_only_toml_startup() {
    named_test_harness("ipv4_only.toml", |port, _, _| {
        let mut io_loop = Runtime::new().unwrap();
        let addr: SocketAddr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), port);
        let (stream, sender) = TcpClientStream::<TokioTcpStream>::new(addr);
        let (bg, mut client) = ClientFuture::new(Box::new(stream), sender, None);

        io_loop.spawn(bg);

        // ipv4 should succeed
        query_a(&mut io_loop, &mut client);

        let addr: SocketAddr = SocketAddr::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).into(), port);
        let (stream, sender) = TcpClientStream::<TokioTcpStream>::new(addr);
        let (bg, mut client) = ClientFuture::new(Box::new(stream), sender, None);

        io_loop.spawn(bg);

        // ipv6 should fail
        let message = io_loop.block_on(client.query(
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
//     let mut io_loop = Runtime::new().unwrap();
//     let addr: SocketAddr = ("127.0.0.1", port).to_socket_addrs().unwrap().next().unwrap();
//     let (stream, sender) = TcpClientStream::new(addr);
//     let client = ClientFuture::new(stream, sender, None);
//     let mut client = io_loop.block_on(client).unwrap();
//
//     // ipv4 should fail
//     assert!(!query(&mut io_loop, client));
//
//     let addr: SocketAddr = ("::1", port).to_socket_addrs().unwrap().next().unwrap();
//     let (stream, sender) = TcpClientStream::new(addr);
//     let client = ClientFuture::new(stream, sender, None);
//     let mut client = io_loop.block_on(client).unwrap();
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
    named_test_harness("ipv4_and_ipv6.toml", |port, _, _| {
        let mut io_loop = Runtime::new().unwrap();
        let addr: SocketAddr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), port);
        let (stream, sender) = TcpClientStream::<TokioTcpStream>::new(addr);
        let (bg, mut client) = ClientFuture::new(Box::new(stream), sender, None);

        io_loop.spawn(bg);

        // ipv4 should succeed
        query_a(&mut io_loop, &mut client);

        let addr: SocketAddr = SocketAddr::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).into(), port);
        let (stream, sender) = TcpClientStream::<TokioTcpStream>::new(addr);
        let (bg, mut client) = ClientFuture::new(Box::new(stream), sender, None);

        io_loop.spawn(bg);

        // ipv6 should succeed
        query_a(&mut io_loop, &mut client);
    })
}

#[test]
fn test_nodata_where_name_exists() {
    named_test_harness("example.toml", |port, _, _| {
        let mut io_loop = Runtime::new().unwrap();
        let addr: SocketAddr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), port);
        let (stream, sender) = TcpClientStream::<TokioTcpStream>::new(addr);
        let (bg, mut client) = ClientFuture::new(Box::new(stream), sender, None);

        io_loop.spawn(bg);

        let msg = io_loop
            .block_on(client.query(
                Name::from_str("www.example.com.").unwrap(),
                DNSClass::IN,
                RecordType::SRV,
            ))
            .unwrap();
        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert!(msg.answers().is_empty());
    })
}

#[test]
fn test_nxdomain_where_no_name_exists() {
    named_test_harness("example.toml", |port, _, _| {
        let mut io_loop = Runtime::new().unwrap();
        let addr: SocketAddr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), port);
        let (stream, sender) = TcpClientStream::<TokioTcpStream>::new(addr);
        let (bg, mut client) = ClientFuture::new(Box::new(stream), sender, None);

        io_loop.spawn(bg);

        let msg = io_loop
            .block_on(client.query(
                Name::from_str("nxdomain.example.com.").unwrap(),
                DNSClass::IN,
                RecordType::SRV,
            ))
            .unwrap();
        assert_eq!(msg.response_code(), ResponseCode::NXDomain);
        assert!(msg.answers().is_empty());
    })
}

#[test]
fn test_server_continues_on_bad_data_udp() {
    named_test_harness("example.toml", |port, _, _| {
        let mut io_loop = Runtime::new().unwrap();
        let addr: SocketAddr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), port);
        let stream = UdpClientStream::<TokioUdpSocket>::new(addr);
        let (bg, mut client) = ClientFuture::connect(stream);

        io_loop.spawn(bg);

        query_a(&mut io_loop, &mut client);

        // Send a bad packet, this should get rejected by the server
        let raw_socket = UdpSocket::bind(SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0))
            .expect("couldn't bind raw");

        raw_socket
            .send_to(b"0xDEADBEEF", addr)
            .expect("raw send failed");

        // just tests that multiple queries work
        let addr: SocketAddr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), port);
        let stream = UdpClientStream::<TokioUdpSocket>::new(addr);
        let (bg, mut client) = ClientFuture::connect(stream);
        io_loop.spawn(bg);

        query_a(&mut io_loop, &mut client);
    })
}

#[test]
fn test_server_continues_on_bad_data_tcp() {
    named_test_harness("example.toml", |port, _, _| {
        let mut io_loop = Runtime::new().unwrap();
        let addr: SocketAddr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), port);
        let (stream, sender) = TcpClientStream::<TokioTcpStream>::new(addr);
        let (bg, mut client) = ClientFuture::new(Box::new(stream), sender, None);

        io_loop.spawn(bg);

        query_a(&mut io_loop, &mut client);

        // Send a bad packet, this should get rejected by the server
        let mut raw_socket = TcpStream::connect(addr).expect("couldn't bind raw");

        raw_socket
            .write_all(b"0xDEADBEEF")
            .expect("raw send failed");

        // just tests that multiple queries work
        let addr: SocketAddr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), port);
        let (stream, sender) = TcpClientStream::<TokioTcpStream>::new(addr);
        let (bg, mut client) = ClientFuture::new(Box::new(stream), sender, None);

        io_loop.spawn(bg);

        query_a(&mut io_loop, &mut client);
    })
}

#[test]
#[cfg(feature = "trust-dns-resolver")]
fn test_forward() {
    use server_harness::query_message;

    env_logger::init();

    named_test_harness("example_forwarder.toml", |port, _, _| {
        let mut io_loop = Runtime::new().unwrap();
        let addr: SocketAddr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), port);
        let (stream, sender) = TcpClientStream::<TokioTcpStream>::new(addr);
        let (bg, mut client) = ClientFuture::new(Box::new(stream), sender, None);

        io_loop.spawn(bg);
        let response = query_message(
            &mut io_loop,
            &mut client,
            Name::from_str("www.example.com").unwrap(),
            RecordType::A,
        );
        assert_eq!(
            *response.answers()[0].rdata().as_a().unwrap(),
            Ipv4Addr::new(93, 184, 216, 34)
        );

        // just tests that multiple queries work
        let addr: SocketAddr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), port);
        let (stream, sender) = TcpClientStream::<TokioTcpStream>::new(addr);
        let (bg, mut client) = ClientFuture::new(Box::new(stream), sender, None);

        io_loop.spawn(bg);
        let response = query_message(
            &mut io_loop,
            &mut client,
            Name::from_str("www.example.com").unwrap(),
            RecordType::A,
        );
        assert_eq!(
            *response.answers()[0].rdata().as_a().unwrap(),
            Ipv4Addr::new(93, 184, 216, 34)
        );
    })
}
