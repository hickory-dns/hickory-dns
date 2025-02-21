// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io::Write;
use std::net::*;
use std::str::FromStr;

use tokio::runtime::Runtime;

use crate::server_harness::{named_test_harness, query_a, query_a_refused};
use hickory_client::client::{Client, ClientHandle};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::tcp::TcpClientStream;
use hickory_proto::udp::UdpClientStream;
use hickory_proto::xfer::Protocol;
use test_support::subscribe;

#[test]
fn test_example_toml_startup() {
    subscribe();
    let provider = TokioRuntimeProvider::new();

    named_test_harness("example.toml", |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
        let (stream, sender) = TcpClientStream::new(addr, None, None, provider.clone());
        let client = Client::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);

        query_a(&mut io_loop, &mut client);

        // just tests that multiple queries work
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
        let (stream, sender) = TcpClientStream::new(addr, None, None, provider.clone());
        let client = Client::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);

        query_a(&mut io_loop, &mut client);
    })
}

#[test]
fn test_ipv4_only_toml_startup() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    named_test_harness("ipv4_only.toml", |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
        let (stream, sender) = TcpClientStream::new(addr, None, None, provider.clone());
        let client = Client::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);

        // ipv4 should succeed
        query_a(&mut io_loop, &mut client);

        let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
        let (stream, sender) = TcpClientStream::new(addr, None, None, provider.clone());
        let client = Client::new(Box::new(stream), sender, None);

        assert!(io_loop.block_on(client).is_err());
        //let (client, bg) = io_loop.block_on(client).expect("client failed to connect");
        //hickory_proto::runtime::spawn_bg(&io_loop, bg);

        // ipv6 should fail
        // FIXME: probably need to send something for proper test... maybe use JoinHandle in tokio 0.2
        // assert!(io_loop.block_on(client).is_err());
    })
}

// TODO: this is commented out b/c at least on macOS, ipv4 will route properly to ipv6 only
//  listeners over the [::ffff:127.0.0.1] interface
//
// #[ignore]
// #[test]
// fn test_ipv6_only_toml_startup() {
//   named_test_harness("ipv6_only.toml", |socket_ports| {
//     let mut io_loop = Runtime::new().unwrap();
//     let tcp_port = socket_ports.get_v4(Protocol::Tcp);
//     let addr: SocketAddr = ("127.0.0.1", port).to_socket_addrs().unwrap().next().unwrap();
//     let (stream, sender) = TcpClientStream::new(addr);
//     let client = AsyncClient::new(stream, sender, None);
//     let mut client = io_loop.block_on(client).unwrap();
//
//     // ipv4 should fail
//     assert!(!query(&mut io_loop, client));
//
//     let addr: SocketAddr = ("::1", port).to_socket_addrs().unwrap().next().unwrap();
//     let (stream, sender) = TcpClientStream::new(addr);
//     let client = AsyncClient::new(stream, sender, None);
//     let mut client = io_loop.block_on(client).unwrap();
//
//     // ipv6 should succeed
//     assert!(query(&mut io_loop, client));
//
//     assert!(true);
//   })
// }

#[test]
fn test_ipv4_and_ipv6_toml_startup() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    named_test_harness("ipv4_and_ipv6.toml", |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
        let (stream, sender) = TcpClientStream::new(addr, None, None, provider.clone());
        let client = Client::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);
        // ipv4 should succeed
        query_a(&mut io_loop, &mut client);

        let tcp_port = socket_ports.get_v6(Protocol::Tcp);
        let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
        let (stream, sender) = TcpClientStream::new(addr, None, None, provider.clone());
        let client = Client::new(Box::new(stream), sender, None);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);

        // ipv6 should succeed
        query_a(&mut io_loop, &mut client);
    })
}

#[test]
fn test_nodata_where_name_exists() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    named_test_harness("example.toml", |socket_ports| {
        let io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
        let (stream, sender) = TcpClientStream::new(addr, None, None, provider.clone());
        let client = Client::new(Box::new(stream), sender, None);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);

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
    subscribe();
    let provider = TokioRuntimeProvider::new();
    named_test_harness("example.toml", |socket_ports| {
        let io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
        let (stream, sender) = TcpClientStream::new(addr, None, None, provider.clone());
        let client = Client::new(Box::new(stream), sender, None);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);

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
    subscribe();
    let provider = TokioRuntimeProvider::new();
    named_test_harness("example.toml", |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let udp_port = socket_ports.get_v4(Protocol::Udp);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, udp_port.expect("no udp_port")));

        let stream = UdpClientStream::builder(addr, provider.clone()).build();
        let client = Client::connect(stream);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);

        query_a(&mut io_loop, &mut client);

        // Send a bad packet, this should get rejected by the server
        let raw_socket = UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0))
            .expect("couldn't bind raw");

        raw_socket
            .send_to(b"0xDEADBEEF", addr)
            .expect("raw send failed");

        // just tests that multiple queries work
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, udp_port.expect("no udp_port")));
        let stream = UdpClientStream::builder(addr, provider).build();
        let client = Client::connect(stream);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);

        query_a(&mut io_loop, &mut client);
    })
}

#[test]
fn test_server_continues_on_bad_data_tcp() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    named_test_harness("example.toml", |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
        let (stream, sender) = TcpClientStream::new(addr, None, None, provider.clone());
        let client = Client::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);

        query_a(&mut io_loop, &mut client);

        // Send a bad packet, this should get rejected by the server
        let mut raw_socket = TcpStream::connect(addr).expect("couldn't bind raw");

        raw_socket
            .write_all(b"0xDEADBEEF")
            .expect("raw send failed");

        // just tests that multiple queries work
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
        let (stream, sender) = TcpClientStream::new(addr, None, None, provider.clone());
        let client = Client::new(Box::new(stream), sender, None);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);

        query_a(&mut io_loop, &mut client);
    })
}

#[test]
#[cfg(feature = "resolver")]
fn test_forward() {
    use crate::server_harness::query_message;

    subscribe();
    let provider = TokioRuntimeProvider::new();

    named_test_harness("example_forwarder.toml", |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
        let (stream, sender) = TcpClientStream::new(addr, None, None, provider.clone());
        let client = Client::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);

        let response = query_message(
            &mut io_loop,
            &mut client,
            Name::from_str("www.example.com.").unwrap(),
            RecordType::A,
        )
        .unwrap();

        assert!(
            response
                .answers()
                .iter()
                .any(|record| record.data().as_a().is_some())
        );

        // just tests that multiple queries work
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
        let (stream, sender) = TcpClientStream::new(addr, None, None, provider.clone());
        let client = Client::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);

        let response = query_message(
            &mut io_loop,
            &mut client,
            Name::from_str("www.example.com.").unwrap(),
            RecordType::A,
        )
        .unwrap();
        assert!(
            response
                .answers()
                .iter()
                .any(|record| record.data().as_a().is_some())
        );
        assert!(!response.header().authoritative());
    })
}

#[test]
fn test_allow_networks_toml_startup() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    named_test_harness("example_allow_networks.toml", |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
        let (stream, sender) = TcpClientStream::new(addr, None, None, provider.clone());
        let client = Client::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);
        // ipv4 should succeed
        query_a(&mut io_loop, &mut client);

        let tcp_port = socket_ports.get_v6(Protocol::Tcp);
        let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
        let (stream, sender) = TcpClientStream::new(addr, None, None, provider.clone());
        let client = Client::new(Box::new(stream), sender, None);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);

        // ipv6 should succeed
        query_a(&mut io_loop, &mut client);
    })
}

#[test]
fn test_deny_networks_toml_startup() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    named_test_harness("example_deny_networks.toml", |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
        let (stream, sender) = TcpClientStream::new(addr, None, None, provider.clone());
        let client = Client::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);
        // ipv4 should be refused
        query_a_refused(&mut io_loop, &mut client);

        let tcp_port = socket_ports.get_v6(Protocol::Tcp);
        let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
        let (stream, sender) = TcpClientStream::new(addr, None, None, provider.clone());
        let client = Client::new(Box::new(stream), sender, None);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);

        // ipv6 should be refused
        query_a_refused(&mut io_loop, &mut client);
    })
}

#[test]
fn test_deny_allow_networks_toml_startup() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    named_test_harness("example_deny_allow_networks.toml", |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
        let (stream, sender) = TcpClientStream::new(addr, None, None, provider.clone());
        let client = Client::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);
        // ipv4 should succeed
        query_a(&mut io_loop, &mut client);

        let tcp_port = socket_ports.get_v6(Protocol::Tcp);
        let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
        let (stream, sender) = TcpClientStream::new(addr, None, None, provider.clone());
        let client = Client::new(Box::new(stream), sender, None);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);

        // ipv6 should be refused
        query_a_refused(&mut io_loop, &mut client);
    })
}
