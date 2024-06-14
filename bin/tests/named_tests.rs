// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

mod server_harness;

use std::io::Write;
use std::net::*;
use std::str::FromStr;

use tokio::net::TcpStream as TokioTcpStream;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::runtime::Runtime;

use hickory_client::client::*;
use hickory_client::op::ResponseCode;
use hickory_client::rr::*;
use hickory_client::tcp::TcpClientStream;
use hickory_client::udp::UdpClientStream;
use hickory_server::server::Protocol;

use hickory_proto::iocompat::AsyncIoTokioAsStd;
use server_harness::{named_test_harness, query_a, query_a_refused};

#[test]
fn test_example_toml_startup() {
    named_test_harness("example.toml", |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr: SocketAddr = SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(),
            tcp_port.expect("no tcp_port"),
        );
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
        let client = AsyncClient::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::spawn_bg(&io_loop, bg);

        query_a(&mut io_loop, &mut client);

        // just tests that multiple queries work
        let addr: SocketAddr = SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(),
            tcp_port.expect("no tcp_port"),
        );
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
        let client = AsyncClient::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::spawn_bg(&io_loop, bg);

        query_a(&mut io_loop, &mut client);
    })
}

#[test]
fn test_ipv4_only_toml_startup() {
    named_test_harness("ipv4_only.toml", |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr: SocketAddr = SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(),
            tcp_port.expect("no tcp_port"),
        );
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
        let client = AsyncClient::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::spawn_bg(&io_loop, bg);

        // ipv4 should succeed
        query_a(&mut io_loop, &mut client);

        let addr: SocketAddr = SocketAddr::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).into(),
            tcp_port.expect("no tcp_port"),
        );
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
        let client = AsyncClient::new(Box::new(stream), sender, None);

        assert!(io_loop.block_on(client).is_err());
        //let (client, bg) = io_loop.block_on(client).expect("client failed to connect");
        //hickory_proto::spawn_bg(&io_loop, bg);

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
    named_test_harness("ipv4_and_ipv6.toml", |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr: SocketAddr = SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(),
            tcp_port.expect("no tcp_port"),
        );
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
        let client = AsyncClient::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::spawn_bg(&io_loop, bg);
        // ipv4 should succeed
        query_a(&mut io_loop, &mut client);

        let tcp_port = socket_ports.get_v6(Protocol::Tcp);
        let addr: SocketAddr = SocketAddr::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).into(),
            tcp_port.expect("no tcp_port"),
        );
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
        let client = AsyncClient::new(Box::new(stream), sender, None);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::spawn_bg(&io_loop, bg);

        // ipv6 should succeed
        query_a(&mut io_loop, &mut client);
    })
}

#[test]
fn test_nodata_where_name_exists() {
    named_test_harness("example.toml", |socket_ports| {
        let io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr: SocketAddr = SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(),
            tcp_port.expect("no tcp_port"),
        );
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
        let client = AsyncClient::new(Box::new(stream), sender, None);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::spawn_bg(&io_loop, bg);

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
    named_test_harness("example.toml", |socket_ports| {
        let io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr: SocketAddr = SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(),
            tcp_port.expect("no tcp_port"),
        );
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
        let client = AsyncClient::new(Box::new(stream), sender, None);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::spawn_bg(&io_loop, bg);

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
    named_test_harness("example.toml", |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let udp_port = socket_ports.get_v4(Protocol::Udp);
        let addr: SocketAddr = SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(),
            udp_port.expect("no udp_port"),
        );
        let stream = UdpClientStream::<TokioUdpSocket>::new(addr);
        let client = AsyncClient::connect(stream);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::spawn_bg(&io_loop, bg);

        query_a(&mut io_loop, &mut client);

        // Send a bad packet, this should get rejected by the server
        let raw_socket = UdpSocket::bind(SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0))
            .expect("couldn't bind raw");

        raw_socket
            .send_to(b"0xDEADBEEF", addr)
            .expect("raw send failed");

        // just tests that multiple queries work
        let addr: SocketAddr = SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(),
            udp_port.expect("no udp_port"),
        );
        let stream = UdpClientStream::<TokioUdpSocket>::new(addr);
        let client = AsyncClient::connect(stream);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::spawn_bg(&io_loop, bg);

        query_a(&mut io_loop, &mut client);
    })
}

#[test]
fn test_server_continues_on_bad_data_tcp() {
    named_test_harness("example.toml", |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr: SocketAddr = SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(),
            tcp_port.expect("no tcp_port"),
        );
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
        let client = AsyncClient::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::spawn_bg(&io_loop, bg);

        query_a(&mut io_loop, &mut client);

        // Send a bad packet, this should get rejected by the server
        let mut raw_socket = TcpStream::connect(addr).expect("couldn't bind raw");

        raw_socket
            .write_all(b"0xDEADBEEF")
            .expect("raw send failed");

        // just tests that multiple queries work
        let addr: SocketAddr = SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(),
            tcp_port.expect("no tcp_port"),
        );
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
        let client = AsyncClient::new(Box::new(stream), sender, None);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::spawn_bg(&io_loop, bg);

        query_a(&mut io_loop, &mut client);
    })
}

#[test]
#[cfg(feature = "resolver")]
fn test_forward() {
    use hickory_proto::rr::rdata::A;
    use server_harness::query_message;

    //env_logger::init();

    named_test_harness("example_forwarder.toml", |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr: SocketAddr = SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(),
            tcp_port.expect("no tcp_port"),
        );
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
        let client = AsyncClient::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::spawn_bg(&io_loop, bg);

        let response = query_message(
            &mut io_loop,
            &mut client,
            Name::from_str("www.example.com").unwrap(),
            RecordType::A,
        )
        .unwrap();
        assert_eq!(
            *response.answers()[0].data().as_a().unwrap(),
            A::new(93, 184, 215, 14)
        );

        // just tests that multiple queries work
        let addr: SocketAddr = SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(),
            tcp_port.expect("no tcp_port"),
        );
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
        let client = AsyncClient::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::spawn_bg(&io_loop, bg);

        let response = query_message(
            &mut io_loop,
            &mut client,
            Name::from_str("www.example.com").unwrap(),
            RecordType::A,
        )
        .unwrap();
        assert_eq!(
            *response.answers()[0].data().as_a().unwrap(),
            A::new(93, 184, 215, 14)
        );
        assert!(!response.header().authoritative());
    })
}

#[test]
fn test_allow_networks_toml_startup() {
    named_test_harness("example_allow_networks.toml", |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr: SocketAddr = SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(),
            tcp_port.expect("no tcp_port"),
        );
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
        let client = AsyncClient::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::spawn_bg(&io_loop, bg);
        // ipv4 should succeed
        query_a(&mut io_loop, &mut client);

        let tcp_port = socket_ports.get_v6(Protocol::Tcp);
        let addr: SocketAddr = SocketAddr::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).into(),
            tcp_port.expect("no tcp_port"),
        );
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
        let client = AsyncClient::new(Box::new(stream), sender, None);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::spawn_bg(&io_loop, bg);

        // ipv6 should succeed
        query_a(&mut io_loop, &mut client);
    })
}

#[test]
fn test_deny_networks_toml_startup() {
    named_test_harness("example_deny_networks.toml", |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr: SocketAddr = SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(),
            tcp_port.expect("no tcp_port"),
        );
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
        let client = AsyncClient::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::spawn_bg(&io_loop, bg);
        // ipv4 should be refused
        query_a_refused(&mut io_loop, &mut client);

        let tcp_port = socket_ports.get_v6(Protocol::Tcp);
        let addr: SocketAddr = SocketAddr::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).into(),
            tcp_port.expect("no tcp_port"),
        );
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
        let client = AsyncClient::new(Box::new(stream), sender, None);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::spawn_bg(&io_loop, bg);

        // ipv6 should be refused
        query_a_refused(&mut io_loop, &mut client);
    })
}

#[test]
fn test_deny_allow_networks_toml_startup() {
    named_test_harness("example_deny_allow_networks.toml", |socket_ports| {
        let mut io_loop = Runtime::new().unwrap();
        let tcp_port = socket_ports.get_v4(Protocol::Tcp);
        let addr: SocketAddr = SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(),
            tcp_port.expect("no tcp_port"),
        );
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
        let client = AsyncClient::new(Box::new(stream), sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::spawn_bg(&io_loop, bg);
        // ipv4 should succeed
        query_a(&mut io_loop, &mut client);

        let tcp_port = socket_ports.get_v6(Protocol::Tcp);
        let addr: SocketAddr = SocketAddr::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).into(),
            tcp_port.expect("no tcp_port"),
        );
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
        let client = AsyncClient::new(Box::new(stream), sender, None);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::spawn_bg(&io_loop, bg);

        // ipv6 should be refused
        query_a_refused(&mut io_loop, &mut client);
    })
}
