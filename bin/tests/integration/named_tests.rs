// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io::Write;
use std::net::*;
use std::str::FromStr;

use crate::server_harness::{TestServer, query_a, query_a_refused};
use hickory_net::client::{Client, ClientHandle};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::udp::UdpClientStream;
use hickory_net::xfer::Protocol;
use hickory_proto::op::ResponseCode;
#[cfg(feature = "resolver")]
use hickory_proto::rr::RData;
use hickory_proto::rr::{DNSClass, Name, RecordType};
use test_support::subscribe;

#[tokio::test]
async fn test_example_toml_startup() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("example.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    query_a(&mut client).await;

    // just tests that multiple queries work
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    query_a(&mut client).await;
}

#[tokio::test]
async fn test_ipv4_only_toml_startup() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("ipv4_only.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    // ipv4 should succeed
    query_a(&mut client).await;

    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, _) = TcpClientStream::new(addr, None, None, provider.clone());
    assert!(future.await.is_err());
    //let (client, bg) = client.await.expect("client failed to connect");
    //tokio::spawn(bg);

    // ipv6 should fail
    // FIXME: probably need to send something for proper test... maybe use JoinHandle in tokio 0.2
    // assert!(client.await.is_err());
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

#[tokio::test]
async fn test_ipv4_and_ipv6_toml_startup() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("ipv4_and_ipv6.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    // ipv4 should succeed
    query_a(&mut client).await;

    let tcp_port = server.ports.get_v6(Protocol::Tcp);
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    // ipv6 should succeed
    query_a(&mut client).await;
}

#[tokio::test]
async fn test_nodata_where_name_exists() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("example.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    let msg = client
        .query(
            Name::from_str("www.example.com.").unwrap(),
            DNSClass::IN,
            RecordType::SRV,
        )
        .await
        .unwrap();
    assert_eq!(msg.response_code(), ResponseCode::NoError);
    assert!(msg.answers().is_empty());
}

#[tokio::test]
async fn test_nxdomain_where_no_name_exists() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("example.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    let msg = client
        .query(
            Name::from_str("nxdomain.example.com.").unwrap(),
            DNSClass::IN,
            RecordType::SRV,
        )
        .await
        .unwrap();
    assert_eq!(msg.response_code(), ResponseCode::NXDomain);
    assert!(msg.answers().is_empty());
}

#[tokio::test]
async fn test_server_continues_on_bad_data_udp() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("example.toml");
    let udp_port = server.ports.get_v4(Protocol::Udp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, udp_port.expect("no udp_port")));
    let stream = UdpClientStream::builder(addr, provider.clone()).build();
    let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
    tokio::spawn(bg);

    query_a(&mut client).await;

    // Send a bad packet, this should get rejected by the server
    let raw_socket = UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0))
        .expect("couldn't bind raw");

    raw_socket
        .send_to(b"0xDEADBEEF", addr)
        .expect("raw send failed");

    // just tests that multiple queries work
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, udp_port.expect("no udp_port")));
    let stream = UdpClientStream::builder(addr, provider).build();
    let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
    tokio::spawn(bg);

    query_a(&mut client).await;
}

#[tokio::test]
async fn test_server_continues_on_bad_data_tcp() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("example.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");

    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    query_a(&mut client).await;

    // Send a bad packet, this should get rejected by the server
    let mut raw_socket = TcpStream::connect(addr).expect("couldn't bind raw");

    raw_socket
        .write_all(b"0xDEADBEEF")
        .expect("raw send failed");

    // just tests that multiple queries work
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    query_a(&mut client).await;
}

#[tokio::test]
#[cfg(feature = "resolver")]
async fn test_forward() {
    use crate::server_harness::query_message;

    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("example_forwarder.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");

    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    let response = query_message(
        &mut client,
        Name::from_str("www.example.com.").unwrap(),
        RecordType::A,
    )
    .await
    .unwrap();

    assert!(
        response
            .answers()
            .iter()
            .any(|record| matches!(record.data(), RData::A(_)))
    );

    // just tests that multiple queries work
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");

    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    let response = query_message(
        &mut client,
        Name::from_str("www.example.com.").unwrap(),
        RecordType::A,
    )
    .await
    .unwrap();
    assert!(
        response
            .answers()
            .iter()
            .any(|record| matches!(record.data(), RData::A(_)))
    );
    assert!(!response.header().authoritative());
}

#[tokio::test]
async fn test_allow_networks_toml_startup() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("example_allow_networks.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");

    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);
    // ipv4 should succeed
    query_a(&mut client).await;

    let tcp_port = server.ports.get_v6(Protocol::Tcp);
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    // ipv6 should succeed
    query_a(&mut client).await;
}

#[tokio::test]
async fn test_deny_networks_toml_startup() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("example_deny_networks.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");

    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);
    // ipv4 should be refused
    query_a_refused(&mut client).await;

    let tcp_port = server.ports.get_v6(Protocol::Tcp);
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    // ipv6 should be refused
    query_a_refused(&mut client).await;
}

#[tokio::test]
async fn test_deny_allow_networks_toml_startup() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("example_deny_allow_networks.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");

    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);
    // ipv4 should succeed
    query_a(&mut client).await;

    let tcp_port = server.ports.get_v6(Protocol::Tcp);
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    // ipv6 should be refused
    query_a_refused(&mut client).await;
}
