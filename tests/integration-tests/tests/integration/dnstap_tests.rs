#![cfg(feature = "dnstap")]

//! Integration tests for DNSTAP support.
//!
//! These tests spin up a mock DNSTAP receiver (Frame Streams server) on TCP,
//! configure a DnstapLayer pointing at it, send a DNS query through the server,
//! and verify that the receiver gets DNSTAP messages.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tracing_subscriber::layer::SubscriberExt;

use hickory_dnstap::{
    DnsTransport, DnstapClient, DnstapConfig, DnstapEndpoint, DnstapLayer, DnstapMessageType,
};
use hickory_proto::op::{DEFAULT_MAX_PAYLOAD_LEN, Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use hickory_server::server::Server;
use hickory_server::zone_handler::Catalog;

/// Received DNSTAP data from Frame Streams.
struct ReceivedFrames {
    data_frames: Vec<Vec<u8>>,
}

/// Run a minimal Frame Streams server that performs the READY/ACCEPT/START
/// handshake and collects data frames until the client closes the stream.
async fn mock_dnstap_receiver(listener: TcpListener, sender: mpsc::Sender<ReceivedFrames>) {
    let (mut stream, _addr) = listener.accept().await.unwrap();

    let mut data_frames = Vec::new();
    test_support::framestream::handshake(&mut stream).await;
    test_support::framestream::collect(&mut stream, |payload| data_frames.push(payload.to_vec()))
        .await;

    let _ = sender.send(ReceivedFrames { data_frames }).await;
}

/// Build a minimal DNS query message in wire format.
fn build_dns_query(name: &str) -> Vec<u8> {
    let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;

    let query = Query::new(
        Name::parse(name, Some(&Name::root())).unwrap(),
        RecordType::A,
    );
    message.add_query(query);

    let mut buf = Vec::new();
    let mut encoder = hickory_proto::serialize::binary::BinEncoder::new(&mut buf);
    message.emit(&mut encoder).unwrap();
    buf
}

#[tokio::test]
async fn test_dnstap_client_sends_to_receiver() {
    let receiver_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver_listener.local_addr().unwrap();

    let (frame_sender, mut frame_receiver) = mpsc::channel(1);
    let receiver_task = tokio::spawn(mock_dnstap_receiver(receiver_listener, frame_sender));

    let config = DnstapConfig {
        endpoint: DnstapEndpoint::Tcp(receiver_addr),
        identity: Some(b"hickory-test".to_vec()),
        version: Some(b"0.26.0".to_vec()),
        buffer_size: 64,
        max_backoff: Duration::from_secs(1),
        log_auth_query: true,
        log_auth_response: true,
        ..Default::default()
    };
    let client = DnstapClient::new(config);

    tokio::time::sleep(Duration::from_millis(200)).await;

    let src_addr: SocketAddr = "192.168.1.100:5353".parse().unwrap();
    let query_bytes = build_dns_query("example.com");
    client.log_query(
        DnstapMessageType::Auth,
        Some(src_addr),
        None,
        Some(DnsTransport::Udp),
        &query_bytes,
    );

    // Drop the client to trigger channel close → STOP frame
    drop(client);

    let received = tokio::time::timeout(Duration::from_secs(5), frame_receiver.recv())
        .await
        .expect("timed out waiting for DNSTAP frames")
        .expect("receiver channel closed");

    assert!(
        !received.data_frames.is_empty(),
        "expected at least one DNSTAP data frame"
    );

    let frame = &received.data_frames[0];
    assert!(!frame.is_empty(), "data frame should not be empty");
    assert!(
        frame
            .windows(b"hickory-test".len())
            .any(|w| w == b"hickory-test"),
        "DNSTAP frame should contain identity 'hickory-test'"
    );

    receiver_task.await.unwrap();
}

#[tokio::test]
async fn test_dnstap_update_query_single_frame() {
    // An update-classified event is delivered as one UPDATE_QUERY frame.
    let receiver_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver_listener.local_addr().unwrap();

    let (frame_sender, mut frame_receiver) = mpsc::channel(1);
    let receiver_task = tokio::spawn(mock_dnstap_receiver(receiver_listener, frame_sender));

    let config = DnstapConfig {
        endpoint: DnstapEndpoint::Tcp(receiver_addr),
        identity: Some(b"hickory-test".to_vec()),
        buffer_size: 64,
        max_backoff: Duration::from_secs(1),
        log_update_query: true,
        ..Default::default()
    };
    let client = DnstapClient::new(config);

    tokio::time::sleep(Duration::from_millis(200)).await;

    let src_addr: SocketAddr = "192.168.1.100:5353".parse().unwrap();
    let update_bytes = b"\x12\x34\x28\x00";
    client.log_query(
        DnstapMessageType::Update,
        Some(src_addr),
        None,
        Some(DnsTransport::Udp),
        update_bytes,
    );

    drop(client);
    let received = tokio::time::timeout(Duration::from_secs(5), frame_receiver.recv())
        .await
        .expect("timed out waiting for DNSTAP frames")
        .expect("receiver channel closed");

    assert_eq!(
        received.data_frames.len(),
        1,
        "an update-classified event must be emitted as a single frame"
    );
    assert!(
        received.data_frames[0]
            .windows(update_bytes.len())
            .any(|w| w == update_bytes),
        "UPDATE_QUERY frame should embed the query message"
    );

    receiver_task.await.unwrap();
}

#[tokio::test]
async fn test_dnstap_layer_with_server() {
    let receiver_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver_listener.local_addr().unwrap();

    let (frame_sender, mut frame_receiver) = mpsc::channel(1);
    let receiver_task = tokio::spawn(mock_dnstap_receiver(receiver_listener, frame_sender));

    let config = DnstapConfig {
        endpoint: DnstapEndpoint::Tcp(receiver_addr),
        identity: Some(b"hickory-integration".to_vec()),
        version: None,
        buffer_size: 64,
        max_backoff: Duration::from_secs(1),
        log_client_query: true,
        log_client_response: true,
        ..Default::default()
    };
    let (dnstap_layer, dnstap_connection) = DnstapLayer::new(config);
    dnstap_connection.start();

    // `set_default` installs a thread-local subscriber, which only works here because
    // `#[tokio::test]` defaults to a current-thread runtime; all spawned tasks run on
    // this thread.
    let subscriber = tracing_subscriber::registry().with(dnstap_layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let udp_socket = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let server_addr = udp_socket.local_addr().unwrap();

    let mut server = Server::new(Catalog::new());
    server.register_socket(udp_socket, DEFAULT_MAX_PAYLOAD_LEN);

    let shutdown = server.shutdown_token().clone();

    let server_task = tokio::spawn(async move {
        server.block_until_done().await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = build_dns_query("example.com");
    client_socket.send_to(&query, server_addr).await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Shut down the server - the DnstapLayer's sender will be dropped when
    // the subscriber guard drops, triggering the STOP frame.
    shutdown.cancel();
    server_task.await.unwrap();

    drop(_guard);

    let received = tokio::time::timeout(Duration::from_secs(5), frame_receiver.recv())
        .await
        .expect("timed out waiting for DNSTAP frames")
        .expect("receiver channel closed");

    // The server classifies the RD-set test query as a CLIENT query; the
    // client-classified event should have produced a frame.
    assert!(
        !received.data_frames.is_empty(),
        "expected at least one DNSTAP data frame from server"
    );

    let frame = &received.data_frames[0];
    assert!(
        frame
            .windows(b"hickory-integration".len())
            .any(|w| w == b"hickory-integration"),
        "DNSTAP frame should contain identity 'hickory-integration'"
    );

    receiver_task.await.unwrap();
}
