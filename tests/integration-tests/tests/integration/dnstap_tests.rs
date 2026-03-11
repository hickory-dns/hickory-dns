#![cfg(feature = "dnstap")]

//! Integration tests for DNSTAP support.
//!
//! These tests spin up a mock DNSTAP receiver (Frame Streams server) on TCP,
//! configure a DnstapLayer pointing at it, send a DNS query through the server,
//! and verify that the receiver gets DNSTAP messages.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tracing_subscriber::layer::SubscriberExt;

use hickory_dnstap::{DnsTransport, DnstapClient, DnstapConfig, DnstapEndpoint, DnstapLayer};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use hickory_server::server::Server;
use hickory_server::zone_handler::Catalog;

/// Received DNSTAP data from Frame Streams.
struct ReceivedFrames {
    data_frames: Vec<Vec<u8>>,
}

/// Run a minimal Frame Streams server that performs the READY/ACCEPT/START
/// handshake and collects data frames until the client sends STOP.
async fn mock_dnstap_receiver(listener: TcpListener, sender: mpsc::Sender<ReceivedFrames>) {
    let (mut stream, _addr) = listener.accept().await.unwrap();

    // Read READY control frame: escape (4 bytes of 0) + length + payload
    let escape = stream.read_u32().await.unwrap();
    assert_eq!(escape, 0, "expected control frame escape");
    let control_len = stream.read_u32().await.unwrap();
    let mut payload = vec![0u8; control_len as usize];
    stream.read_exact(&mut payload).await.unwrap();
    // First 4 bytes of payload are the control type (READY = 0x04)
    assert_eq!(
        u32::from_be_bytes(payload[..4].try_into().unwrap()),
        0x04,
        "expected READY"
    );

    // Send ACCEPT control frame
    let accept = build_control_frame(0x01, true);
    stream.write_all(&accept).await.unwrap();
    stream.flush().await.unwrap();

    // Read START control frame
    let escape = stream.read_u32().await.unwrap();
    assert_eq!(escape, 0, "expected control frame escape for START");
    let control_len = stream.read_u32().await.unwrap();
    let mut payload = vec![0u8; control_len as usize];
    stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(
        u32::from_be_bytes(payload[..4].try_into().unwrap()),
        0x02,
        "expected START"
    );

    // Now read data frames until we get a control frame (STOP)
    let mut data_frames = Vec::new();
    while let Ok(frame_len) = stream.read_u32().await {
        if frame_len == 0 {
            // This is a control frame escape — read the control frame
            let control_len = stream.read_u32().await.unwrap();
            let mut payload = vec![0u8; control_len as usize];
            stream.read_exact(&mut payload).await.unwrap();
            let control_type = u32::from_be_bytes(payload[..4].try_into().unwrap());
            if control_type == 0x03 {
                // STOP — send FINISH and break
                let finish = build_control_frame(0x05, false);
                stream.write_all(&finish).await.unwrap();
                stream.flush().await.unwrap();
                break;
            }
        } else {
            // Data frame
            let mut data = vec![0u8; frame_len as usize];
            stream.read_exact(&mut data).await.unwrap();
            data_frames.push(data);
        }
    }

    let _ = sender.send(ReceivedFrames { data_frames }).await;
}

/// Build a Frame Streams control frame.
fn build_control_frame(control_type: u32, include_content_type: bool) -> Vec<u8> {
    let content_type = b"protobuf:dnstap.Dnstap";
    let mut buf = Vec::new();

    // Escape
    buf.extend_from_slice(&0u32.to_be_bytes());

    // Build the payload first to get its length
    let mut payload = Vec::new();
    payload.extend_from_slice(&control_type.to_be_bytes());
    if include_content_type {
        payload.extend_from_slice(&1u32.to_be_bytes()); // CONTENT_TYPE field type
        payload.extend_from_slice(&(content_type.len() as u32).to_be_bytes());
        payload.extend_from_slice(content_type);
    }

    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(&payload);
    buf
}

/// Build a minimal DNS query message in wire format.
fn build_dns_query(name: &str) -> Vec<u8> {
    let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
    message.set_recursion_desired(true);

    let mut query = Query::new();
    query.set_name(Name::parse(name, Some(&Name::root())).unwrap());
    query.set_query_type(RecordType::A);
    message.add_query(query);

    let mut buf = Vec::new();
    let mut encoder = hickory_proto::serialize::binary::BinEncoder::new(&mut buf);
    message.emit(&mut encoder).unwrap();
    buf
}

#[tokio::test]
async fn test_dnstap_client_sends_to_receiver() {
    // Start mock DNSTAP receiver
    let receiver_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver_listener.local_addr().unwrap();

    let (frame_sender, mut frame_receiver) = mpsc::channel(1);
    let receiver_task = tokio::spawn(mock_dnstap_receiver(receiver_listener, frame_sender));

    // Create DNSTAP client connected to the mock receiver
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

    // Give the client time to connect and handshake
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Send a query event
    let src_addr: SocketAddr = "192.168.1.100:5353".parse().unwrap();
    let query_bytes = build_dns_query("example.com");
    client.log_query(src_addr, None, DnsTransport::Udp, &query_bytes);

    // Drop the client to trigger channel close → STOP frame
    drop(client);

    // Wait for mock receiver to collect frames
    let received = tokio::time::timeout(Duration::from_secs(5), frame_receiver.recv())
        .await
        .expect("timed out waiting for DNSTAP frames")
        .expect("receiver channel closed");

    assert!(
        !received.data_frames.is_empty(),
        "expected at least one DNSTAP data frame"
    );

    // Verify the protobuf contains our identity string
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
async fn test_dnstap_layer_with_server() {
    // Start mock DNSTAP receiver
    let receiver_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver_listener.local_addr().unwrap();

    let (frame_sender, mut frame_receiver) = mpsc::channel(1);
    let receiver_task = tokio::spawn(mock_dnstap_receiver(receiver_listener, frame_sender));

    // Create the DnstapLayer and install it as the tracing subscriber
    let config = DnstapConfig {
        endpoint: DnstapEndpoint::Tcp(receiver_addr),
        identity: Some(b"hickory-integration".to_vec()),
        version: None,
        buffer_size: 64,
        max_backoff: Duration::from_secs(1),
        log_auth_query: true,
        log_auth_response: true,
        ..Default::default()
    };
    let dnstap_layer = DnstapLayer::new(config);

    // Install a subscriber with both the DNSTAP layer and a fmt layer for debug output
    let subscriber = tracing_subscriber::registry().with(dnstap_layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let udp_socket = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let server_addr = udp_socket.local_addr().unwrap();

    let mut server = Server::new(Catalog::new());
    server.register_socket(udp_socket);

    let shutdown = server.shutdown_token().clone();

    let server_task = tokio::spawn(async move {
        server.block_until_done().await.unwrap();
    });

    // Give the DNSTAP layer time to connect
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Send a DNS query to the server via UDP
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = build_dns_query("example.com");
    client_socket.send_to(&query, server_addr).await.unwrap();

    // Give the server time to process and log the DNSTAP event
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Shut down the server — the DnstapLayer's sender will be dropped when
    // the subscriber guard drops, triggering the STOP frame.
    shutdown.cancel();
    server_task.await.unwrap();

    // Drop the subscriber guard to close the DNSTAP channel
    drop(_guard);

    // Collect frames from the receiver
    let received = tokio::time::timeout(Duration::from_secs(5), frame_receiver.recv())
        .await
        .expect("timed out waiting for DNSTAP frames")
        .expect("receiver channel closed");

    // The server should have sent at least one AUTH_QUERY frame
    assert!(
        !received.data_frames.is_empty(),
        "expected at least one DNSTAP data frame from server"
    );

    // Verify identity is present in the frame
    let frame = &received.data_frames[0];
    assert!(
        frame
            .windows(b"hickory-integration".len())
            .any(|w| w == b"hickory-integration"),
        "DNSTAP frame should contain identity 'hickory-integration'"
    );

    receiver_task.await.unwrap();
}
