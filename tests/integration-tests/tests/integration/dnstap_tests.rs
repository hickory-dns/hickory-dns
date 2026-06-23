#![cfg(feature = "dnstap")]

//! Integration tests for DNSTAP support.
//!
//! These tests spin up a mock DNSTAP receiver (Frame Streams server) on TCP,
//! configure a DnstapLayer pointing at it, send a DNS query through the server,
//! and verify that the receiver gets DNSTAP messages.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
#[cfg(any(feature = "__https", feature = "__quic"))]
use std::sync::Arc;
use std::time::Duration;

#[cfg(any(feature = "__https", feature = "__quic"))]
use futures::TryStreamExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tracing_subscriber::layer::SubscriberExt;

use hickory_dnstap::{
    DnsTransport, DnstapClient, DnstapConfig, DnstapEndpoint, DnstapLayer, DnstapMessageType,
};
#[cfg(any(feature = "__https", feature = "__quic"))]
use hickory_net::client::Client;
#[cfg(feature = "__https")]
use hickory_net::h2::HttpsClientStream;
#[cfg(feature = "__h3")]
use hickory_net::h3::H3ClientStream;
#[cfg(feature = "__quic")]
use hickory_net::quic::QuicClientStream;
#[cfg(any(feature = "__https", feature = "__quic"))]
use hickory_net::runtime::TokioRuntimeProvider;
#[cfg(any(feature = "__https", feature = "__quic"))]
use hickory_net::tls::default_provider;
#[cfg(any(feature = "__https", feature = "__quic"))]
use hickory_net::xfer::DnsHandle;
#[cfg(any(feature = "__https", feature = "__quic"))]
use hickory_proto::op::DnsRequest;
use hickory_proto::op::{DEFAULT_MAX_PAYLOAD_LEN, Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use hickory_server::server::Server;
use hickory_server::zone_handler::Catalog;
#[cfg(any(feature = "__https", feature = "__quic"))]
use rustls::sign::SingleCertAndKey;
#[cfg(any(feature = "__https", feature = "__quic"))]
use rustls::{ClientConfig, RootCertStore};
#[cfg(any(feature = "__https", feature = "__quic"))]
use test_support::TestCertificates;

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

/// A client config pointed at the mock collector, with the address fields
/// every frame assertion needs.
fn test_config(collector: SocketAddr) -> DnstapConfig {
    DnstapConfig {
        endpoint: DnstapEndpoint::Tcp(collector),
        identity: Some(b"hickory-test".to_vec()),
        buffer_size: 64,
        max_backoff: Duration::from_secs(1),
        ..Default::default()
    }
}

/// Run the mock Frame Streams collector on an ephemeral loopback port.
async fn spawn_collector() -> (
    SocketAddr,
    mpsc::Receiver<ReceivedFrames>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (sender, receiver) = mpsc::channel(1);
    let task = tokio::spawn(mock_dnstap_receiver(listener, sender));

    (addr, receiver, task)
}

/// Every frame stream carries the configured identity in its START frame.
fn assert_identity(received: &ReceivedFrames) {
    let frame = received
        .data_frames
        .first()
        .expect("expected at least one DNSTAP data frame");
    assert!(
        frame
            .windows(b"hickory-test".len())
            .any(|w| w == b"hickory-test"),
        "DNSTAP frame should contain identity 'hickory-test'"
    );
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
    let (receiver_addr, mut frame_receiver, receiver_task) = spawn_collector().await;

    let mut config = test_config(receiver_addr);
    config.version = Some(b"0.26.0".to_vec());
    config.log_auth_query = true;
    config.log_auth_response = true;
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

    assert_identity(&received);

    receiver_task.await.unwrap();
}

#[tokio::test]
async fn test_dnstap_update_query_single_frame() {
    // An update-classified event is delivered as one UPDATE_QUERY frame.
    let (receiver_addr, mut frame_receiver, receiver_task) = spawn_collector().await;

    let mut config = test_config(receiver_addr);
    config.log_update_query = true;
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
    let (receiver_addr, mut frame_receiver, receiver_task) = spawn_collector().await;

    let mut config = test_config(receiver_addr);
    config.log_client_query = true;
    config.log_client_response = true;
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
    assert_identity(&received);

    receiver_task.await.unwrap();
}

/// DoH3 answers through `H3ResponseHandle`, a separate path from the
/// UDP/TCP/TLS `ResponseHandle`.
#[cfg(feature = "__h3")]
#[tokio::test]
async fn test_dnstap_layer_with_doh3_server() {
    let (receiver_addr, mut frame_receiver, receiver_task) = spawn_collector().await;

    let mut config = test_config(receiver_addr);
    config.log_client_query = true;
    config.log_client_response = true;
    let (dnstap_layer, dnstap_connection) = DnstapLayer::new(config);
    dnstap_connection.start();

    // `set_default` installs a thread-local subscriber, which only works here because
    // `#[tokio::test]` defaults to a current-thread runtime; all spawned tasks run on
    // this thread.
    let subscriber = tracing_subscriber::registry().with(dnstap_layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let certificates = TestCertificates::generate();
    let cert_resolver = SingleCertAndKey::from(certificates.certified_key());

    let quic_socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let server_addr = quic_socket.local_addr().unwrap();

    let mut server = Server::new(Catalog::new());
    server
        .register_h3_listener(quic_socket, None, None, None, Arc::new(cert_resolver), None)
        .unwrap();

    let shutdown = server.shutdown_token().clone();
    let server_task = tokio::spawn(async move {
        server.block_until_done().await.unwrap();
    });

    let mut client_config = tls_client_config(&certificates);
    client_config.alpn_protocols.push(b"h3".to_vec());

    let sender = H3ClientStream::builder()
        .crypto_config(client_config)
        .build(
            server_addr,
            Arc::from("ns.example.com"),
            Arc::from("/dns-query"),
        )
        .await
        .expect("failed to connect over h3");
    let (client, driver) = Client::<TokioRuntimeProvider>::from_sender(sender);
    let _driver = tokio::spawn(driver);

    let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::new(
        Name::parse("example.com.", Some(&Name::root())).unwrap(),
        RecordType::A,
    ));
    // Empty catalog, so the answer is SERVFAIL; a response frame is emitted
    // either way.
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        client
            .send(DnsRequest::from(message))
            .try_collect::<Vec<_>>(),
    )
    .await;
    drop(client);

    tokio::time::sleep(Duration::from_millis(200)).await;

    shutdown.cancel();
    server_task.await.unwrap();
    drop(_guard);

    let received = tokio::time::timeout(Duration::from_secs(5), frame_receiver.recv())
        .await
        .expect("timed out waiting for DNSTAP frames")
        .expect("receiver channel closed");

    assert_eq!(
        received.data_frames.len(),
        2,
        "a DoH3 request must produce one query frame and one response frame"
    );
    assert_identity(&received);

    receiver_task.await.unwrap();
}

/// DoH answers through `HttpsResponseHandle`, a separate path from the
/// UDP/TCP/TLS `ResponseHandle`.
#[cfg(feature = "__https")]
#[tokio::test]
async fn test_dnstap_layer_with_doh_server() {
    let (receiver_addr, mut frame_receiver, receiver_task) = spawn_collector().await;

    let mut config = test_config(receiver_addr);
    config.log_client_query = true;
    config.log_client_response = true;
    let (dnstap_layer, dnstap_connection) = DnstapLayer::new(config);
    dnstap_connection.start();

    // `set_default` installs a thread-local subscriber, which only works here because
    // `#[tokio::test]` defaults to a current-thread runtime; all spawned tasks run on
    // this thread.
    let subscriber = tracing_subscriber::registry().with(dnstap_layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let certificates = TestCertificates::generate();
    let cert_resolver = SingleCertAndKey::from(certificates.certified_key());

    let tcp_listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();

    let mut server = Server::new(Catalog::new());
    server
        .register_https_listener(
            tcp_listener,
            None,
            None,
            None,
            Arc::new(cert_resolver),
            Some("ns.example.com".to_string()),
            "/dns-query".to_string(),
        )
        .unwrap();

    let shutdown = server.shutdown_token().clone();
    let server_task = tokio::spawn(async move {
        server.block_until_done().await.unwrap();
    });

    let sender = HttpsClientStream::builder(
        Arc::new(tls_client_config(&certificates)),
        TokioRuntimeProvider::default(),
    )
    .build(
        server_addr,
        Arc::from("ns.example.com"),
        Arc::from("/dns-query"),
    )
    .await
    .expect("failed to connect over h2");
    let (client, driver) = Client::<TokioRuntimeProvider>::from_sender(sender);
    let _driver = tokio::spawn(driver);

    let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::new(
        Name::parse("example.com.", Some(&Name::root())).unwrap(),
        RecordType::A,
    ));
    // Empty catalog, so the answer is SERVFAIL; a response frame is emitted
    // either way.
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        client
            .send(DnsRequest::from(message))
            .try_collect::<Vec<_>>(),
    )
    .await;
    drop(client);

    tokio::time::sleep(Duration::from_millis(200)).await;

    shutdown.cancel();
    server_task.await.unwrap();
    drop(_guard);

    let received = tokio::time::timeout(Duration::from_secs(5), frame_receiver.recv())
        .await
        .expect("timed out waiting for DNSTAP frames")
        .expect("receiver channel closed");

    assert_eq!(
        received.data_frames.len(),
        2,
        "a DoH request must produce one query frame and one response frame"
    );
    assert_identity(&received);

    receiver_task.await.unwrap();
}

/// DoQ answers through `QuicResponseHandle`, which rewrites the message id to
/// 0 before encoding.
#[cfg(feature = "__quic")]
#[tokio::test]
async fn test_dnstap_layer_with_doq_server() {
    let (receiver_addr, mut frame_receiver, receiver_task) = spawn_collector().await;

    let mut config = test_config(receiver_addr);
    config.log_client_query = true;
    config.log_client_response = true;
    let (dnstap_layer, dnstap_connection) = DnstapLayer::new(config);
    dnstap_connection.start();

    // `set_default` installs a thread-local subscriber, which only works here because
    // `#[tokio::test]` defaults to a current-thread runtime; all spawned tasks run on
    // this thread.
    let subscriber = tracing_subscriber::registry().with(dnstap_layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let certificates = TestCertificates::generate();
    let cert_resolver = SingleCertAndKey::from(certificates.certified_key());

    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let server_addr = socket.local_addr().unwrap();

    let mut server = Server::new(Catalog::new());
    server
        .register_quic_listener(socket, None, None, None, Arc::new(cert_resolver))
        .unwrap();

    let shutdown = server.shutdown_token().clone();
    let server_task = tokio::spawn(async move {
        server.block_until_done().await.unwrap();
    });

    let sender = QuicClientStream::builder()
        .crypto_config(tls_client_config(&certificates))
        .build(server_addr, Arc::from("ns.example.com"))
        .await
        .expect("failed to connect over QUIC");
    let (client, driver) = Client::<TokioRuntimeProvider>::from_sender(sender);
    let _driver = tokio::spawn(driver);

    let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::new(
        Name::parse("example.com.", Some(&Name::root())).unwrap(),
        RecordType::A,
    ));
    // Empty catalog, so the answer is SERVFAIL; a response frame is emitted
    // either way.
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        client
            .send(DnsRequest::from(message))
            .try_collect::<Vec<_>>(),
    )
    .await;
    drop(client);

    tokio::time::sleep(Duration::from_millis(200)).await;

    shutdown.cancel();
    server_task.await.unwrap();
    drop(_guard);

    let received = tokio::time::timeout(Duration::from_secs(5), frame_receiver.recv())
        .await
        .expect("timed out waiting for DNSTAP frames")
        .expect("receiver channel closed");

    assert_eq!(
        received.data_frames.len(),
        2,
        "a DoQ request must produce one query frame and one response frame"
    );
    assert_identity(&received);

    receiver_task.await.unwrap();
}

/// A client config that trusts the test CA, for the DoH, DoH3 and DoQ tests.
#[cfg(any(feature = "__https", feature = "__quic"))]
fn tls_client_config(certificates: &TestCertificates) -> ClientConfig {
    let mut root_store = RootCertStore::empty();
    let (_, ignored) = root_store.add_parsable_certificates(vec![certificates.ca.der().clone()]);
    assert_eq!(ignored, 0, "server certificate did not parse");

    ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}
