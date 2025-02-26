use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
#[cfg(feature = "__tls")]
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures::TryStreamExt;
use hickory_client::client::{Client, ClientHandle};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::tcp::TcpClientStream;
use hickory_proto::udp::UdpClientStream;
#[cfg(feature = "__tls")]
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{
        CertificateDer, PrivateKeyDer,
        pem::{self, PemObject},
    },
    server::ResolvesServerCert,
    sign::{CertifiedKey, SingleCertAndKey},
};
use tokio::net::TcpListener;
use tokio::net::UdpSocket;

use hickory_integration::example_authority::create_example;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
#[cfg(feature = "__tls")]
use hickory_proto::rustls::default_provider;
use hickory_proto::xfer::{DnsHandle, DnsMultiplexer};
use hickory_server::ServerFuture;
use hickory_server::authority::{Authority, Catalog};
use test_support::subscribe;

#[tokio::test]
#[allow(clippy::uninlined_format_args)]
async fn test_server_www_udp() {
    subscribe();

    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let udp_socket = UdpSocket::bind(&addr).await.unwrap();

    let ipaddr = udp_socket.local_addr().unwrap();
    println!("udp_socket on port: {}", ipaddr);
    let server_continue = Arc::new(AtomicBool::new(true));
    let server_continue2 = server_continue.clone();

    let server = tokio::spawn(server_thread_udp(udp_socket, server_continue2));
    let client = tokio::spawn(client_thread_www(lazy_udp_client(ipaddr)));

    let client_result = client.await;
    assert!(client_result.is_ok(), "client failed: {:?}", client_result);
    server_continue.store(false, Ordering::Relaxed);
    server.await.unwrap();
}

#[tokio::test]
#[allow(clippy::uninlined_format_args)]
async fn test_server_www_tcp() {
    subscribe();

    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let tcp_listener = TcpListener::bind(&addr).await.unwrap();

    let ipaddr = tcp_listener.local_addr().unwrap();
    println!("tcp_listener on port: {}", ipaddr);
    let server_continue = Arc::new(AtomicBool::new(true));
    let server_continue2 = server_continue.clone();

    let server = tokio::spawn(server_thread_tcp(tcp_listener, server_continue2));
    let client = tokio::spawn(client_thread_www(lazy_tcp_client(ipaddr)));

    let client_result = client.await;
    assert!(client_result.is_ok(), "client failed: {:?}", client_result);
    server_continue.store(false, Ordering::Relaxed);
    server.await.unwrap();
}

#[tokio::test]
async fn test_server_unknown_type() {
    subscribe();

    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let udp_socket = UdpSocket::bind(&addr).await.unwrap();

    let ipaddr = udp_socket.local_addr().unwrap();
    println!("udp_socket on port: {ipaddr}");
    let server_continue = Arc::new(AtomicBool::new(true));
    let server_continue2 = server_continue.clone();

    let server = tokio::spawn(server_thread_udp(udp_socket, server_continue2));
    let mut client = lazy_udp_client(ipaddr).await;

    let client_result = client
        .query(
            Name::from_str("www.example.com.").unwrap(),
            DNSClass::IN,
            RecordType::Unknown(65535),
        )
        .await
        .expect("query failed for unknown");

    assert_eq!(client_result.response_code(), ResponseCode::NoError);
    assert_eq!(
        client_result.queries().first().unwrap().query_type(),
        RecordType::Unknown(65535)
    );
    assert!(client_result.answers().is_empty());
    assert!(!client_result.name_servers().is_empty());
    // SOA should be the first record in the response
    assert_eq!(
        client_result
            .name_servers()
            .first()
            .expect("no SOA present")
            .record_type(),
        RecordType::SOA
    );

    server_continue.store(false, Ordering::Relaxed);
    server.await.unwrap();
}

#[tokio::test]
async fn test_server_form_error_on_multiple_queries() {
    subscribe();

    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let udp_socket = UdpSocket::bind(&addr).await.unwrap();

    let ipaddr = udp_socket.local_addr().unwrap();
    println!("udp_socket on port: {ipaddr}");
    let server_continue = Arc::new(AtomicBool::new(true));
    let server_continue2 = server_continue.clone();

    let server = tokio::spawn(server_thread_udp(udp_socket, server_continue2));
    let client = lazy_udp_client(ipaddr).await;

    // build the message
    let query_a = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
    let query_aaaa = Query::query(
        Name::from_str("www.example.com.").unwrap(),
        RecordType::AAAA,
    );
    let mut message: Message = Message::new();
    message
        .add_query(query_a)
        .add_query(query_aaaa)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true);

    let mut client_result = client
        .send(message)
        .try_collect::<Vec<_>>()
        .await
        .expect("query failed");

    assert_eq!(client_result.len(), 1);
    let client_result = client_result.pop().expect("there should be one response");

    assert_eq!(client_result.response_code(), ResponseCode::FormErr);

    server_continue.store(false, Ordering::Relaxed);
    server.await.unwrap();
}

#[tokio::test]
async fn test_server_no_response_on_response() {
    subscribe();

    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let udp_socket = UdpSocket::bind(&addr).await.unwrap();

    let ipaddr = udp_socket.local_addr().unwrap();
    println!("udp_socket on port: {}", ipaddr);
    let server_continue = Arc::new(AtomicBool::new(true));
    let server_continue2 = server_continue.clone();

    let server = tokio::spawn(server_thread_udp(udp_socket, server_continue2));
    let client = lazy_udp_client(ipaddr).await;

    // build the message
    let query_a = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
    let mut message = Message::new();
    message
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .add_query(query_a);

    let client_result = client.send(message).try_collect::<Vec<_>>().await.unwrap();
    assert_eq!(client_result.len(), 0);

    server_continue.store(false, Ordering::Relaxed);
    server.await.unwrap();
}

#[cfg(feature = "__tls")]
#[allow(unused)]
fn read_file(path: &str) -> Vec<u8> {
    use std::fs::File;
    use std::io::Read;

    let mut bytes = vec![];

    let mut file = File::open(path).unwrap_or_else(|_| panic!("failed to open file: {}", path));
    file.read_to_end(&mut bytes)
        .unwrap_or_else(|_| panic!("failed to read file: {}", path));
    bytes
}

// TODO: move all this to future based clients
#[cfg(feature = "__tls")]
#[tokio::test]
#[allow(clippy::uninlined_format_args)]
async fn test_server_www_tls() {
    use std::env;

    subscribe();

    let dns_name = "ns.example.com";

    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "../..".to_owned());
    println!("using server src path: {}", server_path);

    let ca = read_certs(format!("{}/tests/test-data/ca.pem", server_path)).unwrap();
    let cert_chain = read_certs(format!("{}/tests/test-data/cert.pem", server_path)).unwrap();

    let key =
        PrivateKeyDer::from_pem_file(format!("{server_path}/tests/test-data/cert.key")).unwrap();

    let certified_key = CertifiedKey::from_der(cert_chain, key, &default_provider()).unwrap();
    let server_cert_resolver = SingleCertAndKey::from(certified_key);

    // Server address
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let tcp_listener = TcpListener::bind(&addr).await.unwrap();

    let ipaddr = tcp_listener.local_addr().unwrap();
    println!("tcp_listener on port: {ipaddr}");
    let server_continue = Arc::new(AtomicBool::new(true));
    let server_continue2 = server_continue.clone();

    let server = tokio::spawn(server_thread_tls(
        tcp_listener,
        server_continue2,
        Arc::new(server_cert_resolver),
    ));

    let client = tokio::spawn(client_thread_www(lazy_tls_client(
        ipaddr,
        dns_name.to_string(),
        ca,
    )));

    let client_result = client.await;

    assert!(client_result.is_ok(), "client failed: {:?}", client_result);
    server_continue.store(false, Ordering::Relaxed);
    server.await.unwrap();
}

async fn lazy_udp_client(addr: SocketAddr) -> Client {
    let conn = UdpClientStream::builder(addr, TokioRuntimeProvider::default()).build();
    let (client, driver) = Client::connect(conn).await.expect("failed to connect");
    tokio::spawn(driver);
    client
}

async fn lazy_tcp_client(addr: SocketAddr) -> Client {
    let (stream, sender) = TcpClientStream::new(addr, None, None, TokioRuntimeProvider::default());
    let multiplexer = DnsMultiplexer::new(stream, sender, None);
    let (client, driver) = Client::connect(multiplexer)
        .await
        .expect("failed to connect");
    tokio::spawn(driver);
    client
}

#[cfg(feature = "__tls")]
fn read_certs(cert_path: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>, pem::Error> {
    CertificateDer::pem_file_iter(cert_path)?.collect::<Result<Vec<_>, _>>()
}

#[cfg(feature = "__tls")]
async fn lazy_tls_client(
    ipaddr: SocketAddr,
    dns_name: String,
    cert_chain: Vec<CertificateDer<'static>>,
) -> Client {
    use hickory_proto::rustls::tls_client_connect_with_bind_addr;

    let mut root_store = RootCertStore::empty();
    let (_, ignored) = root_store.add_parsable_certificates(cert_chain);
    assert_eq!(ignored, 0, "bad certificate!");

    let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let (tls_client_stream, handle) = tls_client_connect_with_bind_addr(
        ipaddr,
        None,
        dns_name,
        Arc::new(config),
        TokioRuntimeProvider::default(),
    );

    let multiplexer = DnsMultiplexer::new(Box::pin(tls_client_stream), handle, None);
    let (client, driver) = Client::connect(multiplexer)
        .await
        .expect("failed to connect");
    tokio::spawn(driver);
    client
}

async fn client_thread_www(future: impl Future<Output = Client>) {
    let name = Name::from_str("www.example.com.").unwrap();

    let mut client = future.await;
    let response = client
        .query(name.clone(), DNSClass::IN, RecordType::A)
        .await
        .expect("error querying");

    assert_eq!(
        response.response_code(),
        ResponseCode::NoError,
        "got an error: {:?}",
        response.response_code()
    );
    assert!(response.header().authoritative());

    let record = &response.answers()[0];
    assert_eq!(record.name(), &name);
    assert_eq!(record.record_type(), RecordType::A);
    assert_eq!(record.dns_class(), DNSClass::IN);

    if let RData::A(address) = *record.data() {
        assert_eq!(address, A::new(93, 184, 215, 14))
    } else {
        panic!();
    }
}

fn new_catalog() -> Catalog {
    let example = create_example();
    let origin = example.origin().clone();

    let mut catalog = Catalog::new();
    catalog.upsert(origin, vec![Arc::new(example)]);
    catalog
}

async fn server_thread_udp(udp_socket: UdpSocket, server_continue: Arc<AtomicBool>) {
    let catalog = new_catalog();
    let mut server = ServerFuture::new(catalog);
    server.register_socket(udp_socket);

    while server_continue.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    server.shutdown_gracefully().await.unwrap();
}

async fn server_thread_tcp(tcp_listener: TcpListener, server_continue: Arc<AtomicBool>) {
    let catalog = new_catalog();
    let mut server = ServerFuture::new(catalog);
    server.register_listener(tcp_listener, Duration::from_secs(30));

    while server_continue.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    server.shutdown_gracefully().await.unwrap();
}

// TODO: need a rustls option
#[cfg(feature = "__tls")]
#[allow(unused)]
async fn server_thread_tls(
    tls_listener: TcpListener,
    server_continue: Arc<AtomicBool>,
    cert_chain: Arc<dyn ResolvesServerCert>,
) {
    use std::path::Path;

    let catalog = new_catalog();
    let mut server = ServerFuture::new(catalog);

    // let pkcs12 = Pkcs12::from_der(&pkcs12_der)
    //     .expect("bad pkcs12 der")
    //     .parse("mypass")
    //     .expect("Pkcs12::from_der");
    // let pkcs12 = ((pkcs12.cert, pkcs12.chain), pkcs12.pkey);

    server
        .register_tls_listener(tls_listener, Duration::from_secs(30), cert_chain)
        .expect("failed to register TLS");

    while server_continue.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    server.shutdown_gracefully().await;
}
