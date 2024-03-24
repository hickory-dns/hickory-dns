use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use futures::{future, Future, FutureExt};
use tokio::net::TcpListener;
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;

use hickory_client::client::*;
use hickory_client::op::*;
use hickory_client::rr::*;
use hickory_client::tcp::TcpClientConnection;
use hickory_client::udp::UdpClientConnection;
use hickory_proto::error::ProtoError;
use hickory_proto::rr::rdata::A;
use hickory_proto::xfer::DnsRequestSender;

use hickory_server::authority::{Authority, Catalog};
use hickory_server::ServerFuture;

use hickory_integration::example_authority::create_example;

#[cfg(feature = "dns-over-rustls")]
use hickory_integration::tls_client_connection::TlsClientConnection;
#[cfg(feature = "dns-over-rustls")]
use rustls::RootCertStore;

#[test]
#[allow(clippy::uninlined_format_args)]
fn test_server_www_udp() {
    let runtime = Runtime::new().expect("failed to create Tokio Runtime");
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0));
    let udp_socket = runtime.block_on(UdpSocket::bind(&addr)).unwrap();

    let ipaddr = udp_socket.local_addr().unwrap();
    println!("udp_socket on port: {}", ipaddr);
    let server_continue = Arc::new(AtomicBool::new(true));
    let server_continue2 = server_continue.clone();

    let server_thread = thread::Builder::new()
        .name("test_server:udp:server".to_string())
        .spawn(move || server_thread_udp(runtime, udp_socket, server_continue2))
        .unwrap();

    let client_thread = thread::Builder::new()
        .name("test_server:udp:client".to_string())
        .spawn(move || client_thread_www(lazy_udp_client(ipaddr)))
        .unwrap();

    let client_result = client_thread.join();

    assert!(client_result.is_ok(), "client failed: {:?}", client_result);
    server_continue.store(false, Ordering::Relaxed);
    server_thread.join().unwrap();
}

#[test]
#[allow(clippy::uninlined_format_args)]
fn test_server_www_tcp() {
    let runtime = Runtime::new().expect("failed to create Tokio Runtime");
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0));
    let tcp_listener = runtime.block_on(TcpListener::bind(&addr)).unwrap();

    let ipaddr = tcp_listener.local_addr().unwrap();
    println!("tcp_listner on port: {}", ipaddr);
    let server_continue = Arc::new(AtomicBool::new(true));
    let server_continue2 = server_continue.clone();

    let server_thread = thread::Builder::new()
        .name("test_server:tcp:server".to_string())
        .spawn(move || server_thread_tcp(runtime, tcp_listener, server_continue2))
        .unwrap();

    let client_thread = thread::Builder::new()
        .name("test_server:tcp:client".to_string())
        .spawn(move || client_thread_www(lazy_tcp_client(ipaddr)))
        .unwrap();

    let client_result = client_thread.join();

    assert!(client_result.is_ok(), "client failed: {:?}", client_result);
    server_continue.store(false, Ordering::Relaxed);
    server_thread.join().unwrap();
}

#[test]
fn test_server_unknown_type() {
    let runtime = Runtime::new().expect("failed to create Tokio Runtime");
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0));
    let udp_socket = runtime.block_on(UdpSocket::bind(&addr)).unwrap();

    let ipaddr = udp_socket.local_addr().unwrap();
    println!("udp_socket on port: {ipaddr}");
    let server_continue = Arc::new(AtomicBool::new(true));
    let server_continue2 = server_continue.clone();

    let server_thread = thread::Builder::new()
        .name("test_server:udp:server".to_string())
        .spawn(move || server_thread_udp(runtime, udp_socket, server_continue2))
        .unwrap();

    let conn = UdpClientConnection::new(ipaddr).unwrap();
    let client = SyncClient::new(conn);
    let client_result = client
        .query(
            &Name::from_str("www.example.com.").unwrap(),
            DNSClass::IN,
            RecordType::Unknown(65535),
        )
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
    server_thread.join().unwrap();
}

#[test]
fn test_server_form_error_on_multiple_queries() {
    let runtime = Runtime::new().expect("failed to create Tokio Runtime");
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0));
    let udp_socket = runtime.block_on(UdpSocket::bind(&addr)).unwrap();

    let ipaddr = udp_socket.local_addr().unwrap();
    println!("udp_socket on port: {ipaddr}");
    let server_continue = Arc::new(AtomicBool::new(true));
    let server_continue2 = server_continue.clone();

    let server_thread = thread::Builder::new()
        .name("test_server:udp:server".to_string())
        .spawn(move || server_thread_udp(runtime, udp_socket, server_continue2))
        .unwrap();

    let conn = UdpClientConnection::new(ipaddr).unwrap();
    let client = SyncClient::new(conn);

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

    let mut client_result = client.send(message);

    assert_eq!(client_result.len(), 1);
    let client_result = client_result
        .pop()
        .expect("there should be one response")
        .expect("should have been a successful network request");

    assert_eq!(client_result.response_code(), ResponseCode::FormErr);

    server_continue.store(false, Ordering::Relaxed);
    server_thread.join().unwrap();
}

#[test]
fn test_server_no_response_on_response() {
    let runtime = Runtime::new().expect("failed to create Tokio Runtime");
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0));
    let udp_socket = runtime.block_on(UdpSocket::bind(&addr)).unwrap();

    let ipaddr = udp_socket.local_addr().unwrap();
    println!("udp_socket on port: {}", ipaddr);
    let server_continue = Arc::new(AtomicBool::new(true));
    let server_continue2 = server_continue.clone();

    let server_thread = thread::Builder::new()
        .name("test_server:udp:server".to_string())
        .spawn(move || server_thread_udp(runtime, udp_socket, server_continue2))
        .unwrap();

    let conn = UdpClientConnection::new(ipaddr).unwrap();
    let client = SyncClient::new(conn);

    // build the message
    let query_a = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
    let mut message = Message::new();
    message
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .add_query(query_a);

    let client_result = client.send(message);
    assert_eq!(client_result.len(), 0);

    server_continue.store(false, Ordering::Relaxed);
    server_thread.join().unwrap();
}

#[cfg(feature = "dns-over-rustls")]
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
#[cfg(feature = "dns-over-rustls")]
#[test]
#[allow(clippy::uninlined_format_args)]
fn test_server_www_tls() {
    use hickory_proto::rustls::tls_server;
    use std::env;
    use std::path::Path;

    let dns_name = "ns.example.com";

    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "../..".to_owned());
    println!("using server src path: {}", server_path);

    let ca = tls_server::read_cert(Path::new(&format!(
        "{}/tests/test-data/ca.pem",
        server_path
    )))
    .map_err(|e| format!("error reading cert: {e}"))
    .unwrap();
    let cert = tls_server::read_cert(Path::new(&format!(
        "{}/tests/test-data/cert.pem",
        server_path
    )))
    .map_err(|e| format!("error reading cert: {e}"))
    .unwrap();
    let key = tls_server::read_key_from_pem(Path::new(&format!(
        "{}/tests/test-data/cert.key",
        server_path
    )))
    .unwrap();

    let cert_key = (cert, key);

    // Server address
    let runtime = Runtime::new().expect("failed to create Tokio Runtime");
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0));
    let tcp_listener = runtime.block_on(TcpListener::bind(&addr)).unwrap();

    let ipaddr = tcp_listener.local_addr().unwrap();
    println!("tcp_listner on port: {ipaddr}");
    let server_continue = Arc::new(AtomicBool::new(true));
    let server_continue2 = server_continue.clone();

    let server_thread = thread::Builder::new()
        .name("test_server:tls:server".to_string())
        .spawn(move || server_thread_tls(tcp_listener, server_continue2, cert_key, runtime))
        .unwrap();

    let client_thread = thread::Builder::new()
        .name("test_server:tcp:client".to_string())
        .spawn(move || client_thread_www(lazy_tls_client(ipaddr, dns_name.to_string(), ca)))
        .unwrap();

    let client_result = client_thread.join();

    assert!(client_result.is_ok(), "client failed: {:?}", client_result);
    server_continue.store(false, Ordering::Relaxed);
    server_thread.join().unwrap();
}

fn lazy_udp_client(ipaddr: SocketAddr) -> UdpClientConnection {
    UdpClientConnection::new(ipaddr).unwrap()
}

fn lazy_tcp_client(ipaddr: SocketAddr) -> TcpClientConnection {
    TcpClientConnection::new(ipaddr).unwrap()
}

#[cfg(feature = "dns-over-rustls")]
fn lazy_tls_client(
    ipaddr: SocketAddr,
    dns_name: String,
    cert_chain: Vec<rustls::Certificate>,
) -> TlsClientConnection<hickory_proto::iocompat::AsyncIoTokioAsStd<tokio::net::TcpStream>> {
    use rustls::ClientConfig;

    let mut root_store = RootCertStore::empty();
    let der_certs = cert_chain
        .into_iter()
        .map(|cert| cert.0)
        .collect::<Vec<_>>();
    let (_, ignored) = root_store.add_parsable_certificates(&der_certs);
    assert_eq!(ignored, 0, "bad certificate!");

    let config = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    TlsClientConnection::new(ipaddr, None, dns_name, Arc::new(config))
}

fn client_thread_www<C: ClientConnection>(conn: C)
where
    C::Sender: DnsRequestSender,
    C::SenderFuture: Future<Output = Result<C::Sender, ProtoError>> + 'static + Send,
{
    let name = Name::from_str("www.example.com").unwrap();
    let client = SyncClient::new(conn);

    let response = client
        .query(&name, DNSClass::IN, RecordType::A)
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

    if let RData::A(ref address) = *record.data().unwrap() {
        assert_eq!(address, &A::new(93, 184, 216, 34))
    } else {
        panic!();
    }
}

fn new_catalog() -> Catalog {
    let example = create_example();
    let origin = example.origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin, vec![Box::new(Arc::new(example))]);
    catalog
}

fn server_thread_udp(io_loop: Runtime, udp_socket: UdpSocket, server_continue: Arc<AtomicBool>) {
    let catalog = new_catalog();

    let mut server = ServerFuture::new(catalog);

    let _guard = io_loop.enter();
    server.register_socket(udp_socket);

    while server_continue.load(Ordering::Relaxed) {
        io_loop.block_on(future::lazy(|_| tokio::time::sleep(Duration::from_millis(10))).flatten());
    }

    _ = io_loop.block_on(server.shutdown_gracefully());
    drop(io_loop);
}

fn server_thread_tcp(
    io_loop: Runtime,
    tcp_listener: TcpListener,
    server_continue: Arc<AtomicBool>,
) {
    let catalog = new_catalog();
    let mut server = ServerFuture::new(catalog);

    let _guard = io_loop.enter();
    server.register_listener(tcp_listener, Duration::from_secs(30));

    while server_continue.load(Ordering::Relaxed) {
        io_loop.block_on(future::lazy(|_| tokio::time::sleep(Duration::from_millis(10))).flatten());
    }

    _ = io_loop.block_on(server.shutdown_gracefully());
}

// TODO: need a rustls option
#[cfg(feature = "dns-over-rustls")]
#[allow(unused)]
fn server_thread_tls(
    tls_listener: TcpListener,
    server_continue: Arc<AtomicBool>,
    cert_chain: (Vec<rustls::Certificate>, rustls::PrivateKey),
    io_loop: Runtime,
) {
    use hickory_server::config::dnssec::{self, CertType, PrivateKeyType, TlsCertConfig};
    use std::path::Path;

    let catalog = new_catalog();
    let mut server = ServerFuture::new(catalog);

    // let pkcs12 = Pkcs12::from_der(&pkcs12_der)
    //     .expect("bad pkcs12 der")
    //     .parse("mypass")
    //     .expect("Pkcs12::from_der");
    // let pkcs12 = ((pkcs12.cert, pkcs12.chain), pkcs12.pkey);
    io_loop.block_on(future::lazy(|_| {
        server
            .register_tls_listener(tls_listener, Duration::from_secs(30), cert_chain)
            .expect("failed to register TLS")
    }));

    while server_continue.load(Ordering::Relaxed) {
        io_loop.block_on(future::lazy(|_| tokio::time::sleep(Duration::from_millis(10))).flatten());
    }

    _ = io_loop.block_on(server.shutdown_gracefully());
}
