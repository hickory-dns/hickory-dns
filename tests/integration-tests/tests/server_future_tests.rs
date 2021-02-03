use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use futures::{future, Future, FutureExt};
use tokio::net::TcpListener;
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;

use trust_dns_client::client::*;
use trust_dns_client::op::*;
use trust_dns_client::rr::*;
use trust_dns_client::tcp::TcpClientConnection;
use trust_dns_client::udp::UdpClientConnection;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::xfer::DnsRequestSender;

use trust_dns_server::authority::{Authority, Catalog};
use trust_dns_server::ServerFuture;

use trust_dns_integration::authority::create_example;

#[cfg(all(feature = "dns-over-openssl", not(feature = "dns-over-rustls")))]
use trust_dns_integration::tls_client_connection::TlsClientConnection;

#[test]
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
    println!("udp_socket on port: {}", ipaddr);
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

#[cfg(all(feature = "dns-over-openssl", not(feature = "dns-over-rustls")))]
fn read_file(path: &str) -> Vec<u8> {
    use std::fs::File;
    use std::io::Read;

    let mut bytes = vec![];

    let mut file = File::open(path).expect(&format!("failed to open file: {}", path));
    file.read_to_end(&mut bytes)
        .expect(&format!("failed to read file: {}", path));
    bytes
}

// TODO: move all this to future based clients
#[cfg(all(feature = "dns-over-openssl", not(feature = "dns-over-rustls")))]
#[test]

fn test_server_www_tls() {
    use std::env;

    let dns_name = "ns.example.com";

    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or("../..".to_owned());
    println!("using server src path: {}", server_path);

    let cert_der = read_file(&format!("{}/tests/test-data/ca.der", server_path));

    let pkcs12_der = read_file(&format!("{}/tests/test-data/cert.p12", server_path));

    // Server address
    let runtime = Runtime::new().expect("failed to create Tokio Runtime");
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0));
    let tcp_listener = runtime.block_on(TcpListener::bind(&addr)).unwrap();

    let ipaddr = tcp_listener.local_addr().unwrap();
    println!("tcp_listner on port: {}", ipaddr);
    let server_continue = Arc::new(AtomicBool::new(true));
    let server_continue2 = server_continue.clone();

    let server_thread = thread::Builder::new()
        .name("test_server:tls:server".to_string())
        .spawn(move || server_thread_tls(tcp_listener, server_continue2, pkcs12_der, runtime))
        .unwrap();

    let client_thread = thread::Builder::new()
        .name("test_server:tcp:client".to_string())
        .spawn(move || client_thread_www(lazy_tls_client(ipaddr, dns_name.to_string(), cert_der)))
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

#[cfg(all(feature = "dns-over-openssl", not(feature = "dns-over-rustls")))]
fn lazy_tls_client(
    ipaddr: SocketAddr,
    dns_name: String,
    cert_der: Vec<u8>,
) -> TlsClientConnection<trust_dns_proto::iocompat::AsyncIoTokioAsStd<tokio::net::TcpStream>> {
    use rustls::{Certificate, ClientConfig};

    let trust_chain = Certificate(cert_der);
    let mut config = ClientConfig::new();
    config
        .root_store
        .add(&trust_chain)
        .expect("bad certificate");

    TlsClientConnection::new(ipaddr, dns_name, Arc::new(config))
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

    assert!(
        response.response_code() == ResponseCode::NoError,
        "got an error: {:?}",
        response.response_code()
    );

    let record = &response.answers()[0];
    assert_eq!(record.name(), &name);
    assert_eq!(record.rr_type(), RecordType::A);
    assert_eq!(record.dns_class(), DNSClass::IN);

    if let RData::A(ref address) = *record.rdata() {
        assert_eq!(address, &Ipv4Addr::new(93, 184, 216, 34))
    } else {
        panic!();
    }

    let mut ns: Vec<_> = response.name_servers().to_vec();
    ns.sort();

    assert_eq!(ns.len(), 2);
    assert_eq!(ns.first().unwrap().rr_type(), RecordType::NS);
    assert_eq!(
        ns.first().unwrap().rdata(),
        &RData::NS(Name::parse("a.iana-servers.net.", None).unwrap())
    );
    assert_eq!(ns.last().unwrap().rr_type(), RecordType::NS);
    assert_eq!(
        ns.last().unwrap().rdata(),
        &RData::NS(Name::parse("b.iana-servers.net.", None).unwrap())
    );
}

fn new_catalog() -> Catalog {
    let example = create_example();
    let origin = example.origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin, Box::new(Arc::new(RwLock::new(example))));
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
}

// TODO: need a rustls option
#[cfg(all(feature = "dns-over-openssl", not(feature = "dns-over-rustls")))]
fn server_thread_tls(
    tls_listener: TcpListener,
    server_continue: Arc<AtomicBool>,
    pkcs12_der: Vec<u8>,
    io_loop: Runtime,
) {
    use openssl::pkcs12::Pkcs12;

    let catalog = new_catalog();
    let mut server = ServerFuture::new(catalog);
    let pkcs12 = Pkcs12::from_der(&pkcs12_der)
        .expect("bad pkcs12 der")
        .parse("mypass")
        .expect("Pkcs12::from_der");
    let pkcs12 = ((pkcs12.cert, pkcs12.chain), pkcs12.pkey);
    io_loop.block_on(future::lazy(|_| {
        server
            .register_tls_listener(tls_listener, Duration::from_secs(30), pkcs12)
            .expect("failed to register TLS")
    }));

    while server_continue.load(Ordering::Relaxed) {
        io_loop.block_on(future::lazy(|_| tokio::time::sleep(Duration::from_millis(10))).flatten());
    }
}
