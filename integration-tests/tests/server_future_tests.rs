extern crate futures;
extern crate openssl;
extern crate rustls;
extern crate trust_dns;
extern crate trust_dns_integration;
extern crate trust_dns_openssl;
extern crate trust_dns_rustls;
extern crate trust_dns_server;

use std::env;
use std::fs::File;
use std::io;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use futures::Stream;
use openssl::pkcs12::Pkcs12;
use rustls::Certificate;

use trust_dns::client::*;
use trust_dns::op::*;
use trust_dns::rr::*;
use trust_dns::udp::UdpClientConnection;
use trust_dns::tcp::TcpClientConnection;
use trust_dns_rustls::TlsClientConnection;

use trust_dns_server::ServerFuture;
use trust_dns_server::authority::*;

use trust_dns_integration::authority::create_example;

#[test]
fn test_server_www_udp() {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0));
    let udp_socket = UdpSocket::bind(&addr).unwrap();

    let ipaddr = udp_socket.local_addr().unwrap();
    println!("udp_socket on port: {}", ipaddr);
    let server_continue = Arc::new(AtomicBool::new(true));
    let server_continue2 = server_continue.clone();

    let server_thread = thread::Builder::new()
        .name("test_server:udp:server".to_string())
        .spawn(move || server_thread_udp(udp_socket, server_continue2))
        .unwrap();

    let client_thread = thread::Builder::new()
        .name("test_server:udp:client".to_string())
        .spawn(move || client_thread_www(lazy_udp_client(ipaddr)))
        .unwrap();

    let client_result = client_thread.join();

    assert!(client_result.is_ok(), "client failed: {:?}", client_result);
    server_continue.store(false, Ordering::Relaxed);
    server_thread.join().unwrap();;
}

#[test]
fn test_server_www_tcp() {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0));
    let tcp_listener = TcpListener::bind(&addr).unwrap();

    let ipaddr = tcp_listener.local_addr().unwrap();
    println!("tcp_listner on port: {}", ipaddr);
    let server_continue = Arc::new(AtomicBool::new(true));
    let server_continue2 = server_continue.clone();

    let server_thread = thread::Builder::new()
        .name("test_server:tcp:server".to_string())
        .spawn(move || server_thread_tcp(tcp_listener, server_continue2))
        .unwrap();

    let client_thread = thread::Builder::new()
        .name("test_server:tcp:client".to_string())
        .spawn(move || client_thread_www(lazy_tcp_client(ipaddr)))
        .unwrap();

    let client_result = client_thread.join();

    assert!(client_result.is_ok(), "client failed: {:?}", client_result);
    server_continue.store(false, Ordering::Relaxed);
    server_thread.join().unwrap();;
}

#[test]
fn test_server_unknown_type() {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0));
    let udp_socket = UdpSocket::bind(&addr).unwrap();

    let ipaddr = udp_socket.local_addr().unwrap();
    println!("udp_socket on port: {}", ipaddr);
    let server_continue = Arc::new(AtomicBool::new(true));
    let server_continue2 = server_continue.clone();

    let server_thread = thread::Builder::new()
        .name("test_server:udp:server".to_string())
        .spawn(move || server_thread_udp(udp_socket, server_continue2))
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

    server_continue.store(false, Ordering::Relaxed);
    server_thread.join().unwrap();;
}

fn read_file(path: &str) -> Vec<u8> {
    let mut bytes = vec![];

    let mut file = File::open(path).expect(&format!("failed to open file: {}", path));
    file.read_to_end(&mut bytes)
        .expect(&format!("failed to read file: {}", path));
    bytes
}

#[test]
fn test_server_www_tls() {
    let dns_name = "ns.example.com";

    let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or("../server".to_owned());
    println!("using server src path: {}", server_path);

    let cert_der = read_file(&format!("{}/../tests/ca.der", server_path));

    let pkcs12_der = read_file(&format!("{}/../tests/cert.p12", server_path));

    // Server address
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0));
    let tcp_listener = TcpListener::bind(&addr).unwrap();

    let ipaddr = tcp_listener.local_addr().unwrap();
    println!("tcp_listner on port: {}", ipaddr);
    let server_continue = Arc::new(AtomicBool::new(true));
    let server_continue2 = server_continue.clone();

    let server_thread = thread::Builder::new()
        .name("test_server:tls:server".to_string())
        .spawn(move || {
            server_thread_tls(tcp_listener, server_continue2, pkcs12_der)
        })
        .unwrap();

    let client_thread = thread::Builder::new()
        .name("test_server:tcp:client".to_string())
        .spawn(move || {
            client_thread_www(lazy_tls_client(ipaddr, dns_name.to_string(), cert_der))
        })
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

fn lazy_tls_client(ipaddr: SocketAddr, dns_name: String, cert_der: Vec<u8>) -> TlsClientConnection {
    let mut builder = TlsClientConnection::builder();

    let trust_chain = Certificate(cert_der);

    builder.add_ca(trust_chain);
    builder.build(ipaddr, dns_name).unwrap()
}

fn client_thread_www<C: ClientConnection>(conn: C)
where
    C::MessageStream: Stream<Item = Vec<u8>, Error = io::Error> + 'static,
{
    let name = Name::from_labels(vec!["www", "example", "com"]);
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

    if let &RData::A(ref address) = record.rdata() {
        assert_eq!(address, &Ipv4Addr::new(93, 184, 216, 34))
    } else {
        assert!(false);
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
    catalog.upsert(origin.clone(), example);
    catalog
}

fn server_thread_udp(udp_socket: UdpSocket, server_continue: Arc<AtomicBool>) {
    let catalog = new_catalog();

    let mut server = ServerFuture::new(catalog).expect("new udp server failed");
    server.register_socket(udp_socket);

    while server_continue.load(Ordering::Relaxed) {
        server.tokio_core().turn(Some(Duration::from_millis(10)));
    }
}

fn server_thread_tcp(tcp_listener: TcpListener, server_continue: Arc<AtomicBool>) {
    let catalog = new_catalog();
    let mut server = ServerFuture::new(catalog).expect("new tcp server failed");
    server
        .register_listener(tcp_listener, Duration::from_secs(30))
        .expect("tcp registration failed");

    while server_continue.load(Ordering::Relaxed) {
        server.tokio_core().turn(Some(Duration::from_millis(10)));
    }
}

fn server_thread_tls(
    tls_listener: TcpListener,
    server_continue: Arc<AtomicBool>,
    pkcs12_der: Vec<u8>,
) {
    let catalog = new_catalog();
    let mut server = ServerFuture::new(catalog).expect("new tcp server failed");
    let pkcs12 = Pkcs12::from_der(&pkcs12_der)
        .expect("bad pkcs12 der")
        .parse("mypass")
        .expect("Pkcs12::from_der");
    server
        .register_tls_listener(tls_listener, Duration::from_secs(30), pkcs12)
        .expect("tcp registration failed");

    while server_continue.load(Ordering::Relaxed) {
        server.tokio_core().turn(Some(Duration::from_millis(10)));
    }
}
