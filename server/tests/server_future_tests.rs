extern crate chrono;
extern crate futures;
extern crate native_tls;
extern crate openssl;
#[cfg(target_os = "macos")]
extern crate security_framework;
extern crate trust_dns;
extern crate trust_dns_server;

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket, TcpListener};
use std::thread;
use std::time::Duration;

use futures::Stream;
use openssl::*;
use openssl::x509::extension::*;
#[cfg(target_os = "linux")]
use openssl::x509::X509 as OpensslX509;
#[cfg(target_os = "macos")]
use security_framework::certificate::SecCertificate;

use trust_dns::client::*;
use trust_dns::op::*;
use trust_dns::rr::*;
use trust_dns::udp::UdpClientConnection;
use trust_dns::tcp::TcpClientConnection;
use trust_dns::tls::TlsClientConnection;

use trust_dns_server::ServerFuture;
use trust_dns_server::authority::*;

mod common;
use common::authority::create_example;

#[test]
fn test_server_www_udp() {
  let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127,0,0,1), 0));
  let udp_socket = UdpSocket::bind(&addr).unwrap();

  let ipaddr = udp_socket.local_addr().unwrap();
  println!("udp_socket on port: {}", ipaddr);

  thread::Builder::new().name("test_server:udp:server".to_string()).spawn(move || server_thread_udp(udp_socket)).unwrap();

  let client_thread = thread::Builder::new().name("test_server:udp:client".to_string()).spawn(move || client_thread_www(lazy_udp_client(ipaddr))).unwrap();

  let client_result = client_thread.join();
  //    let server_result = server_thread.join();

  assert!(client_result.is_ok(), "client failed: {:?}", client_result);
  //    assert!(server_result.is_ok(), "server failed: {:?}", server_result);
}

#[test]
fn test_server_www_tcp() {
  let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127,0,0,1), 0));
  let tcp_listener = TcpListener::bind(&addr).unwrap();

  let ipaddr = tcp_listener.local_addr().unwrap();
  println!("tcp_listner on port: {}", ipaddr);

  thread::Builder::new().name("test_server:tcp:server".to_string()).spawn(move || server_thread_tcp(tcp_listener)).unwrap();

  let client_thread = thread::Builder::new().name("test_server:tcp:client".to_string()).spawn(move || client_thread_www(lazy_tcp_client(ipaddr))).unwrap();

  let client_result = client_thread.join();
  //    let server_result = server_thread.join();

  assert!(client_result.is_ok(), "client failed: {:?}", client_result);
  //    assert!(server_result.is_ok(), "server failed: {:?}", server_result);
}

#[test]
fn test_server_www_tls() {
  // Generate X509 certificate
  let subject_name = "ns.example.com";
  let rsa = rsa::Rsa::generate(2048).unwrap();
  let pkey = pkey::PKey::from_rsa(rsa).unwrap();

  let gen = x509::X509Generator::new()
                         .set_valid_period(365*2)
                         .add_name("CN".to_owned(), subject_name.to_string())
                         .set_sign_hash(hash::MessageDigest::sha256())
                         .add_extension(Extension::KeyUsage(vec![KeyUsageOption::DigitalSignature]));

  let cert = gen.sign(&pkey).unwrap();
  let cert_der = cert.to_der().unwrap();

  let pkcs12_builder = pkcs12::Pkcs12::builder();
  let pkcs12 = pkcs12_builder.build("mypassword", subject_name, &pkey, &cert).unwrap();
  let pkcs12_der = pkcs12.to_der().unwrap();

  // Server address
  let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127,0,0,1), 0));
  let tcp_listener = TcpListener::bind(&addr).unwrap();

  let ipaddr = tcp_listener.local_addr().unwrap();
  println!("tcp_listner on port: {}", ipaddr);

  thread::Builder::new().name("test_server:tls:server".to_string()).spawn(move || server_thread_tls(tcp_listener, pkcs12_der)).unwrap();

  let client_thread = thread::Builder::new().name("test_server:tcp:client".to_string()).spawn(move || client_thread_www(lazy_tls_client(ipaddr, subject_name.to_string(), cert_der))).unwrap();

  let client_result = client_thread.join();
  //    let server_result = server_thread.join();

  assert!(client_result.is_ok(), "client failed: {:?}", client_result);
  //    assert!(server_result.is_ok(), "server failed: {:?}", server_result);
}

fn lazy_udp_client(ipaddr: SocketAddr) -> UdpClientConnection {
  UdpClientConnection::new(ipaddr).unwrap()
}

fn lazy_tcp_client(ipaddr: SocketAddr) -> TcpClientConnection {
  TcpClientConnection::new(ipaddr).unwrap()
}

fn lazy_tls_client(ipaddr: SocketAddr, subject_name: String, cert_der: Vec<u8>) -> TlsClientConnection {
  let mut builder = TlsClientConnection::builder();

  #[cfg(target_os = "macos")]
  let trust_chain = SecCertificate::from_der(&cert_der).unwrap();

  #[cfg(target_os = "linux")]
  let trust_chain = OpensslX509::from_der(&cert_der).unwrap();

  builder.add_ca(trust_chain);
  builder.build(ipaddr, subject_name).unwrap()
}

fn client_thread_www<C: ClientConnection>(conn: C)
where C::MessageStream: Stream<Item=Vec<u8>, Error=io::Error> + 'static {
  let name = Name::with_labels(vec!["www".to_string(), "example".to_string(), "com".to_string()]);
  let client = SyncClient::new(conn);

  let response = client.query(&name, DNSClass::IN, RecordType::A).expect("error querying");

  assert!(response.get_response_code() == ResponseCode::NoError, "got an error: {:?}", response.get_response_code());

  let record = &response.get_answers()[0];
  assert_eq!(record.get_name(), &name);
  assert_eq!(record.get_rr_type(), RecordType::A);
  assert_eq!(record.get_dns_class(), DNSClass::IN);

  if let &RData::A(ref address) = record.get_rdata() {
    assert_eq!(address, &Ipv4Addr::new(93,184,216,34))
  } else {
    assert!(false);
  }

  let mut ns: Vec<_> = response.get_name_servers().to_vec();
  ns.sort();

  assert_eq!(ns.len(), 2);
  assert_eq!(ns.first().unwrap().get_rr_type(), RecordType::NS);
  assert_eq!(ns.first().unwrap().get_rdata(), &RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()) );
  assert_eq!(ns.last().unwrap().get_rr_type(), RecordType::NS);
  assert_eq!(ns.last().unwrap().get_rdata(), &RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()) );
}

fn new_catalog() -> Catalog {
  let example = create_example();
  let origin = example.get_origin().clone();

  let mut catalog: Catalog = Catalog::new();
  catalog.upsert(origin.clone(), example);
  catalog
}

fn server_thread_udp(udp_socket: UdpSocket) {
  let catalog = new_catalog();

  let mut server = ServerFuture::new(catalog).expect("new udp server failed");
  server.register_socket(udp_socket);

  server.listen().unwrap();
}

fn server_thread_tcp(tcp_listener: TcpListener) {
  let catalog = new_catalog();
  let mut server = ServerFuture::new(catalog).expect("new tcp server failed");
  server.register_listener(tcp_listener, Duration::from_secs(30)).expect("tcp registration failed");

  server.listen().unwrap();
}

fn server_thread_tls(tls_listener: TcpListener, pkcs12_der: Vec<u8>) {
  let catalog = new_catalog();
  let mut server = ServerFuture::new(catalog).expect("new tcp server failed");
  let pkcs12 = native_tls::Pkcs12::from_der(&pkcs12_der, "mypassword").expect("Pkcs12::from_der");
  server.register_tls_listener(tls_listener, Duration::from_secs(30), pkcs12).expect("tcp registration failed");

  server.listen().unwrap();
}
