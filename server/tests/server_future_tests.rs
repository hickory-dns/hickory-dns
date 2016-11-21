extern crate mio;
extern crate trust_dns;
extern crate trust_dns_server;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket, TcpListener};
use std::thread;
use std::time::Duration;

use trust_dns::client::*;
use trust_dns::op::*;
use trust_dns::rr::*;
use trust_dns::udp::UdpClientConnection;
use trust_dns::tcp::TcpClientConnection;

use trust_dns_server::ServerFuture;
use trust_dns_server::authority::*;
use trust_dns_server::authority::authority::create_example;


#[test]
fn test_server_www_udp() {
  let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127,0,0,1), 0));
  let udp_socket = UdpSocket::bind(&addr).unwrap();

  let ipaddr = udp_socket.local_addr().unwrap();
  println!("udp_socket on port: {}", ipaddr);

  thread::Builder::new().name("test_server:udp:server".to_string()).spawn(move || server_thread_udp(udp_socket)).unwrap();

  let client_conn = UdpClientConnection::new(ipaddr).unwrap();
  let client_thread = thread::Builder::new().name("test_server:udp:client".to_string()).spawn(move || client_thread_www(client_conn)).unwrap();

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

  let client_conn = TcpClientConnection::new(ipaddr).unwrap();
  let client_thread = thread::Builder::new().name("test_server:tcp:client".to_string()).spawn(move || client_thread_www(client_conn)).unwrap();

  let client_result = client_thread.join();
  //    let server_result = server_thread.join();

  assert!(client_result.is_ok(), "client failed: {:?}", client_result);
  //    assert!(server_result.is_ok(), "server failed: {:?}", server_result);
}

fn client_thread_www<C: ClientConnection>(conn: C) {
  let name = Name::with_labels(vec!["www".to_string(), "example".to_string(), "com".to_string()]);
  println!("about to query server: {:?}", conn);
  let client = Client::new(conn);

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
  server.register_listener(tcp_listener, Duration::from_secs(30));

  server.listen().unwrap();
}
