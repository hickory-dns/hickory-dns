extern crate chrono;
extern crate futures;
extern crate openssl;
extern crate tokio_core;
extern crate trust_dns;
extern crate trust_dns_server;

use std::net::*;

use tokio_core::reactor::Core;

use trust_dns::client::{BasicClientHandle, ClientFuture, ClientHandle, MemoizeClientHandle, SecureClientHandle};
use trust_dns::op::ResponseCode;
use trust_dns::rr::domain;
use trust_dns::rr::{DNSClass, RData, RecordType};
use trust_dns::rr::dnssec::TrustAnchor;
use trust_dns::tcp::TcpClientStream;
use trust_dns::udp::UdpClientStream;

use trust_dns_server::authority::Catalog;
use trust_dns_server::authority::authority::create_secure_example;

mod common;
use common::TestClientStream;

#[test]
fn test_secure_query_example_nonet() {
  with_nonet(test_secure_query_example);
}

#[test]
#[ignore]
fn test_secure_query_example_udp() {
  with_udp(test_secure_query_example);
}

#[test]
#[ignore]
fn test_secure_query_example_tcp() {
  with_tcp(test_secure_query_example);
}

fn test_secure_query_example<H>(client: SecureClientHandle<H>, mut io_loop: Core)
where H: ClientHandle + 'static {
  let name = domain::Name::with_labels(vec!["www".to_string(), "example".to_string(), "com".to_string()]);
  let response = io_loop.run(client.query(name.clone(), DNSClass::IN, RecordType::A)).expect("query failed");

  println!("response records: {:?}", response);
  assert!(response.get_edns().expect("edns not here").is_dnssec_ok());

  assert!(!response.get_answers().is_empty());
  let record = &response.get_answers()[0];
  assert_eq!(record.get_name(), &name);
  assert_eq!(record.get_rr_type(), RecordType::A);
  assert_eq!(record.get_dns_class(), DNSClass::IN);

  if let &RData::A(ref address) = record.get_rdata() {
    assert_eq!(address, &Ipv4Addr::new(93,184,216,34))
  } else {
    assert!(false);
  }
}

#[test]
fn test_nsec_query_example_nonet() {
  with_nonet(test_nsec_query_example);
}

#[test]
#[ignore]
fn test_nsec_query_example_udp() {
  with_udp(test_nsec_query_example);
}

#[test]
#[ignore]
fn test_nsec_query_example_tcp() {
  with_tcp(test_nsec_query_example);
}

fn test_nsec_query_example<H>(client: SecureClientHandle<H>, mut io_loop: Core)
where H: ClientHandle + 'static {
  let name = domain::Name::with_labels(vec!["none".to_string(), "example".to_string(), "com".to_string()]);

  let response = io_loop.run(client.query(name.clone(), DNSClass::IN, RecordType::A)).expect("query failed");
  assert_eq!(response.get_response_code(), ResponseCode::NXDomain);
}

// TODO: NSEC response code wrong in Trust-DNS? Issue #53
// #[test]
// fn test_nsec_query_type_nonet() {
//   with_nonet(test_nsec_query_type);
// }

#[test]
#[ignore]
fn test_nsec_query_type_udp() {
  with_udp(test_nsec_query_type);
}

#[test]
#[ignore]
fn test_nsec_query_type_tcp() {
  with_tcp(test_nsec_query_type);
}

fn test_nsec_query_type<H>(client: SecureClientHandle<H>, mut io_loop: Core)
where H: ClientHandle + 'static {
  let name = domain::Name::with_labels(vec!["www".to_string(), "example".to_string(), "com".to_string()]);

  let response = io_loop.run(client.query(name.clone(), DNSClass::IN, RecordType::NS)).expect("query failed");

  assert_eq!(response.get_response_code(), ResponseCode::NoError);
  assert!(response.get_answers().is_empty());
}

#[test]
#[ignore]
fn test_dnssec_rollernet_td_udp() {
  with_udp(dnssec_rollernet_td_test);
}

#[test]
#[ignore]
fn test_dnssec_rollernet_td_tcp() {
  with_udp(dnssec_rollernet_td_test);
}

#[test]
#[ignore]
fn test_dnssec_rollernet_td_tcp_mixed_case() {
  with_tcp(dnssec_rollernet_td_mixed_case_test);
}

fn dnssec_rollernet_td_test<H>(client: SecureClientHandle<H>, mut io_loop: Core)
where H: ClientHandle + 'static {
  let name = domain::Name::parse("rollernet.us.", None).unwrap();

  let response = io_loop.run(client.query(name.clone(), DNSClass::IN, RecordType::DS)).expect("query failed");

  assert_eq!(response.get_response_code(), ResponseCode::NoError);
  // rollernet doesn't have any DS records...
  //  would have failed validation
  assert!(response.get_answers().is_empty());
}

fn dnssec_rollernet_td_mixed_case_test<H>(client: SecureClientHandle<H>, mut io_loop: Core)
where H: ClientHandle + 'static {
  let name = domain::Name::parse("RollErnet.Us.", None).unwrap();

  let response = io_loop.run(client.query(name.clone(), DNSClass::IN, RecordType::DS)).expect("query failed");

  assert_eq!(response.get_response_code(), ResponseCode::NoError);
  // rollernet doesn't have any DS records...
  //  would have failed validation
  assert!(response.get_answers().is_empty());
}

fn with_nonet<F>(test: F) where F: Fn(SecureClientHandle<MemoizeClientHandle<BasicClientHandle>>, Core) {
  let succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
  let succeeded_clone = succeeded.clone();
  std::thread::Builder::new().name("thread_killer".to_string()).spawn(move || {
    let succeeded = succeeded_clone.clone();
    for _ in 0..15 {
      std::thread::sleep(std::time::Duration::from_secs(1));
      if succeeded.load(std::sync::atomic::Ordering::Relaxed) { return }
    }

    panic!("timeout");
  }).unwrap();

  let authority = create_secure_example();

  let public_key = {
    let signers = authority.get_secure_keys();
    signers.first().expect("expected a key in the authority").get_public_key()
  };

  let mut catalog = Catalog::new();
  catalog.upsert(authority.get_origin().clone(), authority);

  let mut trust_anchor = TrustAnchor::new();
  trust_anchor.insert_trust_anchor(public_key);

  let io_loop = Core::new().unwrap();
  let (stream, sender) = TestClientStream::new(catalog, io_loop.handle());
  let client = ClientFuture::new(stream, sender, io_loop.handle(), None);
  let client = MemoizeClientHandle::new(client);
  let secure_client = SecureClientHandle::with_trust_anchor(client, trust_anchor);

  test(secure_client, io_loop);
  succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
}

fn with_udp<F>(test: F) where F: Fn(SecureClientHandle<MemoizeClientHandle<BasicClientHandle>>, Core) {
  let succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
  let succeeded_clone = succeeded.clone();
  std::thread::Builder::new().name("thread_killer".to_string()).spawn(move || {
    let succeeded = succeeded_clone.clone();
    for _ in 0..15 {
      std::thread::sleep(std::time::Duration::from_secs(1));
      if succeeded.load(std::sync::atomic::Ordering::Relaxed) { return }
    }

    panic!("timeout");
  }).unwrap();

  let io_loop = Core::new().unwrap();
  let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
  let (stream, sender) = UdpClientStream::new(addr, io_loop.handle());
  let client = ClientFuture::new(stream, sender, io_loop.handle(), None);
  let client = MemoizeClientHandle::new(client);
  let secure_client = SecureClientHandle::new(client);

  test(secure_client, io_loop);
  succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
}

fn with_tcp<F>(test: F) where F: Fn(SecureClientHandle<MemoizeClientHandle<BasicClientHandle>>, Core) {
  let succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
  let succeeded_clone = succeeded.clone();
  std::thread::Builder::new().name("thread_killer".to_string()).spawn(move || {
    let succeeded = succeeded_clone.clone();
    for _ in 0..15 {
      std::thread::sleep(std::time::Duration::from_secs(1));
      if succeeded.load(std::sync::atomic::Ordering::Relaxed) { return }
    }

    panic!("timeout");
  }).unwrap();

  let io_loop = Core::new().unwrap();
  let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
  let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
  let client = ClientFuture::new(stream, sender, io_loop.handle(), None);
  let client = MemoizeClientHandle::new(client);
  let secure_client = SecureClientHandle::new(client);

  test(secure_client, io_loop);
  succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
}
