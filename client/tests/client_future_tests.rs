extern crate chrono;
extern crate futures;
extern crate openssl;
extern crate tokio_core;
extern crate trust_dns;
extern crate trust_dns_server;

use std::fmt;
use std::io;
use std::net::*;
use std::cmp::Ordering;

use chrono::Duration;
use futures::{Async, Future, finished, Poll};
use futures::stream::{Fuse, Stream};
use futures::task::park;
use openssl::crypto::rsa::RSA;
use tokio_core::reactor::{Core, Handle};
use tokio_core::channel::{channel, Receiver};

use trust_dns::client::{ClientFuture, BasicClientHandle, ClientHandle, ClientStreamHandle};
use trust_dns::error::*;
use trust_dns::op::ResponseCode;
use trust_dns::rr::domain;
use trust_dns::rr::{DNSClass, RData, Record, RecordType};
use trust_dns::rr::dnssec::{Algorithm, Signer};
use trust_dns::rr::rdata::*;
use trust_dns::udp::UdpClientStream;
use trust_dns::tcp::TcpClientStream;
use trust_dns_server::authority::Catalog;
use trust_dns_server::authority::authority::{create_example};

mod common;
use common::TestClientStream;

#[test]
fn test_query_nonet() {
  let authority = create_example();
  let mut catalog = Catalog::new();
  catalog.upsert(authority.get_origin().clone(), authority);

  let mut io_loop = Core::new().unwrap();
  let (stream, sender) = TestClientStream::new(catalog, io_loop.handle());
  let client = ClientFuture::new(stream, sender, io_loop.handle(), None);

  io_loop.run(test_query(&client)).unwrap();
  io_loop.run(test_query(&client)).unwrap();
}

#[test]
#[ignore]
fn test_query_udp_ipv4() {
  use std::net::{SocketAddr, ToSocketAddrs};
  use tokio_core::reactor::Core;

  let mut io_loop = Core::new().unwrap();
  let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
  let (stream, sender) = UdpClientStream::new(addr, io_loop.handle());
  let client = ClientFuture::new(stream, sender, io_loop.handle(), None);

  // TODO: timeouts on these requests so that the test doesn't hang
  io_loop.run(test_query(&client)).unwrap();
  io_loop.run(test_query(&client)).unwrap();
}

#[test]
#[ignore]
fn test_query_udp_ipv6() {
  use std::net::{SocketAddr, ToSocketAddrs};
  use tokio_core::reactor::Core;

  let mut io_loop = Core::new().unwrap();
  let addr: SocketAddr = ("2001:4860:4860::8888",53).to_socket_addrs().unwrap().next().unwrap();
  let (stream, sender) = UdpClientStream::new(addr, io_loop.handle());
  let client = ClientFuture::new(stream, sender, io_loop.handle(), None);

  // TODO: timeouts on these requests so that the test doesn't hang
  io_loop.run(test_query(&client)).unwrap();
  io_loop.run(test_query(&client)).unwrap();
}

#[test]
#[ignore]
fn test_query_tcp_ipv4() {
  use std::net::{SocketAddr, ToSocketAddrs};
  use tokio_core::reactor::Core;

  let mut io_loop = Core::new().unwrap();
  let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
  let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
  let client = ClientFuture::new(stream, sender, io_loop.handle(), None);

  // TODO: timeouts on these requests so that the test doesn't hang
  io_loop.run(test_query(&client)).unwrap();
  io_loop.run(test_query(&client)).unwrap();
}

#[test]
#[ignore]
fn test_query_tcp_ipv6() {
  use std::net::{SocketAddr, ToSocketAddrs};
  use tokio_core::reactor::Core;

  let mut io_loop = Core::new().unwrap();
  let addr: SocketAddr = ("2001:4860:4860::8888",53).to_socket_addrs().unwrap().next().unwrap();
  let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
  let client = ClientFuture::new(stream, sender, io_loop.handle(), None);

  // TODO: timeouts on these requests so that the test doesn't hang
  io_loop.run(test_query(&client)).unwrap();
  io_loop.run(test_query(&client)).unwrap();
}

#[cfg(test)]
fn test_query(client: &BasicClientHandle) -> Box<Future<Item=(), Error=()>> {
  let name = domain::Name::with_labels(vec!["WWW".to_string(), "example".to_string(), "com".to_string()]);

  Box::new(client.query(name.clone(), DNSClass::IN, RecordType::A)
  .map(move |response| {
    println!("response records: {:?}", response);
    assert_eq!(response.get_queries().first().expect("expected query").get_name().cmp_with_case(&name, false), Ordering::Equal);

    let record = &response.get_answers()[0];
    assert_eq!(record.get_name(), &name);
    assert_eq!(record.get_rr_type(), RecordType::A);
    assert_eq!(record.get_dns_class(), DNSClass::IN);

    if let &RData::A(ref address) = record.get_rdata() {
      assert_eq!(address, &Ipv4Addr::new(93,184,216,34))
    } else {
      assert!(false);
    }
  })
  .map_err(|e| {
    assert!(false, "query failed: {}", e);
  })
)
}

// update tests
//

/// create a client with a sig0 section
fn create_sig0_ready_client(io_loop: &Core) -> (BasicClientHandle, domain::Name) {
  let mut authority = create_example();
  authority.set_allow_update(true);
  let origin = authority.get_origin().clone();

  let rsa = RSA::generate(512).unwrap();

  let signer = Signer::new(Algorithm::RSASHA256,
    rsa,
    domain::Name::with_labels(vec!["trusted".to_string(), "example".to_string(), "com".to_string()]),
    Duration::max_value());

    // insert the KEY for the trusted.example.com
    let mut auth_key = Record::with(domain::Name::with_labels(vec!["trusted".to_string(), "example".to_string(), "com".to_string()]),
    RecordType::KEY,
    Duration::minutes(5).num_seconds() as u32);
    auth_key.rdata(RData::KEY(DNSKEY::new(false, false, false, signer.get_algorithm(), signer.get_public_key())));
    authority.upsert(auth_key, 0);

    // setup the catalog
    let mut catalog = Catalog::new();
    catalog.upsert(authority.get_origin().clone(), authority);

    let (stream, sender) = TestClientStream::new(catalog, io_loop.handle());
    let client = ClientFuture::new(stream, sender, io_loop.handle(), Some(signer));

    (client, origin)
  }

  #[test]
  fn test_create() {
    let mut io_loop = Core::new().unwrap();
    let (client, origin) = create_sig0_ready_client(&io_loop);

    // create a record
    let mut record = Record::with(domain::Name::with_labels(vec!["new".to_string(), "example".to_string(), "com".to_string()]),
    RecordType::A,
    Duration::minutes(5).num_seconds() as u32);
    record.rdata(RData::A(Ipv4Addr::new(100,10,100,10)));


    let result = io_loop.run(client.create(record.clone(), origin.clone())).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);
    let result = io_loop.run(client.query(record.get_name().clone(), record.get_dns_class(), record.get_rr_type())).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);
    assert_eq!(result.get_answers().len(), 1);
    assert_eq!(result.get_answers()[0], record);

    // trying to create again should error
    // TODO: it would be cool to make this
    let result = io_loop.run(client.create(record.clone(), origin.clone())).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::YXRRSet);

    // will fail if already set and not the same value.
    let mut record = record.clone();
    record.rdata(RData::A(Ipv4Addr::new(101,11,101,11)));

    let result = io_loop.run(client.create(record.clone(), origin.clone())).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::YXRRSet);
  }

  #[test]
  fn test_append() {
    let mut io_loop = Core::new().unwrap();
    let (client, origin) = create_sig0_ready_client(&io_loop);

    // append a record
    let mut record = Record::with(domain::Name::with_labels(vec!["new".to_string(), "example".to_string(), "com".to_string()]),
    RecordType::A,
    Duration::minutes(5).num_seconds() as u32);
    record.rdata(RData::A(Ipv4Addr::new(100,10,100,10)));

    // first check the must_exist option
    let result = io_loop.run(client.append(record.clone(), origin.clone(), true)).expect("append failed");
    assert_eq!(result.get_response_code(), ResponseCode::NXRRSet);

    // next append to a non-existent RRset
    let result = io_loop.run(client.append(record.clone(), origin.clone(), false)).expect("append failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop.run(client.query(record.get_name().clone(), record.get_dns_class(), record.get_rr_type())).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);
    assert_eq!(result.get_answers().len(), 1);
    assert_eq!(result.get_answers()[0], record);

    // will fail if already set and not the same value.
    let mut record = record.clone();
    record.rdata(RData::A(Ipv4Addr::new(101,11,101,11)));

    let result = io_loop.run(client.append(record.clone(), origin.clone(), true)).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let result = io_loop.run(client.query(record.get_name().clone(), record.get_dns_class(), record.get_rr_type())).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);
    assert_eq!(result.get_answers().len(), 2);

    assert!(result.get_answers().iter().any(|rr| if let &RData::A(ref ip) = rr.get_rdata() { *ip ==  Ipv4Addr::new(100,10,100,10) } else { false }));
    assert!(result.get_answers().iter().any(|rr| if let &RData::A(ref ip) = rr.get_rdata() { *ip ==  Ipv4Addr::new(101,11,101,11) } else { false }));

    // show that appending the same thing again is ok, but doesn't add any records
    let result = io_loop.run(client.append(record.clone(), origin.clone(), true)).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let result = io_loop.run(client.query(record.get_name().clone(), record.get_dns_class(), record.get_rr_type())).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);
    assert_eq!(result.get_answers().len(), 2);
  }

  #[test]
  fn test_compare_and_swap() {
    let mut io_loop = Core::new().unwrap();
    let (client, origin) = create_sig0_ready_client(&io_loop);

    // create a record
    let mut record = Record::with(domain::Name::with_labels(vec!["new".to_string(), "example".to_string(), "com".to_string()]),
    RecordType::A,
    Duration::minutes(5).num_seconds() as u32);
    record.rdata(RData::A(Ipv4Addr::new(100,10,100,10)));

    let result = io_loop.run(client.create(record.clone(), origin.clone())).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let current = record;
    let mut new = current.clone();
    new.rdata(RData::A(Ipv4Addr::new(101,11,101,11)));

    let result = io_loop.run(client.compare_and_swap(current.clone(), new.clone(), origin.clone())).expect("compare_and_swap failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let result = io_loop.run(client.query(new.get_name().clone(), new.get_dns_class(), new.get_rr_type())).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);
    assert_eq!(result.get_answers().len(), 1);
    assert!(result.get_answers().iter().any(|rr| if let &RData::A(ref ip) = rr.get_rdata() { *ip ==  Ipv4Addr::new(101,11,101,11) } else { false }));

    // check the it fails if tried again.
    let mut new = new;
    new.rdata(RData::A(Ipv4Addr::new(102,12,102,12)));

    let result = io_loop.run(client.compare_and_swap(current, new.clone(), origin.clone())).expect("compare_and_swap failed");
    assert_eq!(result.get_response_code(), ResponseCode::NXRRSet);

    let result = io_loop.run(client.query(new.get_name().clone(), new.get_dns_class(), new.get_rr_type())).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);
    assert_eq!(result.get_answers().len(), 1);
    assert!(result.get_answers().iter().any(|rr| if let &RData::A(ref ip) = rr.get_rdata() { *ip ==  Ipv4Addr::new(101,11,101,11) } else { false }));
  }

  #[test]
  fn test_delete_by_rdata() {
    let mut io_loop = Core::new().unwrap();
    let (client, origin) = create_sig0_ready_client(&io_loop);

    // append a record
    let mut record = Record::with(domain::Name::with_labels(vec!["new".to_string(), "example".to_string(), "com".to_string()]),
    RecordType::A,
    Duration::minutes(5).num_seconds() as u32);
    record.rdata(RData::A(Ipv4Addr::new(100,10,100,10)));

    // first check the must_exist option
    let result = io_loop.run(client.delete_by_rdata(record.clone(), origin.clone())).expect("delete failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop.run(client.create(record.clone(), origin.clone())).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let mut record = record.clone();
    record.rdata(RData::A(Ipv4Addr::new(101,11,101,11)));
    let result = io_loop.run(client.append(record.clone(), origin.clone(), true)).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop.run(client.delete_by_rdata(record.clone(), origin.clone())).expect("delete failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let result = io_loop.run(client.query(record.get_name().clone(), record.get_dns_class(), record.get_rr_type())).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);
    assert_eq!(result.get_answers().len(), 1);
    assert!(result.get_answers().iter().any(|rr| if let &RData::A(ref ip) = rr.get_rdata() { *ip ==  Ipv4Addr::new(100,10,100,10) } else { false }));
  }

  #[test]
  fn test_delete_rrset() {
    let mut io_loop = Core::new().unwrap();
    let (client, origin) = create_sig0_ready_client(&io_loop);

    // append a record
    let mut record = Record::with(domain::Name::with_labels(vec!["new".to_string(), "example".to_string(), "com".to_string()]),
    RecordType::A,
    Duration::minutes(5).num_seconds() as u32);
    record.rdata(RData::A(Ipv4Addr::new(100,10,100,10)));

    // first check the must_exist option
    let result = io_loop.run(client.delete_rrset(record.clone(), origin.clone())).expect("delete failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop.run(client.create(record.clone(), origin.clone())).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let mut record = record.clone();
    record.rdata(RData::A(Ipv4Addr::new(101,11,101,11)));
    let result = io_loop.run(client.append(record.clone(), origin.clone(), true)).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop.run(client.delete_rrset(record.clone(), origin.clone())).expect("delete failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let result = io_loop.run(client.query(record.get_name().clone(), record.get_dns_class(), record.get_rr_type())).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NXDomain);
    assert_eq!(result.get_answers().len(), 0);
  }

  #[test]
  fn test_delete_all() {
    let mut io_loop = Core::new().unwrap();
    let (client, origin) = create_sig0_ready_client(&io_loop);

    // append a record
    let mut record = Record::with(domain::Name::with_labels(vec!["new".to_string(), "example".to_string(), "com".to_string()]),
    RecordType::A,
    Duration::minutes(5).num_seconds() as u32);
    record.rdata(RData::A(Ipv4Addr::new(100,10,100,10)));

    // first check the must_exist option
    let result = io_loop.run(client.delete_all(record.get_name().clone(), origin.clone(), DNSClass::IN)).expect("delete failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop.run(client.create(record.clone(), origin.clone())).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let mut record = record.clone();
    record.rr_type(RecordType::AAAA);
    record.rdata(RData::AAAA(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)));
    let result = io_loop.run(client.create(record.clone(), origin.clone())).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop.run(client.delete_all(record.get_name().clone(), origin.clone(), DNSClass::IN)).expect("delete failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let result = io_loop.run(client.query(record.get_name().clone(), record.get_dns_class(), RecordType::A)).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NXDomain);
    assert_eq!(result.get_answers().len(), 0);

    let result = io_loop.run(client.query(record.get_name().clone(), record.get_dns_class(), RecordType::AAAA)).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NXDomain);
    assert_eq!(result.get_answers().len(), 0);
  }

  // need to do something with the message channel, otherwise the ClientFuture will think there
  //  is no one listening to messages and shutdown...
  #[allow(dead_code)]
  pub struct NeverReturnsClientStream {
    outbound_messages: Fuse<Receiver<Vec<u8>>>,
  }

  impl NeverReturnsClientStream {
    pub fn new(loop_handle: Handle) -> (Box<Future<Item=Self, Error=io::Error>>, Box<ClientStreamHandle>) {
      let (message_sender, outbound_messages) = channel(&loop_handle).expect("somethings wrong with the event loop");

      let stream: Box<Future<Item=NeverReturnsClientStream, Error=io::Error>> = Box::new(finished(
        NeverReturnsClientStream {
          outbound_messages: outbound_messages.fuse()
        }
      ));

      (stream, Box::new(message_sender))
    }
  }

  impl Stream for NeverReturnsClientStream {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
      // always not ready...
      park().unpark();
      Ok(Async::NotReady)
    }
  }

  impl fmt::Debug for NeverReturnsClientStream {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
      write!(f, "TestClientStream catalog")
    }
  }

  #[test]
  fn test_timeout_query_nonet() {
    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.get_origin().clone(), authority);

    let mut io_loop = Core::new().unwrap();
    let (stream, sender) = NeverReturnsClientStream::new(io_loop.handle());
    let client = ClientFuture::with_timeout(stream, sender, io_loop.handle(),
    std::time::Duration::from_millis(1), None);

    let name = domain::Name::with_labels(vec!["www".to_string(), "example".to_string(), "com".to_string()]);

    if let &ClientErrorKind::Timeout = io_loop.run(client.query(name.clone(), DNSClass::IN, RecordType::A)).unwrap_err().kind() {
      ()
    } else {
      assert!(false);
    }


    // test that we don't have any thing funky with registering new timeouts, etc...
    if let &ClientErrorKind::Timeout = io_loop.run(client.query(name.clone(), DNSClass::IN, RecordType::AAAA)).unwrap_err().kind() {
      ()
    } else {
      assert!(false);
    }
  }
