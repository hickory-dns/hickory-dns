extern crate chrono;
extern crate futures;
extern crate openssl;
extern crate trust_dns;
extern crate trust_dns_server;

use std::net::*;
use std::fmt;

use chrono::Duration;
use openssl::rsa::Rsa;

#[allow(deprecated)]
use trust_dns::client::{Client, ClientConnection};
use trust_dns::error::*;
use trust_dns::op::*;
use trust_dns::rr::{DNSClass, Record, RecordType, domain, RData};
use trust_dns::rr::dnssec::{Algorithm, KeyPair, Signer, TrustAnchor};
use trust_dns::rr::rdata::*;
use trust_dns::serialize::binary::{BinDecoder, BinEncoder, BinSerializable};
use trust_dns::tcp::TcpClientConnection;
use trust_dns::udp::UdpClientConnection;

use trust_dns_server::authority::Catalog;

mod common;
use common::authority::{create_example, create_secure_example};

pub struct TestClientConnection<'a> {
  catalog: &'a Catalog
}

impl<'a> TestClientConnection<'a> {
  pub fn new(catalog: &'a Catalog) -> TestClientConnection<'a> {
    TestClientConnection { catalog: catalog }
  }
}

impl<'a> ClientConnection for TestClientConnection<'a> {
  fn send(&mut self, bytes: Vec<u8>) -> ClientResult<Vec<u8>> {
    let mut decoder = BinDecoder::new(&bytes);

    let message = try!(Message::read(&mut decoder));
    let response = self.catalog.handle_request(&message);

    let mut buf = Vec::with_capacity(512);
    {
      let mut encoder = BinEncoder::new(&mut buf);
      try!(response.emit(&mut encoder));
    }

    Ok(buf)
  }
}

impl<'a> fmt::Debug for TestClientConnection<'a> {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "TestClientConnection catalog")
  }
}

#[test]
#[allow(deprecated)]
fn test_query_nonet() {
  let authority = create_example();
  let mut catalog = Catalog::new();
  catalog.upsert(authority.get_origin().clone(), authority);

  let client = Client::new(TestClientConnection::new(&catalog));

  test_query(client);
}

#[test]
#[ignore]
#[allow(deprecated)]
fn test_query_udp() {
  let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
  let conn = UdpClientConnection::new(addr).unwrap();
  let client = Client::new(conn);

  test_query(client);
}

#[test]
#[ignore]
#[allow(deprecated)]
fn test_query_tcp() {
  let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
  let conn = TcpClientConnection::new(addr).unwrap();
  let client = Client::new(conn);

  test_query(client);
}

#[allow(deprecated)]
fn test_query<C: ClientConnection>(client: Client<C>) {
  use std::cmp::Ordering;
  let name = domain::Name::with_labels(vec!["WWW".to_string(), "example".to_string(), "com".to_string()]);

  let response = client.query(&name, DNSClass::IN, RecordType::A);
  assert!(response.is_ok(), "query failed: {}", response.unwrap_err());

  let response = response.unwrap();

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
}

#[test]
#[allow(deprecated)]
fn test_secure_query_example_nonet() {
  let authority = create_secure_example();

  let trust_anchor = {
    let signers = authority.get_secure_keys();
    let public_key = signers.first().expect("expected a key in the authority").get_key();

    let mut trust_anchor = TrustAnchor::new();
    trust_anchor.insert_trust_anchor(public_key.to_public_bytes().expect("to_vec failed"));

    trust_anchor
  };

  let mut catalog = Catalog::new();
  catalog.upsert(authority.get_origin().clone(), authority);

  let client = Client::with_trust_anchor(TestClientConnection::new(&catalog), trust_anchor);

  test_secure_query_example(client);
}

#[test]
#[ignore]
#[allow(deprecated)]
fn test_secure_query_example_udp() {
  let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
  let conn = UdpClientConnection::new(addr).unwrap();
  let client = Client::new(conn);

  test_secure_query_example(client);
}

#[test]
#[ignore]
#[allow(deprecated)]
fn test_secure_query_example_tcp() {
  let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
  let conn = TcpClientConnection::new(addr).unwrap();
  let client = Client::new(conn);

  test_secure_query_example(client);
}

#[allow(deprecated)]
fn test_secure_query_example<C: ClientConnection>(client: Client<C>) {
  let name = domain::Name::with_labels(vec!["www".to_string(), "example".to_string(), "com".to_string()]);
  let response = client.secure_query(&name, DNSClass::IN, RecordType::A);

  assert!(response.is_ok(), "query for {} failed: {}", name, response.unwrap_err());

  let response = response.unwrap();

  println!("response records: {:?}", response);
  assert!(response.get_edns().expect("edns not here").is_dnssec_ok());

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
#[ignore]
#[allow(deprecated)]
fn test_dnssec_rollernet_td_udp() {
  let c = Client::new(UdpClientConnection::new("8.8.8.8:53".parse().unwrap()).unwrap());
  c.secure_query(
    &domain::Name::parse("rollernet.us.", None).unwrap(),
    DNSClass::IN,
    RecordType::DS,
  ).unwrap();
}

#[test]
#[ignore]
#[allow(deprecated)]
fn test_dnssec_rollernet_td_tcp() {
  let c = Client::new(TcpClientConnection::new("8.8.8.8:53".parse().unwrap()).unwrap());
  c.secure_query(
    &domain::Name::parse("rollernet.us.", None).unwrap(),
    DNSClass::IN,
    RecordType::DS,
  ).unwrap();
}

#[test]
#[ignore]
#[allow(deprecated)]
fn test_dnssec_rollernet_td_tcp_mixed_case() {
  let c = Client::new(TcpClientConnection::new("8.8.8.8:53".parse().unwrap()).unwrap());
  c.secure_query(
    &domain::Name::parse("RollErnet.Us.", None).unwrap(),
    DNSClass::IN,
    RecordType::DS,
  ).unwrap();
}

#[test]
#[allow(deprecated)]
fn test_nsec_query_example_nonet() {
  let authority = create_secure_example();

  let trust_anchor = {
    let signers = authority.get_secure_keys();
    let public_key = signers.first().expect("expected a key in the authority").get_key();

    let mut trust_anchor = TrustAnchor::new();
    trust_anchor.insert_trust_anchor(public_key.to_public_bytes().expect("to_vec failed"));

    trust_anchor
  };

  let mut catalog = Catalog::new();
  catalog.upsert(authority.get_origin().clone(), authority);

  let client = Client::with_trust_anchor(TestClientConnection::new(&catalog), trust_anchor);

  test_nsec_query_example(client);
}

#[test]
#[ignore]
#[allow(deprecated)]
fn test_nsec_query_example_udp() {
  let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
  let conn = UdpClientConnection::new(addr).unwrap();
  let client = Client::new(conn);
  test_nsec_query_example(client);
}

#[test]
#[ignore]
#[allow(deprecated)]
fn test_nsec_query_example_tcp() {
  let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
  let conn = TcpClientConnection::new(addr).unwrap();
  let client = Client::new(conn);
  test_nsec_query_example(client);
}

#[allow(deprecated)]
fn test_nsec_query_example<C: ClientConnection>(client: Client<C>) {
  let name = domain::Name::with_labels(vec!["none".to_string(), "example".to_string(), "com".to_string()]);

  let response = client.secure_query(&name, DNSClass::IN, RecordType::A);
  assert!(response.is_ok(), "query failed: {}", response.unwrap_err());

  let response = response.unwrap();
  assert_eq!(response.get_response_code(), ResponseCode::NXDomain);
}


#[test]
#[ignore]
#[allow(deprecated)]
fn test_nsec_query_type() {
  let name = domain::Name::with_labels(vec!["www".to_string(), "example".to_string(), "com".to_string()]);

  let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
  let conn = TcpClientConnection::new(addr).unwrap();
  let client = Client::new(conn);

  let response = client.secure_query(&name, DNSClass::IN, RecordType::NS);
  assert!(response.is_ok(), "query failed: {}", response.unwrap_err());

  let response = response.unwrap();
  // TODO: it would be nice to verify that the NSEC records were validated...
  assert_eq!(response.get_response_code(), ResponseCode::NoError);
  assert!(response.get_answers().is_empty());
}

// TODO: disabled until I decide what to do with NSEC3 see issue #10
//
// TODO these NSEC3 tests don't work, it seems that the zone is not signed properly.
// #[test]
// #[ignore]
// fn test_nsec3_sdsmt() {
//   let addr: SocketAddr = ("75.75.75.75",53).to_socket_addrs().unwrap().next().unwrap();
//   let conn = TcpClientConnection::new(addr).unwrap();
//   let name = domain::Name::with_labels(vec!["none".to_string(), "sdsmt".to_string(), "edu".to_string()]);
//   let client = Client::new(conn);
//
//   let response = client.secure_query(&name, DNSClass::IN, RecordType::NS);
//   assert!(response.is_ok(), "query failed: {}", response.unwrap_err());
//
//   let response = response.unwrap();
//   assert_eq!(response.get_response_code(), ResponseCode::NXDomain);
// }

// TODO: disabled until I decide what to do with NSEC3 see issue #10
//
// #[test]
// #[ignore]
// fn test_nsec3_sdsmt_type() {
//   let addr: SocketAddr = ("75.75.75.75",53).to_socket_addrs().unwrap().next().unwrap();
//   let conn = TcpClientConnection::new(addr).unwrap();
//   let name = domain::Name::with_labels(vec!["www".to_string(), "sdsmt".to_string(), "edu".to_string()]);
//   let client = Client::new(conn);
//
//   let response = client.secure_query(&name, DNSClass::IN, RecordType::NS);
//   assert!(response.is_ok(), "query failed: {}", response.unwrap_err());
//
//   let response = response.unwrap();
//   assert_eq!(response.get_response_code(), ResponseCode::NXDomain);
// }

#[allow(deprecated)]
fn create_sig0_ready_client<'a>(catalog: &'a mut Catalog) -> (Client<TestClientConnection<'a>>, Signer, domain::Name) {
  let mut authority = create_example();
  authority.set_allow_update(true);
  let origin = authority.get_origin().clone();

  let rsa = Rsa::generate(512).unwrap();
  let key = KeyPair::from_rsa(rsa).unwrap();

  let signer = Signer::new(Algorithm::RSASHA256, key,
    domain::Name::with_labels(vec!["trusted".to_string(), "example".to_string(), "com".to_string()]),
    Duration::max_value(), true, true);

  // insert the KEY for the trusted.example.com
  let mut auth_key = Record::with(domain::Name::with_labels(vec!["trusted".to_string(), "example".to_string(), "com".to_string()]),
  RecordType::KEY,
  Duration::minutes(5).num_seconds() as u32);
  auth_key.rdata(RData::KEY(DNSKEY::new(false, false, false, signer.get_algorithm(), signer.get_key().to_public_bytes().expect("to_vec failed"))));
  authority.upsert(auth_key, 0);

  catalog.upsert(authority.get_origin().clone(), authority);
  let client = Client::new(TestClientConnection::new(catalog));

  (client, signer, origin)
}

#[test]
fn test_create() {
  let mut catalog = Catalog::new();
  let (client, signer, origin) = create_sig0_ready_client(&mut catalog);

  // create a record
  let mut record = Record::with(domain::Name::with_labels(vec!["new".to_string(), "example".to_string(), "com".to_string()]),
  RecordType::A,
  Duration::minutes(5).num_seconds() as u32);
  record.rdata(RData::A(Ipv4Addr::new(100,10,100,10)));


  let result = client.create(record.clone(), origin.clone(), &signer).expect("create failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);
  let result = client.query(record.get_name(), record.get_dns_class(), record.get_rr_type()).expect("query failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);
  assert_eq!(result.get_answers().len(), 1);
  assert_eq!(result.get_answers()[0], record);

  // trying to create again should error
  // TODO: it would be cool to make this
  let result = client.create(record.clone(), origin.clone(), &signer).expect("create failed");
  assert_eq!(result.get_response_code(), ResponseCode::YXRRSet);

  // will fail if already set and not the same value.
  let mut record = record.clone();
  record.rdata(RData::A(Ipv4Addr::new(101,11,101,11)));

  let result = client.create(record.clone(), origin.clone(), &signer).expect("create failed");
  assert_eq!(result.get_response_code(), ResponseCode::YXRRSet);

}

#[test]
fn test_append() {
  let mut catalog = Catalog::new();
  let (client, signer, origin) = create_sig0_ready_client(&mut catalog);

  // append a record
  let mut record = Record::with(domain::Name::with_labels(vec!["new".to_string(), "example".to_string(), "com".to_string()]),
  RecordType::A,
  Duration::minutes(5).num_seconds() as u32);
  record.rdata(RData::A(Ipv4Addr::new(100,10,100,10)));

  // first check the must_exist option
  let result = client.append(record.clone(), origin.clone(), true, &signer).expect("append failed");
  assert_eq!(result.get_response_code(), ResponseCode::NXRRSet);

  // next append to a non-existent RRset
  let result = client.append(record.clone(), origin.clone(), false, &signer).expect("append failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);

  // verify record contents
  let result = client.query(record.get_name(), record.get_dns_class(), record.get_rr_type()).expect("query failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);
  assert_eq!(result.get_answers().len(), 1);
  assert_eq!(result.get_answers()[0], record);

  // will fail if already set and not the same value.
  let mut record = record.clone();
  record.rdata(RData::A(Ipv4Addr::new(101,11,101,11)));

  let result = client.append(record.clone(), origin.clone(), true, &signer).expect("create failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);

  let result = client.query(record.get_name(), record.get_dns_class(), record.get_rr_type()).expect("query failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);
  assert_eq!(result.get_answers().len(), 2);

  assert!(result.get_answers().iter().any(|rr| if let &RData::A(ref ip) = rr.get_rdata() { *ip ==  Ipv4Addr::new(100,10,100,10) } else { false }));
  assert!(result.get_answers().iter().any(|rr| if let &RData::A(ref ip) = rr.get_rdata() { *ip ==  Ipv4Addr::new(101,11,101,11) } else { false }));

  // show that appending the same thing again is ok, but doesn't add any records
  let result = client.append(record.clone(), origin.clone(), true, &signer).expect("create failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);

  let result = client.query(record.get_name(), record.get_dns_class(), record.get_rr_type()).expect("query failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);
  assert_eq!(result.get_answers().len(), 2);
}

#[test]
fn test_compare_and_swap() {
  let mut catalog = Catalog::new();
  let (client, signer, origin) = create_sig0_ready_client(&mut catalog);

  // create a record
  let mut record = Record::with(domain::Name::with_labels(vec!["new".to_string(), "example".to_string(), "com".to_string()]),
  RecordType::A,
  Duration::minutes(5).num_seconds() as u32);
  record.rdata(RData::A(Ipv4Addr::new(100,10,100,10)));

  let result = client.create(record.clone(), origin.clone(), &signer).expect("create failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);

  let current = record;
  let mut new = current.clone();
  new.rdata(RData::A(Ipv4Addr::new(101,11,101,11)));

  let result = client.compare_and_swap(current.clone(), new.clone(), origin.clone(), &signer).expect("compare_and_swap failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);

  let result = client.query(new.get_name(), new.get_dns_class(), new.get_rr_type()).expect("query failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);
  assert_eq!(result.get_answers().len(), 1);
  assert!(result.get_answers().iter().any(|rr| if let &RData::A(ref ip) = rr.get_rdata() { *ip ==  Ipv4Addr::new(101,11,101,11) } else { false }));

  // check the it fails if tried again.
  let mut new = new;
  new.rdata(RData::A(Ipv4Addr::new(102,12,102,12)));

  let result = client.compare_and_swap(current, new.clone(), origin.clone(), &signer).expect("compare_and_swap failed");
  assert_eq!(result.get_response_code(), ResponseCode::NXRRSet);

  let result = client.query(new.get_name(), new.get_dns_class(), new.get_rr_type()).expect("query failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);
  assert_eq!(result.get_answers().len(), 1);
  assert!(result.get_answers().iter().any(|rr| if let &RData::A(ref ip) = rr.get_rdata() { *ip ==  Ipv4Addr::new(101,11,101,11) } else { false }));
}

#[test]
fn test_delete_by_rdata() {
  let mut catalog = Catalog::new();
  let (client, signer, origin) = create_sig0_ready_client(&mut catalog);

  // append a record
  let mut record = Record::with(domain::Name::with_labels(vec!["new".to_string(), "example".to_string(), "com".to_string()]),
  RecordType::A,
  Duration::minutes(5).num_seconds() as u32);
  record.rdata(RData::A(Ipv4Addr::new(100,10,100,10)));

  // first check the must_exist option
  let result = client.delete_by_rdata(record.clone(), origin.clone(), &signer).expect("delete failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);

  // next create to a non-existent RRset
  let result = client.create(record.clone(), origin.clone(), &signer).expect("create failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);

  let mut record = record.clone();
  record.rdata(RData::A(Ipv4Addr::new(101,11,101,11)));
  let result = client.append(record.clone(), origin.clone(), true, &signer).expect("create failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);

  // verify record contents
  let result = client.delete_by_rdata(record.clone(), origin.clone(), &signer).expect("delete failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);

  let result = client.query(record.get_name(), record.get_dns_class(), record.get_rr_type()).expect("query failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);
  assert_eq!(result.get_answers().len(), 1);
  assert!(result.get_answers().iter().any(|rr| if let &RData::A(ref ip) = rr.get_rdata() { *ip ==  Ipv4Addr::new(100,10,100,10) } else { false }));
}

#[test]
fn test_delete_rrset() {
  let mut catalog = Catalog::new();
  let (client, signer, origin) = create_sig0_ready_client(&mut catalog);

  // append a record
  let mut record = Record::with(domain::Name::with_labels(vec!["new".to_string(), "example".to_string(), "com".to_string()]),
  RecordType::A,
  Duration::minutes(5).num_seconds() as u32);
  record.rdata(RData::A(Ipv4Addr::new(100,10,100,10)));

  // first check the must_exist option
  let result = client.delete_rrset(record.clone(), origin.clone(), &signer).expect("delete failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);

  // next create to a non-existent RRset
  let result = client.create(record.clone(), origin.clone(), &signer).expect("create failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);

  let mut record = record.clone();
  record.rdata(RData::A(Ipv4Addr::new(101,11,101,11)));
  let result = client.append(record.clone(), origin.clone(), true, &signer).expect("create failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);

  // verify record contents
  let result = client.delete_rrset(record.clone(), origin.clone(), &signer).expect("delete failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);

  let result = client.query(record.get_name(), record.get_dns_class(), record.get_rr_type()).expect("query failed");
  assert_eq!(result.get_response_code(), ResponseCode::NXDomain);
  assert_eq!(result.get_answers().len(), 0);
}

#[test]
fn test_delete_all() {
  let mut catalog = Catalog::new();
  let (client, signer, origin) = create_sig0_ready_client(&mut catalog);

  // append a record
  let mut record = Record::with(domain::Name::with_labels(vec!["new".to_string(), "example".to_string(), "com".to_string()]),
  RecordType::A,
  Duration::minutes(5).num_seconds() as u32);
  record.rdata(RData::A(Ipv4Addr::new(100,10,100,10)));

  // first check the must_exist option
  let result = client.delete_all(record.get_name().clone(), origin.clone(), DNSClass::IN, &signer).expect("delete failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);

  // next create to a non-existent RRset
  let result = client.create(record.clone(), origin.clone(), &signer).expect("create failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);

  let mut record = record.clone();
  record.rr_type(RecordType::AAAA);
  record.rdata(RData::AAAA(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)));
  let result = client.create(record.clone(), origin.clone(), &signer).expect("create failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);

  // verify record contents
  let result = client.delete_all(record.get_name().clone(), origin.clone(), DNSClass::IN, &signer).expect("delete failed");
  assert_eq!(result.get_response_code(), ResponseCode::NoError);

  let result = client.query(record.get_name(), record.get_dns_class(), RecordType::A).expect("query failed");
  assert_eq!(result.get_response_code(), ResponseCode::NXDomain);
  assert_eq!(result.get_answers().len(), 0);

  let result = client.query(record.get_name(), record.get_dns_class(), RecordType::AAAA).expect("query failed");
  assert_eq!(result.get_response_code(), ResponseCode::NXDomain);
  assert_eq!(result.get_answers().len(), 0);
}
