extern crate tokio_core;
extern crate trust_dns;
extern crate trust_dns_server;
extern crate trust_dns_resolver;
extern crate trust_dns_integration;

use std::net::*;
use std::str::FromStr;

use tokio_core::reactor::Core;

use trust_dns::client::ClientFuture;
use trust_dns::op::Query;
use trust_dns::rr::domain;
use trust_dns::rr::{RData, RecordType};
use trust_dns_server::authority::Catalog;
use trust_dns_resolver::lookup::InnerLookupFuture;
use trust_dns_resolver::lookup_state::CachingClient;

use trust_dns_integration::TestClientStream;
use trust_dns_integration::authority::create_example;
use trust_dns_integration::mock_client::*;

#[test]
fn test_lookup() {
    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), authority);

    let mut io_loop = Core::new().unwrap();
    let (stream, sender) = TestClientStream::new(catalog);
    let client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

    let lookup = InnerLookupFuture::lookup(
        vec![domain::Name::from_str("www.example.com.").unwrap()],
        RecordType::A,
        CachingClient::new(0, client),
    );
    let lookup = io_loop.run(lookup).unwrap();

    assert_eq!(
        *lookup.iter().next().unwrap(),
        RData::A(Ipv4Addr::new(93, 184, 216, 34))
    );
}

#[test]
fn test_mock_lookup() {
    let resp_query = Query::query(
        domain::Name::from_str("www.example.com.").unwrap(),
        RecordType::A,
    );
    let v4_record = v4_record(
        domain::Name::from_str("www.example.com.").unwrap(),
        Ipv4Addr::new(93, 184, 216, 34),
    );
    let message = message(resp_query, vec![v4_record], vec![], vec![]);
    let client = MockClientHandle::mock(vec![message]);

    let lookup = InnerLookupFuture::lookup(
        vec![domain::Name::from_str("www.example.com.").unwrap()],
        RecordType::A,
        CachingClient::new(0, client),
    );

    let mut io_loop = Core::new().unwrap();
    let lookup = io_loop.run(lookup).unwrap();

    assert_eq!(
        *lookup.iter().next().unwrap(),
        RData::A(Ipv4Addr::new(93, 184, 216, 34))
    );
}

#[test]
fn test_cname_lookup() {
    let resp_query = Query::query(
        domain::Name::from_str("www.example.com.").unwrap(),
        RecordType::A,
    );
    let cname_record = cname_record(
        domain::Name::from_str("www.example.com.").unwrap(),
        domain::Name::from_str("v4.example.com.").unwrap(),
    );
    let v4_record = v4_record(
        domain::Name::from_str("v4.example.com.").unwrap(),
        Ipv4Addr::new(93, 184, 216, 34),
    );
    let message = message(resp_query, vec![cname_record, v4_record], vec![], vec![]);
    let client = MockClientHandle::mock(vec![message]);

    let lookup = InnerLookupFuture::lookup(
        vec![domain::Name::from_str("www.example.com.").unwrap()],
        RecordType::A,
        CachingClient::new(0, client),
    );

    let mut io_loop = Core::new().unwrap();
    let lookup = io_loop.run(lookup).unwrap();

    assert_eq!(
        *lookup.iter().next().unwrap(),
        RData::A(Ipv4Addr::new(93, 184, 216, 34))
    );
}

#[test]
fn test_chained_cname_lookup() {
    let resp_query = Query::query(
        domain::Name::from_str("www.example.com.").unwrap(),
        RecordType::A,
    );
    let cname_record = cname_record(
        domain::Name::from_str("www.example.com.").unwrap(),
        domain::Name::from_str("v4.example.com.").unwrap(),
    );
    let v4_record = v4_record(
        domain::Name::from_str("v4.example.com.").unwrap(),
        Ipv4Addr::new(93, 184, 216, 34),
    );

    // The first response should be a cname, the second will be the actual record
    let message1 = message(resp_query.clone(), vec![cname_record], vec![], vec![]);
    let message2 = message(resp_query, vec![v4_record], vec![], vec![]);

    // the mock pops messages...
    let client = MockClientHandle::mock(vec![message2, message1]);

    let lookup = InnerLookupFuture::lookup(
        vec![domain::Name::from_str("www.example.com.").unwrap()],
        RecordType::A,
        CachingClient::new(0, client),
    );

    let mut io_loop = Core::new().unwrap();
    let lookup = io_loop.run(lookup).unwrap();

    assert_eq!(
        *lookup.iter().next().unwrap(),
        RData::A(Ipv4Addr::new(93, 184, 216, 34))
    );
}