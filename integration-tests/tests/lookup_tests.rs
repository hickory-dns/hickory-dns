extern crate tokio_core;
extern crate trust_dns_integration;
extern crate trust_dns_proto;
extern crate trust_dns_resolver;
extern crate trust_dns_server;

use std::net::*;
use std::str::FromStr;
use std::sync::Arc;

use tokio_core::reactor::Core;

use trust_dns_proto::DnsFuture;
use trust_dns_proto::op::{NoopMessageFinalizer, Query};
use trust_dns_proto::rr::domain;
use trust_dns_proto::rr::{RData, RecordType};
use trust_dns_server::authority::Catalog;
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::lookup::{InnerLookupFuture, Lookup};
use trust_dns_resolver::lookup_ip::InnerLookupIpFuture;
use trust_dns_resolver::lookup_state::CachingClient;
use trust_dns_resolver::config::LookupIpStrategy;
use trust_dns_resolver::Hosts;

use trust_dns_integration::TestClientStream;
use trust_dns_integration::authority::create_example;
use trust_dns_integration::mock_client::*;

#[test]
fn test_lookup() {
    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), authority);

    let mut io_loop = Core::new().unwrap();
    let (stream, sender) = TestClientStream::new(Arc::new(catalog));
    let client = DnsFuture::new(
        stream,
        Box::new(sender),
        &io_loop.handle(),
        NoopMessageFinalizer::new(),
    );

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
fn test_lookup_hosts() {
    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), authority);

    let mut io_loop = Core::new().unwrap();
    let (stream, sender) = TestClientStream::new(Arc::new(catalog));
    let client = DnsFuture::new(
        stream,
        Box::new(sender),
        &io_loop.handle(),
        NoopMessageFinalizer::new(),
    );

    let mut hosts = Hosts::default();

    hosts.by_name.insert(
        domain::Name::from_str("www.example.com.").unwrap(),
        Lookup::new(Arc::new(vec![RData::A(Ipv4Addr::new(10, 0, 1, 104))])),
    );


    let lookup = InnerLookupIpFuture::lookup(
        vec![domain::Name::from_str("www.example.com.").unwrap()],
        LookupIpStrategy::default(),
        CachingClient::new(0, client),
        Some(Arc::new(hosts)),
    );
    let lookup = io_loop.run(lookup).unwrap();

    assert_eq!(lookup.iter().next().unwrap(), Ipv4Addr::new(10, 0, 1, 104));
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
    let client = MockClientHandle::<ResolveError>::mock(vec![message]);

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

#[test]
fn test_max_chained_lookup_depth() {
    let resp_query = Query::query(
        domain::Name::from_str("www.example.com.").unwrap(),
        RecordType::A,
    );
    let cname_record1 = cname_record(
        domain::Name::from_str("www.example.com.").unwrap(),
        domain::Name::from_str("cname2.example.com.").unwrap(),
    );
    let cname_record2 = cname_record(
        domain::Name::from_str("cname2.example.com.").unwrap(),
        domain::Name::from_str("cname3.example.com.").unwrap(),
    );
    let cname_record3 = cname_record(
        domain::Name::from_str("cname3.example.com.").unwrap(),
        domain::Name::from_str("cname4.example.com.").unwrap(),
    );
    let cname_record4 = cname_record(
        domain::Name::from_str("cname4.example.com.").unwrap(),
        domain::Name::from_str("cname5.example.com.").unwrap(),
    );
    let cname_record5 = cname_record(
        domain::Name::from_str("cname5.example.com.").unwrap(),
        domain::Name::from_str("cname6.example.com.").unwrap(),
    );
    let cname_record6 = cname_record(
        domain::Name::from_str("cname6.example.com.").unwrap(),
        domain::Name::from_str("cname7.example.com.").unwrap(),
    );
    let cname_record7 = cname_record(
        domain::Name::from_str("cname7.example.com.").unwrap(),
        domain::Name::from_str("cname8.example.com.").unwrap(),
    );
    let cname_record8 = cname_record(
        domain::Name::from_str("cname8.example.com.").unwrap(),
        domain::Name::from_str("cname9.example.com.").unwrap(),
    );
    let cname_record9 = cname_record(
        domain::Name::from_str("cname9.example.com.").unwrap(),
        domain::Name::from_str("v4.example.com.").unwrap(),
    );
    let v4_record = v4_record(
        domain::Name::from_str("v4.example.com.").unwrap(),
        Ipv4Addr::new(93, 184, 216, 34),
    );

    // The first response should be a cname, the second will be the actual record
    let message1 = message(resp_query.clone(), vec![cname_record1], vec![], vec![]);
    let message2 = message(resp_query.clone(), vec![cname_record2], vec![], vec![]);
    let message3 = message(resp_query.clone(), vec![cname_record3], vec![], vec![]);
    let message4 = message(resp_query.clone(), vec![cname_record4], vec![], vec![]);
    let message5 = message(resp_query.clone(), vec![cname_record5], vec![], vec![]);
    let message6 = message(resp_query.clone(), vec![cname_record6], vec![], vec![]);
    let message7 = message(resp_query.clone(), vec![cname_record7], vec![], vec![]);
    let message8 = message(resp_query.clone(), vec![cname_record8], vec![], vec![]);
    let message9 = message(resp_query.clone(), vec![cname_record9], vec![], vec![]);
    let message10 = message(resp_query, vec![v4_record], vec![], vec![]);

    // the mock pops messages...
    let client = MockClientHandle::mock(vec![
        message10,
        message9,
        message8,
        message7,
        message6,
        message5,
        message4,
        message3,
        message2,
        message1,
    ]);

    let client = CachingClient::new(0, client);
    let lookup = InnerLookupFuture::lookup(
        vec![domain::Name::from_str("www.example.com.").unwrap()],
        RecordType::A,
        client.clone(),
    );

    let mut io_loop = Core::new().unwrap();

    println!("performing max cname validation");
    // TODO: validate exact error
    assert!(io_loop.run(lookup).is_err());

    // This query should succeed, as the queue depth should reset to 0 on a failed request
    let lookup = InnerLookupFuture::lookup(
        vec![domain::Name::from_str("cname9.example.com.").unwrap()],
        RecordType::A,
        client,
    );

    println!("performing followup resolve, should work");
    let lookup = io_loop.run(lookup).unwrap();

    assert_eq!(
        *lookup.iter().next().unwrap(),
        RData::A(Ipv4Addr::new(93, 184, 216, 34))
    );
}
