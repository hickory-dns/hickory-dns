extern crate futures;
extern crate tokio;
extern crate trust_dns_integration;
extern crate trust_dns_proto;
extern crate trust_dns_resolver;
extern crate trust_dns_server;

use std::net::*;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use futures::{FutureExt, TryFutureExt};
use tokio::runtime::current_thread::Runtime;

use trust_dns_proto::op::{NoopMessageFinalizer, Query};
use trust_dns_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns_proto::xfer::{BufDnsRequestStreamHandle, DnsExchange, DnsMultiplexer};
use trust_dns_resolver::config::LookupIpStrategy;
use trust_dns_resolver::lookup::{Lookup, LookupFuture};
use trust_dns_resolver::lookup_ip::LookupIpFuture;
use trust_dns_resolver::lookup_state::CachingClient;
use trust_dns_resolver::Hosts;
use trust_dns_server::authority::{Authority, Catalog};
use trust_dns_server::store::in_memory::InMemoryAuthority;

use trust_dns_integration::authority::create_example;
use trust_dns_integration::mock_client::*;
use trust_dns_integration::TestClientStream;

#[test]
fn test_lookup() {
    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), Box::new(authority));

    let mut io_loop = Runtime::new().unwrap();
    let (stream, sender) = TestClientStream::new(Arc::new(Mutex::new(catalog)));
    let dns_conn = DnsMultiplexer::new(stream, Box::new(sender), NoopMessageFinalizer::new());

    let (stream, handle) = DnsExchange::connect(dns_conn);
    io_loop.spawn(stream.and_then(|stream| stream).map_err(|e| {
        println!("error, udp connection shutting down: {}", e);
    }).map(|_: Result<_,_>| ()));

    let client = BufDnsRequestStreamHandle::new(handle);

    let lookup = LookupFuture::lookup(
        vec![Name::from_str("www.example.com.").unwrap()],
        RecordType::A,
        Default::default(),
        CachingClient::new(0, client),
    );
    let lookup = io_loop.block_on(lookup).unwrap();

    assert_eq!(
        *lookup.iter().next().unwrap(),
        RData::A(Ipv4Addr::new(93, 184, 216, 34))
    );
}

#[test]
fn test_lookup_hosts() {
    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), Box::new(authority));

    let mut io_loop = Runtime::new().unwrap();
    let (stream, sender) = TestClientStream::new(Arc::new(Mutex::new(catalog)));
    let dns_conn = DnsMultiplexer::new(stream, Box::new(sender), NoopMessageFinalizer::new());

    let (stream, handle) = DnsExchange::connect(dns_conn);
    io_loop.spawn(stream.and_then(|stream| stream).map_err(|e| {
        println!("error, udp connection shutting down: {}", e);
    }).map(|_: Result<_,_>| ()));

    let client = BufDnsRequestStreamHandle::new(handle);

    let mut hosts = Hosts::default();
    let record = Record::from_rdata(
        Name::from_str("www.example.com.").unwrap(),
        86400,
        RData::A(Ipv4Addr::new(10, 0, 1, 104)),
    );
    hosts.insert(
        Name::from_str("www.example.com.").unwrap(),
        RecordType::A,
        Lookup::new_with_max_ttl(
            Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A),
            Arc::new(vec![record]),
        ),
    );

    let lookup = LookupIpFuture::lookup(
        vec![Name::from_str("www.example.com.").unwrap()],
        LookupIpStrategy::default(),
        CachingClient::new(0, client),
        Default::default(),
        Some(Arc::new(hosts)),
        None,
    );
    let lookup = io_loop.block_on(lookup).unwrap();

    assert_eq!(lookup.iter().next().unwrap(), Ipv4Addr::new(10, 0, 1, 104));
}

fn create_ip_like_example() -> InMemoryAuthority {
    let mut authority = create_example();
    authority.upsert(
        Record::new()
            .set_name(Name::from_str("1.2.3.4.example.com.").unwrap())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::A(Ipv4Addr::new(198, 51, 100, 35)))
            .clone(),
        0,
    );

    authority
}

#[test]
fn test_lookup_ipv4_like() {
    let authority = create_ip_like_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), Box::new(authority));

    let mut io_loop = Runtime::new().unwrap();
    let (stream, sender) = TestClientStream::new(Arc::new(Mutex::new(catalog)));
    let dns_conn = DnsMultiplexer::new(stream, Box::new(sender), NoopMessageFinalizer::new());

    let (stream, handle) = DnsExchange::connect(dns_conn);
    io_loop.spawn(stream.and_then(|stream| stream).map_err(|e| {
        println!("error, udp connection shutting down: {}", e);
    }).map(|_: Result<_,_>| ()));

    let client = BufDnsRequestStreamHandle::new(handle);

    let lookup = LookupIpFuture::lookup(
        vec![Name::from_str("1.2.3.4.example.com.").unwrap()],
        LookupIpStrategy::default(),
        CachingClient::new(0, client),
        Default::default(),
        Some(Arc::new(Hosts::default())),
        Some(RData::A(Ipv4Addr::new(1, 2, 3, 4))),
    );
    let lookup = io_loop.block_on(lookup).unwrap();

    assert_eq!(
        lookup.iter().next().unwrap(),
        Ipv4Addr::new(198, 51, 100, 35)
    );
}

#[test]
fn test_lookup_ipv4_like_fall_through() {
    let authority = create_ip_like_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), Box::new(authority));

    let mut io_loop = Runtime::new().unwrap();
    let (stream, sender) = TestClientStream::new(Arc::new(Mutex::new(catalog)));
    let dns_conn = DnsMultiplexer::new(stream, Box::new(sender), NoopMessageFinalizer::new());

    let (stream, handle) = DnsExchange::connect(dns_conn);
    io_loop.spawn(stream.and_then(|stream| stream).map_err(|e| {
        println!("error, udp connection shutting down: {}", e);
    }).map(|_: Result<_,_>| ()));

    let client = BufDnsRequestStreamHandle::new(handle);

    let lookup = LookupIpFuture::lookup(
        vec![Name::from_str("198.51.100.35.example.com.").unwrap()],
        LookupIpStrategy::default(),
        CachingClient::new(0, client),
        Default::default(),
        Some(Arc::new(Hosts::default())),
        Some(RData::A(Ipv4Addr::new(198, 51, 100, 35))),
    );
    let lookup = io_loop.block_on(lookup).unwrap();

    assert_eq!(
        lookup.iter().next().unwrap(),
        Ipv4Addr::new(198, 51, 100, 35)
    );
}

#[test]
fn test_mock_lookup() {
    let resp_query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
    let v4_record = v4_record(
        Name::from_str("www.example.com.").unwrap(),
        Ipv4Addr::new(93, 184, 216, 34),
    );
    let message = message(resp_query, vec![v4_record], vec![], vec![]);
    let client = MockClientHandle::mock(vec![message.map(Into::into)]);

    let lookup = LookupFuture::lookup(
        vec![Name::from_str("www.example.com.").unwrap()],
        RecordType::A,
        Default::default(),
        CachingClient::new(0, client),
    );

    let mut io_loop = Runtime::new().unwrap();
    let lookup = io_loop.block_on(lookup).unwrap();

    assert_eq!(
        *lookup.iter().next().unwrap(),
        RData::A(Ipv4Addr::new(93, 184, 216, 34))
    );
}

#[test]
fn test_cname_lookup() {
    let resp_query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
    let cname_record = cname_record(
        Name::from_str("www.example.com.").unwrap(),
        Name::from_str("v4.example.com.").unwrap(),
    );
    let v4_record = v4_record(
        Name::from_str("v4.example.com.").unwrap(),
        Ipv4Addr::new(93, 184, 216, 34),
    );
    let message = message(resp_query, vec![cname_record, v4_record], vec![], vec![]);
    let client = MockClientHandle::mock(vec![message.map(Into::into)]);

    let lookup = LookupFuture::lookup(
        vec![Name::from_str("www.example.com.").unwrap()],
        RecordType::A,
        Default::default(),
        CachingClient::new(0, client),
    );

    let mut io_loop = Runtime::new().unwrap();
    let lookup = io_loop.block_on(lookup).unwrap();

    assert_eq!(
        *lookup.iter().next().unwrap(),
        RData::A(Ipv4Addr::new(93, 184, 216, 34))
    );
}

#[test]
fn test_chained_cname_lookup() {
    let resp_query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
    let cname_record = cname_record(
        Name::from_str("www.example.com.").unwrap(),
        Name::from_str("v4.example.com.").unwrap(),
    );
    let v4_record = v4_record(
        Name::from_str("v4.example.com.").unwrap(),
        Ipv4Addr::new(93, 184, 216, 34),
    );

    // The first response should be a cname, the second will be the actual record
    let message1 = message(resp_query.clone(), vec![cname_record], vec![], vec![]);
    let message2 = message(resp_query, vec![v4_record], vec![], vec![]);

    // the mock pops messages...
    let client = MockClientHandle::mock(vec![message2.map(Into::into), message1.map(Into::into)]);

    let lookup = LookupFuture::lookup(
        vec![Name::from_str("www.example.com.").unwrap()],
        RecordType::A,
        Default::default(),
        CachingClient::new(0, client),
    );

    let mut io_loop = Runtime::new().unwrap();
    let lookup = io_loop.block_on(lookup).unwrap();

    assert_eq!(
        *lookup.iter().next().unwrap(),
        RData::A(Ipv4Addr::new(93, 184, 216, 34))
    );
}

#[test]
fn test_max_chained_lookup_depth() {
    let resp_query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
    let cname_record1 = cname_record(
        Name::from_str("www.example.com.").unwrap(),
        Name::from_str("cname2.example.com.").unwrap(),
    );
    let cname_record2 = cname_record(
        Name::from_str("cname2.example.com.").unwrap(),
        Name::from_str("cname3.example.com.").unwrap(),
    );
    let cname_record3 = cname_record(
        Name::from_str("cname3.example.com.").unwrap(),
        Name::from_str("cname4.example.com.").unwrap(),
    );
    let cname_record4 = cname_record(
        Name::from_str("cname4.example.com.").unwrap(),
        Name::from_str("cname5.example.com.").unwrap(),
    );
    let cname_record5 = cname_record(
        Name::from_str("cname5.example.com.").unwrap(),
        Name::from_str("cname6.example.com.").unwrap(),
    );
    let cname_record6 = cname_record(
        Name::from_str("cname6.example.com.").unwrap(),
        Name::from_str("cname7.example.com.").unwrap(),
    );
    let cname_record7 = cname_record(
        Name::from_str("cname7.example.com.").unwrap(),
        Name::from_str("cname8.example.com.").unwrap(),
    );
    let cname_record8 = cname_record(
        Name::from_str("cname8.example.com.").unwrap(),
        Name::from_str("cname9.example.com.").unwrap(),
    );
    let cname_record9 = cname_record(
        Name::from_str("cname9.example.com.").unwrap(),
        Name::from_str("v4.example.com.").unwrap(),
    );
    let v4_record = v4_record(
        Name::from_str("v4.example.com.").unwrap(),
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
        message10.map(Into::into),
        message9.map(Into::into),
        message8.map(Into::into),
        message7.map(Into::into),
        message6.map(Into::into),
        message5.map(Into::into),
        message4.map(Into::into),
        message3.map(Into::into),
        message2.map(Into::into),
        message1.map(Into::into),
    ]);

    let client = CachingClient::new(0, client);
    let lookup = LookupFuture::lookup(
        vec![Name::from_str("www.example.com.").unwrap()],
        RecordType::A,
        Default::default(),
        client.clone(),
    );

    let mut io_loop = Runtime::new().unwrap();

    println!("performing max cname validation");
    // TODO: validate exact error
    assert!(io_loop.block_on(lookup).is_err());

    // This query should succeed, as the queue depth should reset to 0 on a failed request
    let lookup = LookupFuture::lookup(
        vec![Name::from_str("cname9.example.com.").unwrap()],
        RecordType::A,
        Default::default(),
        client,
    );

    println!("performing followup resolve, should work");
    let lookup = io_loop.block_on(lookup).unwrap();

    assert_eq!(
        *lookup.iter().next().unwrap(),
        RData::A(Ipv4Addr::new(93, 184, 216, 34))
    );
}
