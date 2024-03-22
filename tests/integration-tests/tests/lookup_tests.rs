use std::{
    net::*,
    str::FromStr,
    sync::{Arc, Mutex as StdMutex},
};

use tokio::runtime::Runtime;

use hickory_proto::{
    op::{NoopMessageFinalizer, Query},
    rr::{rdata::A, DNSClass, Name, RData, Record, RecordType},
    xfer::{DnsExchange, DnsMultiplexer, DnsResponse},
    TokioTime,
};
use hickory_resolver::{
    caching_client::CachingClient,
    config::LookupIpStrategy,
    lookup::{Lookup, LookupFuture},
    lookup_ip::LookupIpFuture,
    Hosts,
};
use hickory_server::{
    authority::{Authority, Catalog},
    store::in_memory::InMemoryAuthority,
};

use hickory_integration::{example_authority::create_example, mock_client::*, TestClientStream};

#[test]
fn test_lookup() {
    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(
        authority.origin().clone(),
        vec![Box::new(Arc::new(authority))],
    );

    let io_loop = Runtime::new().unwrap();
    let (stream, sender) = TestClientStream::new(Arc::new(StdMutex::new(catalog)));
    let dns_conn = DnsMultiplexer::new(stream, sender, NoopMessageFinalizer::new());
    let client = DnsExchange::connect::<_, _, TokioTime>(dns_conn);

    let (client, bg) = io_loop.block_on(client).expect("client failed to connect");
    hickory_proto::spawn_bg(&io_loop, bg);

    let lookup = LookupFuture::lookup(
        vec![Name::from_str("www.example.com.").unwrap()],
        RecordType::A,
        Default::default(),
        CachingClient::new(0, client, false),
    );
    let lookup = io_loop.block_on(lookup).unwrap();

    assert_eq!(
        *lookup.iter().next().unwrap(),
        RData::A(A::new(93, 184, 216, 34))
    );
}

#[test]
fn test_lookup_hosts() {
    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(
        authority.origin().clone(),
        vec![Box::new(Arc::new(authority))],
    );

    let io_loop = Runtime::new().unwrap();
    let (stream, sender) = TestClientStream::new(Arc::new(StdMutex::new(catalog)));
    let dns_conn = DnsMultiplexer::new(stream, sender, NoopMessageFinalizer::new());

    let client = DnsExchange::connect::<_, _, TokioTime>(dns_conn);
    let (client, bg) = io_loop.block_on(client).expect("client connect failed");
    hickory_proto::spawn_bg(&io_loop, bg);

    let mut hosts = Hosts::default();
    let record = Record::from_rdata(
        Name::from_str("www.example.com.").unwrap(),
        86400,
        RData::A(A::new(10, 0, 1, 104)),
    );
    hosts.insert(
        Name::from_str("www.example.com.").unwrap(),
        RecordType::A,
        Lookup::new_with_max_ttl(
            Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A),
            Arc::from([record]),
        ),
    );

    let lookup = LookupIpFuture::lookup(
        vec![Name::from_str("www.example.com.").unwrap()],
        LookupIpStrategy::default(),
        CachingClient::new(0, client, false),
        Default::default(),
        Some(Arc::new(hosts)),
        None,
    );
    let lookup = io_loop.block_on(lookup).unwrap();

    assert_eq!(lookup.iter().next().unwrap(), Ipv4Addr::new(10, 0, 1, 104));
}

fn create_ip_like_example() -> InMemoryAuthority {
    let mut authority = create_example();
    authority.upsert_mut(
        Record::new()
            .set_name(Name::from_str("1.2.3.4.example.com.").unwrap())
            .set_ttl(86400)
            .set_record_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::A(A::new(198, 51, 100, 35))))
            .clone(),
        0,
    );

    authority
}

#[test]
fn test_lookup_ipv4_like() {
    let authority = create_ip_like_example();
    let mut catalog = Catalog::new();
    catalog.upsert(
        authority.origin().clone(),
        vec![Box::new(Arc::new(authority))],
    );

    let io_loop = Runtime::new().unwrap();
    let (stream, sender) = TestClientStream::new(Arc::new(StdMutex::new(catalog)));
    let dns_conn = DnsMultiplexer::new(stream, sender, NoopMessageFinalizer::new());

    let client = DnsExchange::connect::<_, _, TokioTime>(dns_conn);
    let (client, bg) = io_loop.block_on(client).expect("client connect failed");
    hickory_proto::spawn_bg(&io_loop, bg);

    let lookup = LookupIpFuture::lookup(
        vec![Name::from_str("1.2.3.4.example.com.").unwrap()],
        LookupIpStrategy::default(),
        CachingClient::new(0, client, false),
        Default::default(),
        Some(Arc::new(Hosts::default())),
        Some(RData::A(A::new(1, 2, 3, 4))),
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
    catalog.upsert(
        authority.origin().clone(),
        vec![Box::new(Arc::new(authority))],
    );

    let io_loop = Runtime::new().unwrap();
    let (stream, sender) = TestClientStream::new(Arc::new(StdMutex::new(catalog)));
    let dns_conn = DnsMultiplexer::new(stream, sender, NoopMessageFinalizer::new());

    let client = DnsExchange::connect::<_, _, TokioTime>(dns_conn);
    let (client, bg) = io_loop.block_on(client).expect("client connect failed");
    hickory_proto::spawn_bg(&io_loop, bg);

    let lookup = LookupIpFuture::lookup(
        vec![Name::from_str("198.51.100.35.example.com.").unwrap()],
        LookupIpStrategy::default(),
        CachingClient::new(0, client, false),
        Default::default(),
        Some(Arc::new(Hosts::default())),
        Some(RData::A(A::new(198, 51, 100, 35))),
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
    let client: MockClientHandle<_> =
        MockClientHandle::mock(vec![Ok(DnsResponse::from_message(message).unwrap())]);

    let lookup = LookupFuture::lookup(
        vec![Name::from_str("www.example.com.").unwrap()],
        RecordType::A,
        Default::default(),
        CachingClient::new(0, client, false),
    );

    let io_loop = Runtime::new().unwrap();
    let lookup = io_loop.block_on(lookup).unwrap();

    assert_eq!(
        *lookup.iter().next().unwrap(),
        RData::A(A::new(93, 184, 216, 34))
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
    let client: MockClientHandle<_> =
        MockClientHandle::mock(vec![Ok(DnsResponse::from_message(message).unwrap())]);

    let lookup = LookupFuture::lookup(
        vec![Name::from_str("www.example.com.").unwrap()],
        RecordType::A,
        Default::default(),
        CachingClient::new(0, client, false),
    );

    let io_loop = Runtime::new().unwrap();
    let lookup = io_loop.block_on(lookup).unwrap();

    assert_eq!(
        *lookup.iter().next().unwrap(),
        RData::A(A::new(93, 184, 216, 34))
    );
}

#[test]
fn test_cname_lookup_preserve() {
    let resp_query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
    let cname_record = cname_record(
        Name::from_str("www.example.com.").unwrap(),
        Name::from_str("v4.example.com.").unwrap(),
    );
    let v4_record = v4_record(
        Name::from_str("v4.example.com.").unwrap(),
        Ipv4Addr::new(93, 184, 216, 34),
    );
    let message = message(
        resp_query,
        vec![cname_record.clone(), v4_record],
        vec![],
        vec![],
    );
    let client: MockClientHandle<_> =
        MockClientHandle::mock(vec![Ok(DnsResponse::from_message(message).unwrap())]);

    let lookup = LookupFuture::lookup(
        vec![Name::from_str("www.example.com.").unwrap()],
        RecordType::A,
        Default::default(),
        CachingClient::new(0, client, true),
    );

    let io_loop = Runtime::new().unwrap();
    let lookup = io_loop.block_on(lookup).unwrap();

    let mut iter = lookup.iter();
    assert_eq!(iter.next().unwrap(), cname_record.data().unwrap());
    assert_eq!(*iter.next().unwrap(), RData::A(A::new(93, 184, 216, 34)));
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
    let client: MockClientHandle<_> = MockClientHandle::mock(vec![
        Ok(DnsResponse::from_message(message2).unwrap()),
        Ok(DnsResponse::from_message(message1).unwrap()),
    ]);

    let lookup = LookupFuture::lookup(
        vec![Name::from_str("www.example.com.").unwrap()],
        RecordType::A,
        Default::default(),
        CachingClient::new(0, client, false),
    );

    let io_loop = Runtime::new().unwrap();
    let lookup = io_loop.block_on(lookup).unwrap();

    assert_eq!(
        *lookup.iter().next().unwrap(),
        RData::A(A::new(93, 184, 216, 34))
    );
}

#[test]
fn test_chained_cname_lookup_preserve() {
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
    let message1 = message(
        resp_query.clone(),
        vec![cname_record.clone()],
        vec![],
        vec![],
    );
    let message2 = message(resp_query, vec![v4_record], vec![], vec![]);

    // the mock pops messages...
    let client: MockClientHandle<_> = MockClientHandle::mock(vec![
        Ok(DnsResponse::from_message(message2).unwrap()),
        Ok(DnsResponse::from_message(message1).unwrap()),
    ]);

    let lookup = LookupFuture::lookup(
        vec![Name::from_str("www.example.com.").unwrap()],
        RecordType::A,
        Default::default(),
        CachingClient::new(0, client, true),
    );

    let io_loop = Runtime::new().unwrap();
    let lookup = io_loop.block_on(lookup).unwrap();

    let mut iter = lookup.iter();
    assert_eq!(iter.next().unwrap(), cname_record.data().unwrap());
    assert_eq!(*iter.next().unwrap(), RData::A(A::new(93, 184, 216, 34)));
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
    let client: MockClientHandle<_> = MockClientHandle::mock(vec![
        Ok(DnsResponse::from_message(message10).unwrap()),
        Ok(DnsResponse::from_message(message9).unwrap()),
        Ok(DnsResponse::from_message(message8).unwrap()),
        Ok(DnsResponse::from_message(message7).unwrap()),
        Ok(DnsResponse::from_message(message6).unwrap()),
        Ok(DnsResponse::from_message(message5).unwrap()),
        Ok(DnsResponse::from_message(message4).unwrap()),
        Ok(DnsResponse::from_message(message3).unwrap()),
        Ok(DnsResponse::from_message(message2).unwrap()),
        Ok(DnsResponse::from_message(message1).unwrap()),
    ]);

    let client = CachingClient::new(0, client, false);
    let lookup = LookupFuture::lookup(
        vec![Name::from_str("www.example.com.").unwrap()],
        RecordType::A,
        Default::default(),
        client.clone(),
    );

    let io_loop = Runtime::new().unwrap();

    println!("performing max cname validation");
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
        RData::A(A::new(93, 184, 216, 34))
    );
}
