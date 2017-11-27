extern crate chrono;
extern crate futures;
extern crate log;
extern crate openssl;
extern crate tokio_core;
extern crate trust_dns;
extern crate trust_dns_integration;
extern crate trust_dns_server;

use std::net::*;
use std::cmp::Ordering;
use std::sync::Arc;

use chrono::Duration;
use futures::Future;
use openssl::rsa::Rsa;
use tokio_core::reactor::Core;

use trust_dns::client::{BasicClientHandle, ClientFuture, ClientHandle};
use trust_dns::op::ResponseCode;
use trust_dns::rr::domain;
use trust_dns::rr::{DNSClass, IntoRecordSet, RData, Record, RecordSet, RecordType};
use trust_dns::rr::dnssec::{Algorithm, KeyPair, Signer};
use trust_dns::rr::rdata::{DNSSECRData, DNSSECRecordType};
use trust_dns::udp::UdpClientStream;
use trust_dns::tcp::TcpClientStream;
use trust_dns_server::authority::Catalog;

use trust_dns_integration::{NeverReturnsClientStream, TestClientStream};
use trust_dns_integration::authority::create_example;

#[test]
fn test_query_nonet() {
    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), authority);

    let mut io_loop = Core::new().unwrap();
    let (stream, sender) = TestClientStream::new(Arc::new(catalog));
    let mut client = ClientFuture::new(stream, Box::new(sender), &io_loop.handle(), None);

    io_loop.run(test_query(&mut client)).unwrap();
    io_loop.run(test_query(&mut client)).unwrap();
}

#[test]
#[ignore]
fn test_query_udp_ipv4() {
    use std::net::{SocketAddr, ToSocketAddrs};
    use tokio_core::reactor::Core;

    let mut io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = UdpClientStream::new(addr, &io_loop.handle());
    let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.run(test_query(&mut client)).unwrap();
    io_loop.run(test_query(&mut client)).unwrap();
}

#[test]
#[ignore]
fn test_query_udp_ipv6() {
    use std::net::{SocketAddr, ToSocketAddrs};
    use tokio_core::reactor::Core;

    let mut io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("2001:4860:4860::8888", 53)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let (stream, sender) = UdpClientStream::new(addr, &io_loop.handle());
    let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.run(test_query(&mut client)).unwrap();
    io_loop.run(test_query(&mut client)).unwrap();
}

#[test]
#[ignore]
fn test_query_tcp_ipv4() {
    use std::net::{SocketAddr, ToSocketAddrs};
    use tokio_core::reactor::Core;

    let mut io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
    let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.run(test_query(&mut client)).unwrap();
    io_loop.run(test_query(&mut client)).unwrap();
}

#[test]
#[ignore]
fn test_query_tcp_ipv6() {
    use std::net::{SocketAddr, ToSocketAddrs};
    use tokio_core::reactor::Core;

    let mut io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("2001:4860:4860::8888", 53)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
    let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.run(test_query(&mut client)).unwrap();
    io_loop.run(test_query(&mut client)).unwrap();
}

#[cfg(test)]
fn test_query(client: &mut BasicClientHandle) -> Box<Future<Item = (), Error = ()>> {
    let name = domain::Name::from_labels(vec!["WWW", "example", "com"]);

    Box::new(
        client
            .query(name.clone(), DNSClass::IN, RecordType::A)
            .map(move |response| {
                println!("response records: {:?}", response);
                assert_eq!(
                    response
                        .queries()
                        .first()
                        .expect("expected query")
                        .name()
                        .cmp_with_case(&name, false),
                    Ordering::Equal
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
            })
            .map_err(|e| {
                assert!(false, "query failed: {}", e);
            }),
    )
}

#[test]
fn test_notify() {
    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), authority);

    let mut io_loop = Core::new().unwrap();
    let (stream, sender) = TestClientStream::new(Arc::new(catalog));
    let mut client = ClientFuture::new(stream, Box::new(sender), &io_loop.handle(), None);

    let name = domain::Name::from_labels(vec!["ping", "example", "com"]);

    let message = io_loop.run(client.notify(
        name.clone(),
        DNSClass::IN,
        RecordType::A,
        None::<RecordSet>,
    ));
    assert!(message.is_ok());
    let message = message.unwrap();
    assert_eq!(
        message.response_code(),
        ResponseCode::NotImp,
        "the catalog must support Notify now, update this"
    );
}

// update tests
//

/// create a client with a sig0 section
fn create_sig0_ready_client(io_loop: &Core) -> (BasicClientHandle, domain::Name) {
    let mut authority = create_example();
    authority.set_allow_update(true);
    let origin = authority.origin().clone();

    let trusted_name = domain::Name::from_labels(vec!["trusted", "example", "com"]);

    let rsa = Rsa::generate(2048).unwrap();
    let key = KeyPair::from_rsa(rsa).unwrap();
    let sig0_key = key.to_sig0key(Algorithm::RSASHA256).unwrap();

    let signer = Signer::sig0(sig0_key.clone(), key, trusted_name.clone());

    // insert the KEY for the trusted.example.com
    let mut auth_key = Record::with(
        trusted_name,
        RecordType::DNSSEC(DNSSECRecordType::KEY),
        Duration::minutes(5).num_seconds() as u32,
    );
    auth_key.set_rdata(RData::DNSSEC(DNSSECRData::KEY(sig0_key)));
    authority.upsert(auth_key, 0);

    // setup the catalog
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), authority);

    let (stream, sender) = TestClientStream::new(Arc::new(catalog));
    let client = ClientFuture::new(
        stream,
        Box::new(sender),
        &io_loop.handle(),
        Some(Arc::new(signer)),
    );

    (client, origin)
}

#[test]
fn test_create() {
    let mut io_loop = Core::new().unwrap();
    let (mut client, origin) = create_sig0_ready_client(&io_loop);

    // create a record
    let mut record = Record::with(
        domain::Name::from_labels(vec!["new", "example", "com"]),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));
    let record = record;


    let result = io_loop
        .run(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    let result = io_loop
        .run(client.query(
            record.name().clone(),
            record.dns_class(),
            record.rr_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // trying to create again should error
    // TODO: it would be cool to make this
    let result = io_loop
        .run(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);

    // will fail if already set and not the same value.
    let mut record = record.clone();
    record.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));

    let result = io_loop
        .run(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);
}

#[test]
fn test_create_multi() {
    let mut io_loop = Core::new().unwrap();
    let (mut client, origin) = create_sig0_ready_client(&io_loop);

    // create a record
    let mut record = Record::with(
        domain::Name::from_labels(vec!["new", "example", "com"]),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));
    let record = record;

    let mut record2 = record.clone();
    record2.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 11)));
    let record2 = record2;

    let mut rrset = record.clone().into_record_set();
    rrset.insert(record2.clone(), 0);
    let rrset = rrset;

    let result = io_loop
        .run(client.create(rrset.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    let result = io_loop
        .run(client.query(
            record.name().clone(),
            record.dns_class(),
            record.rr_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);

    assert!(result.answers().iter().any(|rr| *rr == record));
    assert!(result.answers().iter().any(|rr| *rr == record2));

    // trying to create again should error
    // TODO: it would be cool to make this
    let result = io_loop
        .run(client.create(rrset, origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);

    // will fail if already set and not the same value.
    let mut record = record.clone();
    record.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 12)));

    let result = io_loop
        .run(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);
}

#[test]
fn test_append() {
    let mut io_loop = Core::new().unwrap();
    let (mut client, origin) = create_sig0_ready_client(&io_loop);

    // append a record
    let mut record = Record::with(
        domain::Name::from_labels(vec!["new", "example", "com"]),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));
    let record = record;

    // first check the must_exist option
    let result = io_loop
        .run(client.append(record.clone(), origin.clone(), true))
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    // next append to a non-existent RRset
    let result = io_loop
        .run(client.append(record.clone(), origin.clone(), false))
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .run(client.query(
            record.name().clone(),
            record.dns_class(),
            record.rr_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // will fail if already set and not the same value.
    let mut record2 = record.clone();
    record2.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
    let record2 = record2;

    let result = io_loop
        .run(client.append(record2.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .run(client.query(
            record.name().clone(),
            record.dns_class(),
            record.rr_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);

    assert!(result.answers().iter().any(|rr| *rr == record));
    assert!(result.answers().iter().any(|rr| *rr == record2));

    // show that appending the same thing again is ok, but doesn't add any records
    let result = io_loop
        .run(client.append(record.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .run(client.query(
            record.name().clone(),
            record.dns_class(),
            record.rr_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);
}

#[test]
fn test_append_multi() {
    let mut io_loop = Core::new().unwrap();
    let (mut client, origin) = create_sig0_ready_client(&io_loop);

    // append a record
    let mut record = Record::with(
        domain::Name::from_labels(vec!["new", "example", "com"]),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

    // first check the must_exist option
    let result = io_loop
        .run(client.append(record.clone(), origin.clone(), true))
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    // next append to a non-existent RRset
    let result = io_loop
        .run(client.append(record.clone(), origin.clone(), false))
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .run(client.query(
            record.name().clone(),
            record.dns_class(),
            record.rr_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // will fail if already set and not the same value.
    let mut record2 = record.clone();
    record2.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
    let mut record3 = record.clone();
    record3.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 12)));

    // build the append set
    let mut rrset = record2.clone().into_record_set();
    rrset.insert(record3.clone(), 0);

    let result = io_loop
        .run(client.append(rrset, origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .run(client.query(
            record.name().clone(),
            record.dns_class(),
            record.rr_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 3);

    assert!(result.answers().iter().any(|rr| *rr == record));
    assert!(result.answers().iter().any(|rr| *rr == record2));
    assert!(result.answers().iter().any(|rr| *rr == record3));

    // show that appending the same thing again is ok, but doesn't add any records
    // TODO: technically this is a test for the Server, not client...
    let result = io_loop
        .run(client.append(record.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .run(client.query(
            record.name().clone(),
            record.dns_class(),
            record.rr_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 3);
}

#[test]
fn test_compare_and_swap() {
    let mut io_loop = Core::new().unwrap();
    let (mut client, origin) = create_sig0_ready_client(&io_loop);

    // create a record
    let mut record = Record::with(
        domain::Name::from_labels(vec!["new", "example", "com"]),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));
    let record = record;

    let result = io_loop
        .run(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let current = record;
    let mut new = current.clone();
    new.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
    let new = new;

    let result = io_loop
        .run(client.compare_and_swap(
            current.clone(),
            new.clone(),
            origin.clone(),
        ))
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .run(client.query(
            new.name().clone(),
            new.dns_class(),
            new.rr_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result.answers().iter().any(|rr| *rr == new));
    assert!(!result.answers().iter().any(|rr| *rr == current));

    // check the it fails if tried again.
    let mut not = new.clone();
    not.set_rdata(RData::A(Ipv4Addr::new(102, 12, 102, 12)));
    let not = not;

    let result = io_loop
        .run(client.compare_and_swap(
            current,
            not.clone(),
            origin.clone(),
        ))
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    let result = io_loop
        .run(client.query(
            new.name().clone(),
            new.dns_class(),
            new.rr_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result.answers().iter().any(|rr| *rr == new));
    assert!(!result.answers().iter().any(|rr| *rr == not));
}

#[test]
fn test_compare_and_swap_multi() {
    let mut io_loop = Core::new().unwrap();
    let (mut client, origin) = create_sig0_ready_client(&io_loop);

    // create a record
    let mut current = RecordSet::with_ttl(
        domain::Name::from_labels(vec!["new", "example", "com"]),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );

    let current1 = current
        .new_record(&RData::A(Ipv4Addr::new(100, 10, 100, 10)))
        .clone();
    let current2 = current
        .new_record(&RData::A(Ipv4Addr::new(100, 10, 100, 11)))
        .clone();
    let current = current;

    let result = io_loop
        .run(client.create(current.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let mut new = RecordSet::with_ttl(current.name().clone(), current.record_type(), current.ttl());
    let new1 = new.new_record(&RData::A(Ipv4Addr::new(100, 10, 101, 10)))
        .clone();
    let new2 = new.new_record(&RData::A(Ipv4Addr::new(100, 10, 101, 11)))
        .clone();
    let new = new;

    let result = io_loop
        .run(client.compare_and_swap(
            current.clone(),
            new.clone(),
            origin.clone(),
        ))
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .run(client.query(
            new.name().clone(),
            new.dns_class(),
            new.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);
    assert!(result.answers().iter().any(|rr| *rr == new1));
    assert!(result.answers().iter().any(|rr| *rr == new2));
    assert!(!result.answers().iter().any(|rr| *rr == current1));
    assert!(!result.answers().iter().any(|rr| *rr == current2));

    // check the it fails if tried again.
    let mut not = new1.clone();
    not.set_rdata(RData::A(Ipv4Addr::new(102, 12, 102, 12)));
    let not = not;

    let result = io_loop
        .run(client.compare_and_swap(
            current,
            not.clone(),
            origin.clone(),
        ))
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    let result = io_loop
        .run(client.query(
            new.name().clone(),
            new.dns_class(),
            new.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);
    assert!(result.answers().iter().any(|rr| *rr == new1));
    assert!(!result.answers().iter().any(|rr| *rr == not));
}

#[test]
fn test_delete_by_rdata() {
    let mut io_loop = Core::new().unwrap();
    let (mut client, origin) = create_sig0_ready_client(&io_loop);

    // append a record
    let mut record1 = Record::with(
        domain::Name::from_labels(vec!["new", "example", "com"]),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record1.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

    // first check the must_exist option
    let result = io_loop
        .run(client.delete_by_rdata(record1.clone(), origin.clone()))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop
        .run(client.create(record1.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let mut record2 = record1.clone();
    record2.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
    let result = io_loop
        .run(client.append(record2.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .run(client.delete_by_rdata(record2.clone(), origin.clone()))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .run(client.query(
            record1.name().clone(),
            record1.dns_class(),
            record1.rr_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result.answers().iter().any(|rr| *rr == record1));
}

#[test]
fn test_delete_by_rdata_multi() {
    let mut io_loop = Core::new().unwrap();
    let (mut client, origin) = create_sig0_ready_client(&io_loop);

    // append a record
    let mut rrset = RecordSet::with_ttl(
        domain::Name::from_labels(vec!["new", "example", "com"]),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );

    let record1 = rrset
        .new_record(&RData::A(Ipv4Addr::new(100, 10, 100, 10)))
        .clone();
    let record2 = rrset
        .new_record(&RData::A(Ipv4Addr::new(100, 10, 100, 11)))
        .clone();
    let record3 = rrset
        .new_record(&RData::A(Ipv4Addr::new(100, 10, 100, 12)))
        .clone();
    let record4 = rrset
        .new_record(&RData::A(Ipv4Addr::new(100, 10, 100, 13)))
        .clone();
    let rrset = rrset;

    // first check the must_exist option
    let result = io_loop
        .run(client.delete_by_rdata(rrset.clone(), origin.clone()))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop
        .run(client.create(rrset.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // append a record
    let mut rrset = RecordSet::with_ttl(
        domain::Name::from_labels(vec!["new", "example", "com"]),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );

    let record1 = rrset.new_record(record1.rdata()).clone();
    let record3 = rrset.new_record(record3.rdata()).clone();
    let rrset = rrset;

    let result = io_loop
        .run(client.append(rrset.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .run(client.delete_by_rdata(rrset.clone(), origin.clone()))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .run(client.query(
            record1.name().clone(),
            record1.dns_class(),
            record1.rr_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);
    assert!(!result.answers().iter().any(|rr| *rr == record1));
    assert!(result.answers().iter().any(|rr| *rr == record2));
    assert!(!result.answers().iter().any(|rr| *rr == record3));
    assert!(result.answers().iter().any(|rr| *rr == record4));
}

#[test]
fn test_delete_rrset() {
    let mut io_loop = Core::new().unwrap();
    let (mut client, origin) = create_sig0_ready_client(&io_loop);

    // append a record
    let mut record = Record::with(
        domain::Name::from_labels(vec!["new", "example", "com"]),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

    // first check the must_exist option
    let result = io_loop
        .run(client.delete_rrset(record.clone(), origin.clone()))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop
        .run(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let mut record = record.clone();
    record.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
    let result = io_loop
        .run(client.append(record.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .run(client.delete_rrset(record.clone(), origin.clone()))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .run(client.query(
            record.name().clone(),
            record.dns_class(),
            record.rr_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);
}

#[test]
fn test_delete_all() {
    let mut io_loop = Core::new().unwrap();
    let (mut client, origin) = create_sig0_ready_client(&io_loop);

    // append a record
    let mut record = Record::with(
        domain::Name::from_labels(vec!["new", "example", "com"]),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

    // first check the must_exist option
    let result = io_loop
        .run(client.delete_all(
            record.name().clone(),
            origin.clone(),
            DNSClass::IN,
        ))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop
        .run(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let mut record = record.clone();
    record.set_rr_type(RecordType::AAAA);
    record.set_rdata(RData::AAAA(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)));
    let result = io_loop
        .run(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .run(client.delete_all(
            record.name().clone(),
            origin.clone(),
            DNSClass::IN,
        ))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .run(client.query(
            record.name().clone(),
            record.dns_class(),
            RecordType::A,
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);

    let result = io_loop
        .run(client.query(
            record.name().clone(),
            record.dns_class(),
            RecordType::AAAA,
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);
}

fn test_timeout_query(mut client: BasicClientHandle, mut io_loop: Core) {
    let name = domain::Name::from_labels(vec!["www", "example", "com"]);

    let err = io_loop
        .run(client.query(name.clone(), DNSClass::IN, RecordType::A))
        .unwrap_err();

    let error_str = format!("{}", err);
    assert!(
        error_str.contains("timed out"),
        format!("actual error: {}", error_str)
    );

    io_loop
        .run(client.query(name.clone(), DNSClass::IN, RecordType::AAAA))
        .unwrap_err();

    // test that we don't have any thing funky with registering new timeouts, etc...
    //   it would be cool if we could maintain a different error here, but shutdown is problably ok.
    //
    // match err.kind() {
    //     &ClientErrorKind::Timeout => (),
    //     e @ _ => assert!(false, format!("something else: {}", e)),
    // }
}

#[test]
fn test_timeout_query_nonet() {
    let io_loop = Core::new().unwrap();
    let (stream, sender) = NeverReturnsClientStream::new();
    let client = ClientFuture::with_timeout(
        stream,
        Box::new(sender),
        &io_loop.handle(),
        std::time::Duration::from_millis(1),
        None,
    );
    test_timeout_query(client, io_loop);
}

#[test]
fn test_timeout_query_udp() {
    let io_loop = Core::new().unwrap();

    // this is a test network, it should NOT be in use
    let addr: SocketAddr = ("203.0.113.0", 53)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let (stream, sender) = UdpClientStream::new(addr, &io_loop.handle());
    let client = ClientFuture::with_timeout(
        stream,
        sender,
        &io_loop.handle(),
        std::time::Duration::from_millis(1),
        None,
    );
    test_timeout_query(client, io_loop);
}

#[test]
fn test_timeout_query_tcp() {
    let io_loop = Core::new().unwrap();

    // this is a test network, it should NOT be in use
    let addr: SocketAddr = ("203.0.113.0", 53)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let (stream, sender) =
        TcpClientStream::with_timeout(addr, &io_loop.handle(), std::time::Duration::from_millis(1));
    let client = ClientFuture::with_timeout(
        stream,
        sender,
        &io_loop.handle(),
        std::time::Duration::from_millis(1),
        None,
    );
    test_timeout_query(client, io_loop);
}
