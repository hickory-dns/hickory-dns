extern crate chrono;
extern crate env_logger;
extern crate futures;
extern crate log;
extern crate openssl;
#[cfg(feature = "dns-over-https-rustls")]
extern crate rustls;
extern crate tokio;
extern crate tokio_tcp;
extern crate tokio_udp;
extern crate trust_dns;
#[cfg(feature = "dns-over-https")]
extern crate trust_dns_https;
extern crate trust_dns_integration;
extern crate trust_dns_proto;
extern crate trust_dns_server;
#[cfg(feature = "dns-over-https-rustls")]
extern crate webpki_roots;

use std::net::*;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

#[cfg(feature = "dnssec")]
use chrono::Duration;
use futures::Future;
use tokio::runtime::current_thread::Runtime;
use tokio_tcp::TcpStream as TokioTcpStream;
use tokio_udp::UdpSocket as TokioUdpSocket;

use trust_dns::client::{BasicClientHandle, ClientFuture, ClientHandle};
use trust_dns::error::ClientErrorKind;
use trust_dns::op::ResponseCode;
#[cfg(feature = "dnssec")]
use trust_dns::rr::dnssec::Signer;
#[cfg(feature = "dnssec")]
use trust_dns::rr::Record;
use trust_dns::rr::{DNSClass, Name, RData, RecordSet, RecordType};
use trust_dns::tcp::TcpClientStream;
use trust_dns::udp::UdpClientStream;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::xfer::DnsResponse;
#[cfg(feature = "dnssec")]
use trust_dns_proto::xfer::{DnsMultiplexer, DnsMultiplexerConnect, DnsMultiplexerSerialResponse};
use trust_dns_server::authority::{Authority, Catalog};

use trust_dns_integration::authority::create_example;
use trust_dns_integration::{NeverReturnsClientStream, TestClientStream};

#[test]
fn test_query_nonet() {
    // env_logger::init();

    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), Box::new(authority));

    let mut io_loop = Runtime::new().unwrap();
    let (stream, sender) = TestClientStream::new(Arc::new(Mutex::new(catalog)));
    let (bg, mut client) = ClientFuture::new(stream, Box::new(sender), None);
    io_loop.spawn(bg);

    io_loop.block_on(test_query(&mut client)).unwrap();
    io_loop.block_on(test_query(&mut client)).unwrap();
}

#[test]
fn test_query_udp_ipv4() {
    let mut io_loop = Runtime::new().unwrap();
    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let stream = UdpClientStream::<TokioUdpSocket>::new(addr);
    let (bg, mut client) = ClientFuture::connect(stream);
    io_loop.spawn(bg);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.block_on(test_query(&mut client)).unwrap();
    io_loop.block_on(test_query(&mut client)).unwrap();
}

#[test]
#[ignore]
fn test_query_udp_ipv6() {
    let mut io_loop = Runtime::new().unwrap();
    let addr: SocketAddr = ("2001:4860:4860::8888", 53)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let stream = UdpClientStream::<TokioUdpSocket>::new(addr);
    let (bg, mut client) = ClientFuture::connect(stream);
    io_loop.spawn(bg);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.block_on(test_query(&mut client)).unwrap();
    io_loop.block_on(test_query(&mut client)).unwrap();
}

#[test]
fn test_query_tcp_ipv4() {
    let mut io_loop = Runtime::new().unwrap();
    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = TcpClientStream::<TokioTcpStream>::new(addr);
    let (bg, mut client) = ClientFuture::new(Box::new(stream), sender, None);
    io_loop.spawn(bg);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.block_on(test_query(&mut client)).unwrap();
    io_loop.block_on(test_query(&mut client)).unwrap();
}

#[test]
#[ignore]
fn test_query_tcp_ipv6() {
    let mut io_loop = Runtime::new().unwrap();
    let addr: SocketAddr = ("2001:4860:4860::8888", 53)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let (stream, sender) = TcpClientStream::<TokioTcpStream>::new(addr);
    let (bg, mut client) = ClientFuture::new(Box::new(stream), sender, None);
    io_loop.spawn(bg);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.block_on(test_query(&mut client)).unwrap();
    io_loop.block_on(test_query(&mut client)).unwrap();
}

#[test]
#[cfg(feature = "dns-over-https-rustls")]
fn test_query_https() {
    use rustls::{ClientConfig, ProtocolVersion, RootCertStore};
    use trust_dns_https::HttpsClientStreamBuilder;

    let mut io_loop = Runtime::new().unwrap();
    let addr: SocketAddr = ("1.1.1.1", 443).to_socket_addrs().unwrap().next().unwrap();

    // using the mozilla default root store
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(&self::webpki_roots::TLS_SERVER_ROOTS);
    let versions = vec![ProtocolVersion::TLSv1_2];

    let mut client_config = ClientConfig::new();
    client_config.root_store = root_store;
    client_config.versions = versions;

    let https_builder = HttpsClientStreamBuilder::with_client_config(client_config);
    let (bg, mut client) =
        ClientFuture::connect(https_builder.build(addr, "cloudflare-dns.com".to_string()));
    io_loop.spawn(bg);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.block_on(test_query(&mut client)).unwrap();
    io_loop.block_on(test_query(&mut client)).unwrap();
}

#[cfg(test)]
fn test_query<R>(client: &mut BasicClientHandle<R>) -> Box<dyn Future<Output = Result<(), ()>>>
where
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send,
{
    let name = Name::from_ascii("WWW.example.com").unwrap();

    Box::new(
        client
            .query(name.clone(), DNSClass::IN, RecordType::A)
            .map(move |response| {
                println!("response records: {:?}", response);
                assert!(response
                    .queries()
                    .first()
                    .expect("expected query")
                    .name()
                    .eq_case(&name));

                let record = &response.answers()[0];
                assert_eq!(record.name(), &name);
                assert_eq!(record.rr_type(), RecordType::A);
                assert_eq!(record.dns_class(), DNSClass::IN);

                if let RData::A(ref address) = *record.rdata() {
                    assert_eq!(address, &Ipv4Addr::new(93, 184, 216, 34))
                } else {
                    panic!();
                }
            })
            .map_err(|e| {
                panic!("query failed: {}", e);
            }),
    )
}

#[test]
fn test_notify() {
    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), Box::new(authority));

    let mut io_loop = Runtime::new().unwrap();
    let (stream, sender) = TestClientStream::new(Arc::new(Mutex::new(catalog)));
    let (bg, mut client) = ClientFuture::new(stream, Box::new(sender), None);
    io_loop.spawn(bg);

    let name = Name::from_str("ping.example.com").unwrap();

    let message = io_loop.block_on(client.notify(
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
#[cfg(feature = "dnssec")]
#[allow(clippy::type_complexity)]
fn create_sig0_ready_client(
    _io_loop: &mut Runtime,
) -> (
    ClientFuture<
        DnsMultiplexerConnect<
            Box<Future<Output = Result<TestClientStream, ProtoError>> + Send>,
            TestClientStream,
            Signer,
        >,
        DnsMultiplexer<TestClientStream, Signer>,
        DnsMultiplexerSerialResponse,
    >,
    BasicClientHandle<impl Future<Output = Result<DnsResponse, ProtoError>>>,
    Name,
) {
    use openssl::rsa::Rsa;
    use trust_dns::rr::dnssec::{Algorithm, KeyPair};
    use trust_dns::rr::rdata::{DNSSECRData, DNSSECRecordType};
    use trust_dns_server::store::sqlite::SqliteAuthority;

    let authority = create_example();
    let mut authority = SqliteAuthority::new(authority, true, false);
    let origin = authority.origin().clone();

    let trusted_name = Name::from_str("trusted.example.com").unwrap();

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
    catalog.upsert(authority.origin().clone(), Box::new(authority));

    let signer = Arc::new(signer);
    let (stream, sender) = TestClientStream::new(Arc::new(Mutex::new(catalog)));
    let (bg, client) = ClientFuture::new(stream, Box::new(sender), Some(signer));

    (bg, client, origin.into())
}

#[cfg(feature = "dnssec")]
#[test]
fn test_create() {
    let mut io_loop = Runtime::new().unwrap();
    let (bg, mut client, origin) = create_sig0_ready_client(&mut io_loop);

    // create a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));
    let record = record;

    io_loop.spawn(bg);
    let result = io_loop
        .block_on(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    let result = io_loop
        .block_on(client.query(record.name().clone(), record.dns_class(), record.rr_type()))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // trying to create again should error
    // TODO: it would be cool to make this
    let result = io_loop
        .block_on(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);

    // will fail if already set and not the same value.
    let mut record = record.clone();
    record.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));

    let result = io_loop
        .block_on(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);
}

#[cfg(feature = "dnssec")]
#[test]
fn test_create_multi() {
    let mut io_loop = Runtime::new().unwrap();
    let (bg, mut client, origin) = create_sig0_ready_client(&mut io_loop);

    // create a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));
    let record = record;

    let mut record2 = record.clone();
    record2.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 11)));
    let record2 = record2;

    let mut rrset = RecordSet::from(record.clone());
    rrset.insert(record2.clone(), 0);
    let rrset = rrset;

    io_loop.spawn(bg);
    let result = io_loop
        .block_on(client.create(rrset.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    let result = io_loop
        .block_on(client.query(record.name().clone(), record.dns_class(), record.rr_type()))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);

    assert!(result.answers().iter().any(|rr| *rr == record));
    assert!(result.answers().iter().any(|rr| *rr == record2));

    // trying to create again should error
    // TODO: it would be cool to make this
    let result = io_loop
        .block_on(client.create(rrset, origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);

    // will fail if already set and not the same value.
    let mut record = record.clone();
    record.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 12)));

    let result = io_loop
        .block_on(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);
}

#[cfg(feature = "dnssec")]
#[test]
fn test_append() {
    let mut io_loop = Runtime::new().unwrap();
    let (bg, mut client, origin) = create_sig0_ready_client(&mut io_loop);

    // append a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));
    let record = record;

    // first check the must_exist option
    io_loop.spawn(bg);
    let result = io_loop
        .block_on(client.append(record.clone(), origin.clone(), true))
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    // next append to a non-existent RRset
    let result = io_loop
        .block_on(client.append(record.clone(), origin.clone(), false))
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .block_on(client.query(record.name().clone(), record.dns_class(), record.rr_type()))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // will fail if already set and not the same value.
    let mut record2 = record.clone();
    record2.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
    let record2 = record2;

    let result = io_loop
        .block_on(client.append(record2.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(record.name().clone(), record.dns_class(), record.rr_type()))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);

    assert!(result.answers().iter().any(|rr| *rr == record));
    assert!(result.answers().iter().any(|rr| *rr == record2));

    // show that appending the same thing again is ok, but doesn't add any records
    let result = io_loop
        .block_on(client.append(record.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(record.name().clone(), record.dns_class(), record.rr_type()))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);
}

#[cfg(feature = "dnssec")]
#[test]
fn test_append_multi() {
    let mut io_loop = Runtime::new().unwrap();
    let (bg, mut client, origin) = create_sig0_ready_client(&mut io_loop);

    // append a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

    // first check the must_exist option
    io_loop.spawn(bg);
    let result = io_loop
        .block_on(client.append(record.clone(), origin.clone(), true))
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    // next append to a non-existent RRset
    let result = io_loop
        .block_on(client.append(record.clone(), origin.clone(), false))
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .block_on(client.query(record.name().clone(), record.dns_class(), record.rr_type()))
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
    let mut rrset = RecordSet::from(record2.clone());
    rrset.insert(record3.clone(), 0);

    let result = io_loop
        .block_on(client.append(rrset, origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(record.name().clone(), record.dns_class(), record.rr_type()))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 3);

    assert!(result.answers().iter().any(|rr| *rr == record));
    assert!(result.answers().iter().any(|rr| *rr == record2));
    assert!(result.answers().iter().any(|rr| *rr == record3));

    // show that appending the same thing again is ok, but doesn't add any records
    // TODO: technically this is a test for the Server, not client...
    let result = io_loop
        .block_on(client.append(record.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(record.name().clone(), record.dns_class(), record.rr_type()))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 3);
}

#[cfg(feature = "dnssec")]
#[test]
fn test_compare_and_swap() {
    let mut io_loop = Runtime::new().unwrap();
    let (bg, mut client, origin) = create_sig0_ready_client(&mut io_loop);

    // create a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));
    let record = record;

    io_loop.spawn(bg);
    let result = io_loop
        .block_on(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let current = record;
    let mut new = current.clone();
    new.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
    let new = new;

    let result = io_loop
        .block_on(client.compare_and_swap(current.clone(), new.clone(), origin.clone()))
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(new.name().clone(), new.dns_class(), new.rr_type()))
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
        .block_on(client.compare_and_swap(current, not.clone(), origin.clone()))
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    let result = io_loop
        .block_on(client.query(new.name().clone(), new.dns_class(), new.rr_type()))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result.answers().iter().any(|rr| *rr == new));
    assert!(!result.answers().iter().any(|rr| *rr == not));
}

#[cfg(feature = "dnssec")]
#[test]
fn test_compare_and_swap_multi() {
    let mut io_loop = Runtime::new().unwrap();
    let (bg, mut client, origin) = create_sig0_ready_client(&mut io_loop);

    // create a record
    let mut current = RecordSet::with_ttl(
        Name::from_str("new.example.com").unwrap(),
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

    io_loop.spawn(bg);
    let result = io_loop
        .block_on(client.create(current.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let mut new = RecordSet::with_ttl(current.name().clone(), current.record_type(), current.ttl());
    let new1 = new
        .new_record(&RData::A(Ipv4Addr::new(100, 10, 101, 10)))
        .clone();
    let new2 = new
        .new_record(&RData::A(Ipv4Addr::new(100, 10, 101, 11)))
        .clone();
    let new = new;

    let result = io_loop
        .block_on(client.compare_and_swap(current.clone(), new.clone(), origin.clone()))
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(new.name().clone(), new.dns_class(), new.record_type()))
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
        .block_on(client.compare_and_swap(current, not.clone(), origin.clone()))
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    let result = io_loop
        .block_on(client.query(new.name().clone(), new.dns_class(), new.record_type()))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);
    assert!(result.answers().iter().any(|rr| *rr == new1));
    assert!(!result.answers().iter().any(|rr| *rr == not));
}

#[cfg(feature = "dnssec")]
#[test]
fn test_delete_by_rdata() {
    let mut io_loop = Runtime::new().unwrap();
    let (bg, mut client, origin) = create_sig0_ready_client(&mut io_loop);

    // append a record
    let mut record1 = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record1.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

    // first check the must_exist option
    io_loop.spawn(bg);
    let result = io_loop
        .block_on(client.delete_by_rdata(record1.clone(), origin.clone()))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop
        .block_on(client.create(record1.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let mut record2 = record1.clone();
    record2.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
    let result = io_loop
        .block_on(client.append(record2.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .block_on(client.delete_by_rdata(record2.clone(), origin.clone()))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(
            record1.name().clone(),
            record1.dns_class(),
            record1.rr_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result.answers().iter().any(|rr| *rr == record1));
}

#[cfg(feature = "dnssec")]
#[test]
fn test_delete_by_rdata_multi() {
    let mut io_loop = Runtime::new().unwrap();
    let (bg, mut client, origin) = create_sig0_ready_client(&mut io_loop);

    // append a record
    let mut rrset = RecordSet::with_ttl(
        Name::from_str("new.example.com").unwrap(),
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
    io_loop.spawn(bg);
    let result = io_loop
        .block_on(client.delete_by_rdata(rrset.clone(), origin.clone()))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop
        .block_on(client.create(rrset.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // append a record
    let mut rrset = RecordSet::with_ttl(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );

    let record1 = rrset.new_record(record1.rdata()).clone();
    let record3 = rrset.new_record(record3.rdata()).clone();
    let rrset = rrset;

    let result = io_loop
        .block_on(client.append(rrset.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .block_on(client.delete_by_rdata(rrset.clone(), origin.clone()))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(
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

#[cfg(feature = "dnssec")]
#[test]
fn test_delete_rrset() {
    let mut io_loop = Runtime::new().unwrap();
    let (bg, mut client, origin) = create_sig0_ready_client(&mut io_loop);

    // append a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

    // first check the must_exist option
    io_loop.spawn(bg);
    let result = io_loop
        .block_on(client.delete_rrset(record.clone(), origin.clone()))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop
        .block_on(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let mut record = record.clone();
    record.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
    let result = io_loop
        .block_on(client.append(record.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .block_on(client.delete_rrset(record.clone(), origin.clone()))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(record.name().clone(), record.dns_class(), record.rr_type()))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);
}

#[cfg(feature = "dnssec")]
#[test]
fn test_delete_all() {
    let mut io_loop = Runtime::new().unwrap();
    let (bg, mut client, origin) = create_sig0_ready_client(&mut io_loop);

    // append a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

    // first check the must_exist option
    io_loop.spawn(bg);
    let result = io_loop
        .block_on(client.delete_all(record.name().clone(), origin.clone(), DNSClass::IN))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop
        .block_on(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let mut record = record.clone();
    record.set_rr_type(RecordType::AAAA);
    record.set_rdata(RData::AAAA(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)));
    let result = io_loop
        .block_on(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .block_on(client.delete_all(record.name().clone(), origin.clone(), DNSClass::IN))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(record.name().clone(), record.dns_class(), RecordType::A))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);

    let result = io_loop
        .block_on(client.query(record.name().clone(), record.dns_class(), RecordType::AAAA))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);
}

fn test_timeout_query<R>(mut client: BasicClientHandle<R>, mut io_loop: Runtime)
where
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send,
{
    let name = Name::from_str("www.example.com").unwrap();

    let err = io_loop
        .block_on(client.query(name.clone(), DNSClass::IN, RecordType::A))
        .unwrap_err();

    println!("got error: {:?}", err);
    assert_eq!(err.kind(), &ClientErrorKind::Timeout);

    io_loop
        .block_on(client.query(name.clone(), DNSClass::IN, RecordType::AAAA))
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
    env_logger::try_init().ok();
    let mut io_loop = Runtime::new().unwrap();
    let (stream, sender) = NeverReturnsClientStream::new();
    let (bg, client) = ClientFuture::with_timeout(
        stream,
        Box::new(sender),
        std::time::Duration::from_millis(1),
        None,
    );

    io_loop.spawn(bg);
    test_timeout_query(client, io_loop);
}

#[test]
fn test_timeout_query_udp() {
    env_logger::try_init().ok();
    let mut io_loop = Runtime::new().unwrap();

    // this is a test network, it should NOT be in use
    let addr: SocketAddr = ("203.0.113.0", 53)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let stream =
        UdpClientStream::<TokioUdpSocket>::with_timeout(addr, std::time::Duration::from_millis(1));
    let (bg, client) = ClientFuture::connect(stream);
    io_loop.spawn(bg);
    test_timeout_query(client, io_loop);
}

#[test]
fn test_timeout_query_tcp() {
    env_logger::try_init().ok();
    let mut io_loop = Runtime::new().unwrap();

    // this is a test network, it should NOT be in use
    let addr: SocketAddr = ("203.0.113.0", 53)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let (stream, sender) =
        TcpClientStream::<TokioTcpStream>::with_timeout(addr, std::time::Duration::from_millis(1));
    let (bg, client) = ClientFuture::with_timeout(
        Box::new(stream),
        sender,
        std::time::Duration::from_millis(1),
        None,
    );
    io_loop.spawn(bg);
    test_timeout_query(client, io_loop);
}
