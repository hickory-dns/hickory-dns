use std::{
    net::*,
    str::FromStr,
    sync::{Arc, Mutex as StdMutex},
};

use futures::{Future, FutureExt, TryFutureExt};
#[cfg(feature = "dnssec")]
use time::Duration;
use tokio::{
    net::{TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket},
    runtime::Runtime,
};

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
use hickory_client::client::Signer;
use hickory_client::{
    client::{AsyncClient, ClientHandle},
    error::ClientErrorKind,
    op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        rdata::{
            opt::{EdnsCode, EdnsOption},
            A,
        },
        DNSClass, Name, RData, RecordSet, RecordType,
    },
    tcp::TcpClientStream,
    udp::UdpClientStream,
};
#[cfg(feature = "dnssec")]
use hickory_proto::rr::{dnssec::SigSigner, Record};
#[cfg(feature = "dnssec")]
use hickory_proto::xfer::{DnsExchangeBackground, DnsMultiplexer};
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
use hickory_proto::TokioTime;
use hickory_proto::{iocompat::AsyncIoTokioAsStd, xfer::FirstAnswer, DnsHandle};

use hickory_server::authority::{Authority, Catalog};

use hickory_integration::{
    example_authority::create_example, NeverReturnsClientStream, TestClientStream,
};

#[test]
fn test_query_nonet() {
    // env_logger::init();

    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(
        authority.origin().clone(),
        vec![Box::new(Arc::new(authority))],
    );

    let io_loop = Runtime::new().unwrap();
    let (stream, sender) = TestClientStream::new(Arc::new(StdMutex::new(catalog)));
    let client = AsyncClient::new(stream, sender, None);
    let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
    hickory_proto::spawn_bg(&io_loop, bg);

    io_loop.block_on(test_query(&mut client));
    io_loop.block_on(test_query(&mut client));
}

#[test]
fn test_query_udp_ipv4() {
    let io_loop = Runtime::new().unwrap();
    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let stream = UdpClientStream::<TokioUdpSocket>::new(addr);
    let client = AsyncClient::connect(stream);
    let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
    hickory_proto::spawn_bg(&io_loop, bg);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.block_on(test_query(&mut client));
    io_loop.block_on(test_query(&mut client));
    io_loop.block_on(test_query_edns(&mut client));
}

#[test]
#[ignore]
fn test_query_udp_ipv6() {
    let io_loop = Runtime::new().unwrap();
    let addr: SocketAddr = ("2001:4860:4860::8888", 53)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let stream = UdpClientStream::<TokioUdpSocket>::new(addr);
    let client = AsyncClient::connect(stream);
    let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
    hickory_proto::spawn_bg(&io_loop, bg);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.block_on(test_query(&mut client));
    io_loop.block_on(test_query(&mut client));
    io_loop.block_on(test_query_edns(&mut client));
}

#[test]
fn test_query_tcp_ipv4() {
    let io_loop = Runtime::new().unwrap();
    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
    let client = AsyncClient::new(stream, sender, None);
    let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
    hickory_proto::spawn_bg(&io_loop, bg);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.block_on(test_query(&mut client));
    io_loop.block_on(test_query(&mut client));
}

#[test]
#[ignore]
fn test_query_tcp_ipv6() {
    let io_loop = Runtime::new().unwrap();
    let addr: SocketAddr = ("2001:4860:4860::8888", 53)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
    let client = AsyncClient::new(stream, sender, None);
    let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
    hickory_proto::spawn_bg(&io_loop, bg);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.block_on(test_query(&mut client));
    io_loop.block_on(test_query(&mut client));
}

#[test]
#[cfg(feature = "dns-over-https-rustls")]
fn test_query_https() {
    use hickory_proto::h2::HttpsClientStreamBuilder;
    use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};

    const ALPN_H2: &[u8] = b"h2";

    let io_loop = Runtime::new().unwrap();
    let addr: SocketAddr = ("1.1.1.1", 443).to_socket_addrs().unwrap().next().unwrap();

    // using the mozilla default root store
    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let mut client_config = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_config.alpn_protocols.push(ALPN_H2.to_vec());

    let https_builder = HttpsClientStreamBuilder::with_client_config(Arc::new(client_config));
    let client = AsyncClient::connect(
        https_builder
            .build::<AsyncIoTokioAsStd<TokioTcpStream>>(addr, "cloudflare-dns.com".to_string()),
    );
    let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
    hickory_proto::spawn_bg(&io_loop, bg);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.block_on(test_query(&mut client));
    io_loop.block_on(test_query(&mut client));
}

#[cfg(test)]
fn test_query(client: &mut AsyncClient) -> impl Future<Output = ()> {
    let name = Name::from_ascii("WWW.example.com").unwrap();

    client
        .query(name.clone(), DNSClass::IN, RecordType::A)
        .map_ok(move |response| {
            println!("response records: {response:?}");
            assert!(response
                .queries()
                .first()
                .expect("expected query")
                .name()
                .eq_case(&name));

            let record = &response.answers()[0];
            assert_eq!(record.name(), &name);
            assert_eq!(record.record_type(), RecordType::A);
            assert_eq!(record.dns_class(), DNSClass::IN);

            if let RData::A(ref address) = record.data().unwrap() {
                assert_eq!(address, &A::new(93, 184, 216, 34))
            } else {
                panic!();
            }
        })
        .map(|r: Result<_, _>| r.expect("query failed"))
}

#[cfg(test)]
fn test_query_edns(client: &mut AsyncClient) -> impl Future<Output = ()> {
    let name = Name::from_ascii("WWW.example.com").unwrap();
    let mut edns = Edns::new();
    // garbage subnet value, but lets check
    edns.options_mut()
        .insert(EdnsOption::Subnet("1.2.0.0/16".parse().unwrap()));

    // TODO: write builder
    let mut msg = Message::new();
    msg.add_query({
        let mut query = Query::query(name.clone(), RecordType::A);
        query.set_query_class(DNSClass::IN);
        query
    })
    .set_id(rand::random::<u16>())
    .set_message_type(MessageType::Query)
    .set_op_code(OpCode::Query)
    .set_recursion_desired(true)
    .set_edns(edns)
    .extensions_mut()
    .as_mut()
    .map(|edns| edns.set_max_payload(1232).set_version(0));

    client
        .send(msg)
        .first_answer()
        .map_ok(move |response| {
            println!("response records: {response:?}");
            assert!(response
                .queries()
                .first()
                .expect("expected query")
                .name()
                .eq_case(&name));

            let record = &response.answers()[0];
            assert_eq!(record.name(), &name);
            assert_eq!(record.record_type(), RecordType::A);
            assert_eq!(record.dns_class(), DNSClass::IN);
            assert!(response.extensions().is_some());
            assert_eq!(
                response
                    .extensions()
                    .as_ref()
                    .unwrap()
                    .option(EdnsCode::Subnet)
                    .unwrap(),
                &EdnsOption::Subnet("1.2.0.0/16".parse().unwrap())
            );
            if let RData::A(ref address) = *record.data().unwrap() {
                assert_eq!(address, &A::new(93, 184, 216, 34))
            } else {
                panic!();
            }
        })
        .map(|r: Result<_, _>| r.expect("query failed"))
}

#[test]
fn test_notify() {
    let io_loop = Runtime::new().unwrap();
    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(
        authority.origin().clone(),
        vec![Box::new(Arc::new(authority))],
    );

    let (stream, sender) = TestClientStream::new(Arc::new(StdMutex::new(catalog)));
    let client = AsyncClient::new(stream, sender, None);
    let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
    hickory_proto::spawn_bg(&io_loop, bg);

    let name = Name::from_str("ping.example.com").unwrap();

    let message =
        io_loop.block_on(client.notify(name, DNSClass::IN, RecordType::A, None::<RecordSet>));
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
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[allow(clippy::type_complexity)]
async fn create_sig0_ready_client() -> (
    (
        AsyncClient,
        DnsExchangeBackground<DnsMultiplexer<TestClientStream, Signer>, TokioTime>,
    ),
    Name,
) {
    use hickory_proto::rr::dnssec::rdata::DNSSECRData;
    use hickory_proto::rr::dnssec::{Algorithm, KeyPair};
    use hickory_server::store::sqlite::SqliteAuthority;
    use openssl::rsa::Rsa;

    let authority = create_example();
    let mut authority = SqliteAuthority::new(authority, true, false);
    let origin = authority.origin().clone();

    let trusted_name = Name::from_str("trusted.example.com").unwrap();

    let rsa = Rsa::generate(2048).unwrap();
    let key = KeyPair::from_rsa(rsa).unwrap();
    let sig0_key = key.to_sig0key(Algorithm::RSASHA256).unwrap();

    let signer = SigSigner::sig0(sig0_key.clone(), key, trusted_name.clone());

    // insert the KEY for the trusted.example.com
    let mut auth_key = Record::with(
        trusted_name,
        RecordType::KEY,
        Duration::minutes(5).whole_seconds() as u32,
    );
    auth_key.set_data(Some(RData::DNSSEC(DNSSECRData::KEY(sig0_key))));
    authority.upsert_mut(auth_key, 0);

    // setup the catalog
    let mut catalog = Catalog::new();
    catalog.upsert(
        authority.origin().clone(),
        vec![Box::new(Arc::new(authority))],
    );

    let signer = Arc::new(signer.into());
    let (stream, sender) = TestClientStream::new(Arc::new(StdMutex::new(catalog)));
    let client = AsyncClient::new(stream, sender, Some(signer))
        .await
        .expect("failed to get new AsyncClient");

    (client, origin.into())
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_create() {
    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::spawn_bg(&io_loop, bg);

    // create a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).whole_seconds() as u32,
    );
    record.set_data(Some(RData::A(A::new(100, 10, 100, 10))));
    let record = record;

    let result = io_loop
        .block_on(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    let result = io_loop
        .block_on(client.query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        ))
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
    let mut record = record;
    record.set_data(Some(RData::A(A::new(101, 11, 101, 11))));

    let result = io_loop
        .block_on(client.create(record, origin))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_create_multi() {
    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::spawn_bg(&io_loop, bg);

    // create a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).whole_seconds() as u32,
    );
    record.set_data(Some(RData::A(A::new(100, 10, 100, 10))));
    let record = record;

    let mut record2 = record.clone();
    record2.set_data(Some(RData::A(A::new(100, 10, 100, 11))));
    let record2 = record2;

    let mut rrset = RecordSet::from(record.clone());
    rrset.insert(record2.clone(), 0);
    let rrset = rrset;

    let result = io_loop
        .block_on(client.create(rrset.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    let result = io_loop
        .block_on(client.query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        ))
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
    let mut record = record;
    record.set_data(Some(RData::A(A::new(101, 11, 101, 12))));

    let result = io_loop
        .block_on(client.create(record, origin))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_append() {
    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::spawn_bg(&io_loop, bg);

    // append a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).whole_seconds() as u32,
    );
    record.set_data(Some(RData::A(A::new(100, 10, 100, 10))));
    let record = record;

    // first check the must_exist option
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
        .block_on(client.query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // will fail if already set and not the same value.
    let mut record2 = record.clone();
    record2.set_data(Some(RData::A(A::new(101, 11, 101, 11))));
    let record2 = record2;

    let result = io_loop
        .block_on(client.append(record2.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);

    assert!(result.answers().iter().any(|rr| *rr == record));
    assert!(result.answers().iter().any(|rr| *rr == record2));

    // show that appending the same thing again is ok, but doesn't add any records
    let result = io_loop
        .block_on(client.append(record.clone(), origin, true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_append_multi() {
    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::spawn_bg(&io_loop, bg);

    // append a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).whole_seconds() as u32,
    );
    record.set_data(Some(RData::A(A::new(100, 10, 100, 10))));

    // first check the must_exist option
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
        .block_on(client.query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // will fail if already set and not the same value.
    let mut record2 = record.clone();
    record2.set_data(Some(RData::A(A::new(101, 11, 101, 11))));
    let mut record3 = record.clone();
    record3.set_data(Some(RData::A(A::new(101, 11, 101, 12))));

    // build the append set
    let mut rrset = RecordSet::from(record2.clone());
    rrset.insert(record3.clone(), 0);

    let result = io_loop
        .block_on(client.append(rrset, origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
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
        .block_on(client.append(record.clone(), origin, true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 3);
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_compare_and_swap() {
    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::spawn_bg(&io_loop, bg);

    // create a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).whole_seconds() as u32,
    );
    record.set_data(Some(RData::A(A::new(100, 10, 100, 10))));
    let record = record;

    let result = io_loop
        .block_on(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let current = record;
    let mut new = current.clone();
    new.set_data(Some(RData::A(A::new(101, 11, 101, 11))));
    let new = new;

    let result = io_loop
        .block_on(client.compare_and_swap(current.clone(), new.clone(), origin.clone()))
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(new.name().clone(), new.dns_class(), new.record_type()))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result.answers().iter().any(|rr| *rr == new));
    assert!(!result.answers().iter().any(|rr| *rr == current));

    // check the it fails if tried again.
    let mut not = new.clone();
    not.set_data(Some(RData::A(A::new(102, 12, 102, 12))));
    let not = not;

    let result = io_loop
        .block_on(client.compare_and_swap(current, not.clone(), origin))
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    let result = io_loop
        .block_on(client.query(new.name().clone(), new.dns_class(), new.record_type()))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result.answers().iter().any(|rr| *rr == new));
    assert!(!result.answers().iter().any(|rr| *rr == not));
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_compare_and_swap_multi() {
    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::spawn_bg(&io_loop, bg);

    // create a record
    let mut current = RecordSet::with_ttl(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).whole_seconds() as u32,
    );

    let current1 = current
        .new_record(&RData::A(A::new(100, 10, 100, 10)))
        .clone();
    let current2 = current
        .new_record(&RData::A(A::new(100, 10, 100, 11)))
        .clone();
    let current = current;

    let result = io_loop
        .block_on(client.create(current.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let mut new = RecordSet::with_ttl(current.name().clone(), current.record_type(), current.ttl());
    let new1 = new.new_record(&RData::A(A::new(100, 10, 101, 10))).clone();
    let new2 = new.new_record(&RData::A(A::new(100, 10, 101, 11))).clone();
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
    not.set_data(Some(RData::A(A::new(102, 12, 102, 12))));
    let not = not;

    let result = io_loop
        .block_on(client.compare_and_swap(current, not.clone(), origin))
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

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_delete_by_rdata() {
    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::spawn_bg(&io_loop, bg);

    // append a record
    let mut record1 = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).whole_seconds() as u32,
    );
    record1.set_data(Some(RData::A(A::new(100, 10, 100, 10))));

    // first check the must_exist option
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
    record2.set_data(Some(RData::A(A::new(101, 11, 101, 11))));
    let result = io_loop
        .block_on(client.append(record2.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .block_on(client.delete_by_rdata(record2, origin))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(
            record1.name().clone(),
            record1.dns_class(),
            record1.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result.answers().iter().any(|rr| *rr == record1));
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_delete_by_rdata_multi() {
    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::spawn_bg(&io_loop, bg);

    // append a record
    let mut rrset = RecordSet::with_ttl(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).whole_seconds() as u32,
    );

    let record1 = rrset
        .new_record(&RData::A(A::new(100, 10, 100, 10)))
        .clone();
    let record2 = rrset
        .new_record(&RData::A(A::new(100, 10, 100, 11)))
        .clone();
    let record3 = rrset
        .new_record(&RData::A(A::new(100, 10, 100, 12)))
        .clone();
    let record4 = rrset
        .new_record(&RData::A(A::new(100, 10, 100, 13)))
        .clone();
    let rrset = rrset;

    // first check the must_exist option
    let result = io_loop
        .block_on(client.delete_by_rdata(rrset.clone(), origin.clone()))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop
        .block_on(client.create(rrset, origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // append a record
    let mut rrset = RecordSet::with_ttl(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).whole_seconds() as u32,
    );

    let record1 = rrset.new_record(record1.data().unwrap()).clone();
    let record3 = rrset.new_record(record3.data().unwrap()).clone();
    let rrset = rrset;

    let result = io_loop
        .block_on(client.append(rrset.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .block_on(client.delete_by_rdata(rrset, origin))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(
            record1.name().clone(),
            record1.dns_class(),
            record1.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);
    assert!(!result.answers().iter().any(|rr| *rr == record1));
    assert!(result.answers().iter().any(|rr| *rr == record2));
    assert!(!result.answers().iter().any(|rr| *rr == record3));
    assert!(result.answers().iter().any(|rr| *rr == record4));
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_delete_rrset() {
    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::spawn_bg(&io_loop, bg);

    // append a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).whole_seconds() as u32,
    );
    record.set_data(Some(RData::A(A::new(100, 10, 100, 10))));

    // first check the must_exist option
    let result = io_loop
        .block_on(client.delete_rrset(record.clone(), origin.clone()))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop
        .block_on(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    record.set_data(Some(RData::A(A::new(101, 11, 101, 11))));
    let result = io_loop
        .block_on(client.append(record.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .block_on(client.delete_rrset(record.clone(), origin))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_delete_all() {
    use hickory_proto::rr::rdata::AAAA;

    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::spawn_bg(&io_loop, bg);

    // append a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).whole_seconds() as u32,
    );
    record.set_data(Some(RData::A(A::new(100, 10, 100, 10))));

    // first check the must_exist option
    let result = io_loop
        .block_on(client.delete_all(record.name().clone(), origin.clone(), DNSClass::IN))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop
        .block_on(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    record.set_record_type(RecordType::AAAA);
    record.set_data(Some(RData::AAAA(AAAA::new(1, 2, 3, 4, 5, 6, 7, 8))));
    let result = io_loop
        .block_on(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .block_on(client.delete_all(record.name().clone(), origin, DNSClass::IN))
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

fn test_timeout_query(mut client: AsyncClient, io_loop: Runtime) {
    let name = Name::from_str("www.example.com").unwrap();

    let err = io_loop
        .block_on(client.query(name.clone(), DNSClass::IN, RecordType::A))
        .unwrap_err();

    println!("got error: {err:?}");
    if let ClientErrorKind::Timeout = err.kind() {
    } else {
        panic!("expected timeout error");
    }

    io_loop
        .block_on(client.query(name, DNSClass::IN, RecordType::AAAA))
        .unwrap_err();

    // test that we don't have any thing funky with registering new timeouts, etc...
    //   it would be cool if we could maintain a different error here, but shutdown is probably ok.
    //
    // match err.kind() {
    //     &ClientErrorKind::Timeout => (),
    //     e @ _ => assert!(false, format!("something else: {}", e)),
    // }
}

#[test]
fn test_timeout_query_nonet() {
    //env_logger::try_init().ok();
    let io_loop = Runtime::new().expect("failed to create Tokio Runtime");
    let (stream, sender) = NeverReturnsClientStream::new();
    let client =
        AsyncClient::with_timeout(stream, sender, std::time::Duration::from_millis(1), None);
    let (client, bg) = io_loop.block_on(client).expect("client failed to connect");
    hickory_proto::spawn_bg(&io_loop, bg);

    test_timeout_query(client, io_loop);
}

#[test]
fn test_timeout_query_udp() {
    //env_logger::try_init().ok();
    let io_loop = Runtime::new().unwrap();

    // this is a test network, it should NOT be in use
    let addr: SocketAddr = ("203.0.113.0", 53)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let stream =
        UdpClientStream::<TokioUdpSocket>::with_timeout(addr, std::time::Duration::from_millis(1));
    let client = AsyncClient::connect(stream);
    let (client, bg) = io_loop.block_on(client).expect("client failed to connect");
    hickory_proto::spawn_bg(&io_loop, bg);

    test_timeout_query(client, io_loop);
}

#[test]
fn test_timeout_query_tcp() {
    //env_logger::try_init().ok();
    let io_loop = Runtime::new().unwrap();

    // this is a test network, it should NOT be in use
    let addr: SocketAddr = ("203.0.113.0", 53)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::with_timeout(
        addr,
        std::time::Duration::from_millis(1),
    );
    let client = AsyncClient::with_timeout(
        Box::new(stream),
        sender,
        std::time::Duration::from_millis(1),
        None,
    );

    assert!(io_loop.block_on(client).is_err());
}
