use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    sync::{Arc, Mutex as StdMutex},
};

use futures::{Future, FutureExt, TryFutureExt};
use test_support::subscribe;
#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
use time::Duration;

use hickory_client::client::{Client, ClientHandle};
use hickory_integration::{
    GOOGLE_V4, GOOGLE_V6, NeverReturnsClientStream, TEST3_V4, TestClientStream,
    example_authority::create_example,
};
use hickory_proto::{
    DnsHandle, ProtoErrorKind,
    op::{Edns, Message, Query, ResponseCode},
    rr::{
        DNSClass, Name, RecordSet, RecordType,
        rdata::opt::{EdnsCode, EdnsOption},
    },
    runtime::TokioRuntimeProvider,
    tcp::TcpClientStream,
    udp::UdpClientStream,
    xfer::{DnsRequest, FirstAnswer},
};
#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
use hickory_proto::{
    dnssec::{Algorithm, SigSigner, SigningKey, crypto::RsaSigningKey, rdata::DNSSECRData},
    rr::{RData, Record, rdata::A},
    runtime::TokioTime,
    xfer::{DnsExchangeBackground, DnsMultiplexer},
};
#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
use hickory_server::authority::AxfrPolicy;
use hickory_server::authority::{Authority, Catalog};

#[tokio::test]
async fn test_query_nonet() {
    subscribe();

    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), vec![Arc::new(authority)]);

    let (stream, sender) = TestClientStream::new(Arc::new(StdMutex::new(catalog)));
    let client = Client::new(stream, sender, None);
    let (mut client, bg) = client.await.expect("client failed to connect");
    tokio::spawn(bg);

    test_query(&mut client).await;
    test_query(&mut client).await;
}

#[tokio::test]
async fn test_query_udp_ipv4() {
    subscribe();
    let stream = UdpClientStream::builder(GOOGLE_V4, TokioRuntimeProvider::new()).build();
    let client = Client::connect(stream);
    let (mut client, bg) = client.await.expect("client failed to connect");
    tokio::spawn(bg);

    // TODO: timeouts on these requests so that the test doesn't hang
    test_query(&mut client).await;
    test_query(&mut client).await;
    test_query_edns(&mut client).await;
}

#[tokio::test]
#[ignore]
async fn test_query_udp_ipv6() {
    subscribe();
    let stream = UdpClientStream::builder(GOOGLE_V6, TokioRuntimeProvider::new()).build();
    let client = Client::connect(stream);
    let (mut client, bg) = client.await.expect("client failed to connect");
    tokio::spawn(bg);

    // TODO: timeouts on these requests so that the test doesn't hang
    test_query(&mut client).await;
    test_query(&mut client).await;
    test_query_edns(&mut client).await;
}

#[tokio::test]
async fn test_query_tcp_ipv4() {
    subscribe();
    let (stream, sender) = TcpClientStream::new(GOOGLE_V4, None, None, TokioRuntimeProvider::new());
    let client = Client::new(stream, sender, None);
    let (mut client, bg) = client.await.expect("client failed to connect");
    tokio::spawn(bg);

    // TODO: timeouts on these requests so that the test doesn't hang
    test_query(&mut client).await;
    test_query(&mut client).await;
}

#[tokio::test]
#[ignore]
async fn test_query_tcp_ipv6() {
    subscribe();
    let (stream, sender) = TcpClientStream::new(GOOGLE_V6, None, None, TokioRuntimeProvider::new());
    let client = Client::new(stream, sender, None);
    let (mut client, bg) = client.await.expect("client failed to connect");
    tokio::spawn(bg);

    // TODO: timeouts on these requests so that the test doesn't hang
    test_query(&mut client).await;
    test_query(&mut client).await;
}

#[tokio::test]
#[cfg(feature = "__https")]
async fn test_query_https() {
    use hickory_integration::CLOUDFLARE_V4_TLS;
    use hickory_proto::h2::HttpsClientStreamBuilder;
    use hickory_proto::rustls::default_provider;
    use rustls::{ClientConfig, RootCertStore};

    const ALPN_H2: &[u8] = b"h2";

    subscribe();

    // using the mozilla default root store
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut client_config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_config.alpn_protocols.push(ALPN_H2.to_vec());

    let https_builder = HttpsClientStreamBuilder::with_client_config(
        Arc::new(client_config),
        TokioRuntimeProvider::new(),
    );
    let client = Client::connect(https_builder.build(
        CLOUDFLARE_V4_TLS,
        Arc::from("cloudflare-dns.com"),
        Arc::from("/dns-query"),
    ));
    let (mut client, bg) = client.await.expect("client failed to connect");
    tokio::spawn(bg);

    // TODO: timeouts on these requests so that the test doesn't hang
    test_query(&mut client).await;
    test_query(&mut client).await;
}

fn test_query(client: &mut Client) -> impl Future<Output = ()> {
    let name = Name::from_ascii("WWW.example.com.").unwrap();

    client
        .query(name.clone(), DNSClass::IN, RecordType::A)
        .map_ok(move |response| {
            println!("response records: {response:?}");
            assert!(
                response
                    .queries()
                    .first()
                    .expect("expected query")
                    .name()
                    .eq_case(&name)
            );

            assert!(!response.answers().is_empty());
        })
        .map(|r: Result<_, _>| r.expect("query failed"))
}

fn test_query_edns(client: &mut Client) -> impl Future<Output = ()> {
    let name = Name::from_ascii("WWW.example.com.").unwrap();
    let mut edns = Edns::new();
    // garbage subnet value, but lets check
    edns.options_mut()
        .insert(EdnsOption::Subnet("1.2.0.0/16".parse().unwrap()));

    // TODO: write builder
    let mut msg = Message::query();
    msg.add_query({
        let mut query = Query::query(name.clone(), RecordType::A);
        query.set_query_class(DNSClass::IN);
        query
    })
    .set_recursion_desired(true)
    .set_edns(edns)
    .extensions_mut()
    .as_mut()
    .map(|edns| edns.set_max_payload(1232).set_version(0));

    client
        .send(DnsRequest::from(msg))
        .first_answer()
        .map_ok(move |response| {
            println!("response records: {response:?}");
            assert!(
                response
                    .queries()
                    .first()
                    .expect("expected query")
                    .name()
                    .eq_case(&name)
            );

            assert!(!response.answers().is_empty());
            assert!(response.extensions().is_some());
            let subnet_option = response
                .extensions()
                .as_ref()
                .unwrap()
                .option(EdnsCode::Subnet)
                .unwrap();
            let EdnsOption::Subnet(client_subnet) = subnet_option else {
                panic!("incorrect option type: {subnet_option:?}");
            };
            assert_eq!(client_subnet.addr(), IpAddr::V4(Ipv4Addr::new(1, 2, 0, 0)));
            assert_eq!(client_subnet.source_prefix(), 16);
            // ignore scope_prefix
        })
        .map(|r: Result<_, _>| r.expect("query failed"))
}

#[tokio::test]
async fn test_notify() {
    subscribe();
    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), vec![Arc::new(authority)]);

    let (stream, sender) = TestClientStream::new(Arc::new(StdMutex::new(catalog)));
    let client = Client::new(stream, sender, None);
    let (mut client, bg) = client.await.expect("client failed to connect");
    tokio::spawn(bg);

    let name = Name::from_str("ping.example.com.").unwrap();

    let message = client
        .notify(name, DNSClass::IN, RecordType::A, None::<RecordSet>)
        .await;
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
#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
async fn create_sig0_ready_client() -> (
    (
        Client,
        DnsExchangeBackground<DnsMultiplexer<TestClientStream>, TokioTime>,
    ),
    Name,
) {
    use hickory_proto::dnssec::rdata::KEY;
    use hickory_server::store::sqlite::SqliteAuthority;
    use rustls_pki_types::PrivatePkcs8KeyDer;

    let authority = create_example();
    let mut authority = SqliteAuthority::new(authority, AxfrPolicy::Deny, true, false);
    let origin = authority.origin().clone();

    let trusted_name = Name::from_str("trusted.example.com.").unwrap();

    const KEY: &[u8] = include_bytes!("../rsa-2048.pk8");
    let key =
        RsaSigningKey::from_pkcs8(&PrivatePkcs8KeyDer::from(KEY), Algorithm::RSASHA256).unwrap();
    let pub_key = key.to_public_key().unwrap();
    let sig0_key = KEY::new_sig0key(&pub_key);

    let signer = SigSigner::sig0(sig0_key.clone(), Box::new(key), trusted_name.clone());

    // insert the KEY for the trusted.example.com
    let auth_key = Record::from_rdata(
        trusted_name,
        Duration::minutes(5).whole_seconds() as u32,
        RData::DNSSEC(DNSSECRData::KEY(sig0_key)),
    );
    authority.upsert_mut(auth_key, 0);

    // setup the catalog
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), vec![Arc::new(authority)]);

    let signer = Arc::new(signer);
    let (stream, sender) = TestClientStream::new(Arc::new(StdMutex::new(catalog)));
    let client = Client::new(stream, sender, Some(signer))
        .await
        .expect("failed to get new Client");

    (client, origin.into())
}

#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
#[tokio::test]
async fn test_create() {
    subscribe();
    let ((mut client, bg), origin) = create_sig0_ready_client().await;
    tokio::spawn(bg);

    // create a record
    let record = Record::from_rdata(
        Name::from_str("new.example.com.").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    let result = client
        .create(record.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    let result = client
        .query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        )
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // trying to create again should error
    // TODO: it would be cool to make this
    let result = client
        .create(record.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);

    // will fail if already set and not the same value.
    let mut record = record;
    record.set_data(RData::A(A::new(101, 11, 101, 11)));

    let result = client.create(record, origin).await.expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);
}

#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
#[tokio::test]
async fn test_create_multi() {
    subscribe();
    let ((mut client, bg), origin) = create_sig0_ready_client().await;
    tokio::spawn(bg);

    // create a record
    let record = Record::from_rdata(
        Name::from_str("new.example.com.").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    let mut record2 = record.clone();
    record2.set_data(RData::A(A::new(100, 10, 100, 11)));
    let record2 = record2;

    let mut rrset = RecordSet::from(record.clone());
    rrset.insert(record2.clone(), 0);
    let rrset = rrset;

    let result = client
        .create(rrset.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    let result = client
        .query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        )
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);

    assert!(result.answers().contains(&record));
    assert!(result.answers().contains(&record2));

    // trying to create again should error
    // TODO: it would be cool to make this
    let result = client
        .create(rrset, origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);

    // will fail if already set and not the same value.
    let mut record = record;
    record.set_data(RData::A(A::new(101, 11, 101, 12)));

    let result = client.create(record, origin).await.expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);
}

#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
#[tokio::test]
async fn test_append() {
    subscribe();
    let ((mut client, bg), origin) = create_sig0_ready_client().await;
    tokio::spawn(bg);

    // append a record
    let record = Record::from_rdata(
        Name::from_str("new.example.com.").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    // first check the must_exist option
    let result = client
        .append(record.clone(), origin.clone(), true)
        .await
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    // next append to a non-existent RRset
    let result = client
        .append(record.clone(), origin.clone(), false)
        .await
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = client
        .query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        )
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // will fail if already set and not the same value.
    let mut record2 = record.clone();
    record2.set_data(RData::A(A::new(101, 11, 101, 11)));
    let record2 = record2;

    let result = client
        .append(record2.clone(), origin.clone(), true)
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        )
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);

    assert!(result.answers().contains(&record));
    assert!(result.answers().contains(&record2));

    // show that appending the same thing again is ok, but doesn't add any records
    let result = client
        .append(record.clone(), origin, true)
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        )
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);
}

#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
#[tokio::test]
async fn test_append_multi() {
    subscribe();
    let ((mut client, bg), origin) = create_sig0_ready_client().await;
    tokio::spawn(bg);

    // append a record
    let record = Record::from_rdata(
        Name::from_str("new.example.com.").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    // first check the must_exist option
    let result = client
        .append(record.clone(), origin.clone(), true)
        .await
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    // next append to a non-existent RRset
    let result = client
        .append(record.clone(), origin.clone(), false)
        .await
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = client
        .query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        )
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // will fail if already set and not the same value.
    let mut record2 = record.clone();
    record2.set_data(RData::A(A::new(101, 11, 101, 11)));
    let mut record3 = record.clone();
    record3.set_data(RData::A(A::new(101, 11, 101, 12)));

    // build the append set
    let mut rrset = RecordSet::from(record2.clone());
    rrset.insert(record3.clone(), 0);

    let result = client
        .append(rrset, origin.clone(), true)
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        )
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 3);

    assert!(result.answers().contains(&record));
    assert!(result.answers().contains(&record2));
    assert!(result.answers().contains(&record3));

    // show that appending the same thing again is ok, but doesn't add any records
    // TODO: technically this is a test for the Server, not client...
    let result = client
        .append(record.clone(), origin, true)
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        )
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 3);
}

#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
#[tokio::test]
async fn test_compare_and_swap() {
    subscribe();
    let ((mut client, bg), origin) = create_sig0_ready_client().await;
    tokio::spawn(bg);

    // create a record
    let record = Record::from_rdata(
        Name::from_str("new.example.com.").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    let result = client
        .create(record.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let current = record;
    let mut new = current.clone();
    new.set_data(RData::A(A::new(101, 11, 101, 11)));
    let new = new;

    let result = client
        .compare_and_swap(current.clone(), new.clone(), origin.clone())
        .await
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(new.name().clone(), new.dns_class(), new.record_type())
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result.answers().contains(&new));
    assert!(!result.answers().contains(&current));

    // check the it fails if tried again.
    let mut not = new.clone();
    not.set_data(RData::A(A::new(102, 12, 102, 12)));
    let not = not;

    let result = client
        .compare_and_swap(current, not.clone(), origin)
        .await
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    let result = client
        .query(new.name().clone(), new.dns_class(), new.record_type())
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result.answers().contains(&new));
    assert!(!result.answers().contains(&not));
}

#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
#[tokio::test]
async fn test_compare_and_swap_multi() {
    subscribe();
    let ((mut client, bg), origin) = create_sig0_ready_client().await;
    tokio::spawn(bg);

    // create a record
    let mut current = RecordSet::with_ttl(
        Name::from_str("new.example.com.").unwrap(),
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

    let result = client
        .create(current.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let mut new = RecordSet::with_ttl(current.name().clone(), current.record_type(), current.ttl());
    let new1 = new.new_record(&RData::A(A::new(100, 10, 101, 10))).clone();
    let new2 = new.new_record(&RData::A(A::new(100, 10, 101, 11))).clone();
    let new = new;

    let result = client
        .compare_and_swap(current.clone(), new.clone(), origin.clone())
        .await
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(new.name().clone(), new.dns_class(), new.record_type())
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);
    assert!(result.answers().contains(&new1));
    assert!(result.answers().contains(&new2));
    assert!(!result.answers().contains(&current1));
    assert!(!result.answers().contains(&current2));

    // check the it fails if tried again.
    let mut not = new1.clone();
    not.set_data(RData::A(A::new(102, 12, 102, 12)));
    let not = not;

    let result = client
        .compare_and_swap(current, not.clone(), origin)
        .await
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    let result = client
        .query(new.name().clone(), new.dns_class(), new.record_type())
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);
    assert!(result.answers().contains(&new1));
    assert!(!result.answers().contains(&not));
}

#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
#[tokio::test]
async fn test_delete_by_rdata() {
    subscribe();
    let ((mut client, bg), origin) = create_sig0_ready_client().await;
    tokio::spawn(bg);

    // append a record
    let record1 = Record::from_rdata(
        Name::from_str("new.example.com.").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    // first check the must_exist option
    let result = client
        .delete_by_rdata(record1.clone(), origin.clone())
        .await
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = client
        .create(record1.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let mut record2 = record1.clone();
    record2.set_data(RData::A(A::new(101, 11, 101, 11)));
    let result = client
        .append(record2.clone(), origin.clone(), true)
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = client
        .delete_by_rdata(record2, origin)
        .await
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(
            record1.name().clone(),
            record1.dns_class(),
            record1.record_type(),
        )
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result.answers().contains(&record1));
}

#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
#[tokio::test]
async fn test_delete_by_rdata_multi() {
    subscribe();
    let ((mut client, bg), origin) = create_sig0_ready_client().await;
    tokio::spawn(bg);

    // append a record
    let mut rrset = RecordSet::with_ttl(
        Name::from_str("new.example.com.").unwrap(),
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
    let result = client
        .delete_by_rdata(rrset.clone(), origin.clone())
        .await
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = client
        .create(rrset, origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // append a record
    let mut rrset = RecordSet::with_ttl(
        Name::from_str("new.example.com.").unwrap(),
        RecordType::A,
        Duration::minutes(5).whole_seconds() as u32,
    );

    let record1 = rrset.new_record(record1.data()).clone();
    let record3 = rrset.new_record(record3.data()).clone();
    let rrset = rrset;

    let result = client
        .append(rrset.clone(), origin.clone(), true)
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = client
        .delete_by_rdata(rrset, origin)
        .await
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(
            record1.name().clone(),
            record1.dns_class(),
            record1.record_type(),
        )
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);
    assert!(!result.answers().contains(&record1));
    assert!(result.answers().contains(&record2));
    assert!(!result.answers().contains(&record3));
    assert!(result.answers().contains(&record4));
}

#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
#[tokio::test]
async fn test_delete_rrset() {
    subscribe();
    let ((mut client, bg), origin) = create_sig0_ready_client().await;
    tokio::spawn(bg);

    // append a record
    let mut record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    // first check the must_exist option
    let result = client
        .delete_rrset(record.clone(), origin.clone())
        .await
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = client
        .create(record.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    record.set_data(RData::A(A::new(101, 11, 101, 11)));
    let result = client
        .append(record.clone(), origin.clone(), true)
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = client
        .delete_rrset(record.clone(), origin)
        .await
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        )
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);
}

#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
#[tokio::test]
async fn test_delete_all() {
    use hickory_proto::rr::rdata::AAAA;

    subscribe();

    let ((mut client, bg), origin) = create_sig0_ready_client().await;
    tokio::spawn(bg);

    // append a record
    let mut record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    // first check the must_exist option
    let result = client
        .delete_all(record.name().clone(), origin.clone(), DNSClass::IN)
        .await
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = client
        .create(record.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    record.set_data(RData::AAAA(AAAA::new(1, 2, 3, 4, 5, 6, 7, 8)));
    let result = client
        .create(record.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = client
        .delete_all(record.name().clone(), origin, DNSClass::IN)
        .await
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(record.name().clone(), record.dns_class(), RecordType::A)
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);

    let result = client
        .query(record.name().clone(), record.dns_class(), RecordType::AAAA)
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);
}

async fn test_timeout_query(mut client: Client) {
    let name = Name::from_str("www.example.com").unwrap();

    let err = client
        .query(name.clone(), DNSClass::IN, RecordType::A)
        .await
        .unwrap_err();

    println!("got error: {err:?}");
    if let ProtoErrorKind::Timeout = err.kind() {
    } else {
        panic!("expected timeout error");
    }

    client
        .query(name, DNSClass::IN, RecordType::AAAA)
        .await
        .unwrap_err();

    // test that we don't have any thing funky with registering new timeouts, etc...
    //   it would be cool if we could maintain a different error here, but shutdown is probably ok.
    //
    // match err.kind() {
    //     &ClientErrorKind::Timeout => (),
    //     e @ _ => assert!(false, format!("something else: {}", e)),
    // }
}

#[tokio::test]
async fn test_timeout_query_nonet() {
    subscribe();
    let (stream, sender) = NeverReturnsClientStream::new();
    let client = Client::with_timeout(stream, sender, std::time::Duration::from_millis(1), None);
    let (client, bg) = client.await.expect("client failed to connect");
    tokio::spawn(bg);

    test_timeout_query(client).await;
}

#[tokio::test]
async fn test_timeout_query_udp() {
    subscribe();
    let stream = UdpClientStream::builder(TEST3_V4, TokioRuntimeProvider::new())
        .with_timeout(Some(std::time::Duration::from_millis(1)))
        .build();

    let client = Client::connect(stream);
    let (client, bg) = client.await.expect("client failed to connect");
    tokio::spawn(bg);

    test_timeout_query(client).await;
}

#[tokio::test]
async fn test_timeout_query_tcp() {
    subscribe();

    let (stream, sender) = TcpClientStream::new(
        TEST3_V4,
        None,
        Some(std::time::Duration::from_millis(1)),
        TokioRuntimeProvider::new(),
    );
    let client = Client::with_timeout(
        Box::new(stream),
        sender,
        std::time::Duration::from_millis(1),
        None,
    );

    assert!(client.await.is_err());
}
