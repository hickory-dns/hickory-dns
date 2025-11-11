#![cfg(feature = "__dnssec")]

//! These tests confirm that NSEC3 validation fails when omitting any required NSEC3 record from
//! responses.

use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::Duration,
};

use hickory_client::client::ClientHandle;
use hickory_integration::{
    generate_key,
    mock_request_handler::{MockHandler, fetch_dnskey},
    print_response, setup_dnssec_client_server,
};
use hickory_proto::{
    DnsError, ProtoErrorKind,
    dnssec::{
        Algorithm, DigestType, Nsec3HashAlgorithm, Proof, SigSigner, SigningKey,
        crypto::Ed25519SigningKey,
        rdata::{DNSKEY, DNSSECRData, DS},
    },
    op::{DnsResponse, ResponseCode},
    rr::{
        DNSClass, RData, Record, RecordType,
        rdata::{A, AAAA, HINFO, MX, NS, SOA},
    },
};
use hickory_resolver::Name;
use hickory_server::{
    dnssec::NxProofKind,
    store::in_memory::InMemoryZoneHandler,
    zone_handler::{AxfrPolicy, Catalog, ZoneType},
};
use test_support::{LogWriter, subscribe};
use tracing::Dispatch;
use tracing_subscriber::layer::SubscriberExt;

/// Based on RFC 5155 section B.1.
#[tokio::test]
async fn name_error() {
    subscribe();

    let (key, public_key) = generate_key();
    let catalog = example_zone_catalog(key);
    let (mut client, _honest_server) = setup_dnssec_client_server(catalog, &public_key).await;

    let query_name = Name::parse("a.c.x.w.example.", None).unwrap();
    let query_type = RecordType::A;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NXDomain);

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Covers "next closer" name.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
    )
    .await;

    // Matches closest encloser.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "b4um86eghhds6nea196smvmlo4ors995",
    )
    .await;

    // Covers wildcard at closest encloser.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "35mthgpgcu1qg68fab165klnsnk3dpvl",
    )
    .await;
}

/// Based on RFC 5155 section B.2.
#[tokio::test]
async fn no_data_error() {
    subscribe();

    let (key, public_key) = generate_key();
    let catalog = example_zone_catalog(key);
    let (mut client, _honest_server) = setup_dnssec_client_server(catalog, &public_key).await;

    let query_name = Name::parse("ns1.example.", None).unwrap();
    let query_type = RecordType::MX;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answers().is_empty());

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Matches query.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
    )
    .await;
}

/// Based on RFC 5155 section B.2.1.
#[tokio::test]
async fn no_data_error_empty_non_terminal() {
    subscribe();

    let (key, public_key) = generate_key();
    let catalog = example_zone_catalog(key);
    let (mut client, _honest_server) = setup_dnssec_client_server(catalog, &public_key).await;

    let query_name = Name::parse("y.w.example.", None).unwrap();
    let query_type = RecordType::A;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answers().is_empty());

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Matches query.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "ji6neoaepv8b5o6k4ev33abha8ht9fgc",
    )
    .await;
}

/// Based on RFC 5155 section B.3.
#[ignore = "zone handler returns an NXDOMAIN for mc.c.example. instead of a referral to nameservers for c.example."]
#[tokio::test]
async fn referral_opt_out_unsigned() {
    subscribe();

    let (key, public_key) = generate_key();
    let catalog = example_zone_catalog(key);
    let (mut client, _honest_server) = setup_dnssec_client_server(catalog, &public_key).await;

    let query_name = Name::parse("mc.c.example.", None).unwrap();
    let query_type = RecordType::MX;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert_eq!(response.answer_count(), 0);
    assert!(
        response
            .authorities()
            .iter()
            .any(|record| record.record_type().is_ns())
    );

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Covers "next closer" name.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "35mthgpgcu1qg68fab165klnsnk3dpvl",
    )
    .await;

    // Matches closest encloser.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
    )
    .await;
}

/// Based on RFC 5155 section B.4.
#[tokio::test]
async fn wildcard_expansion() {
    subscribe();

    let (key, public_key) = generate_key();
    let catalog = example_zone_catalog(key);
    let (mut client, _honest_server) = setup_dnssec_client_server(catalog, &public_key).await;

    let query_name = Name::parse("a.z.w.example.", None).unwrap();
    let query_type = RecordType::MX;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answer_count() > 0);

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Covers "next closer" name.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "q04jkcevqvmu85r014c7dkba38o0ji5r",
    )
    .await;
}

/// Based on RFC 5155 section B.5.
#[ignore = "validation fails for one NSEC3 record's signature"]
#[tokio::test]
async fn wildcard_no_data_error() {
    subscribe();

    let (key, public_key) = generate_key();
    let catalog = example_zone_catalog(key);
    let (mut client, _honest_server) = setup_dnssec_client_server(catalog, &public_key).await;

    let query_name = Name::parse("a.z.w.example.", None).unwrap();
    let query_type = RecordType::AAAA;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answers().is_empty());

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Matches closest encloser.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "k8udemvp1j2f7eg6jebps17vp3n8i58h",
    )
    .await;

    // Covers "next closer" name.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "q04jkcevqvmu85r014c7dkba38o0ji5r",
    )
    .await;

    // Matches wildcard at closest encloser.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "r53bq7cc2uvmubfu5ocmm6pers9tk9en",
    )
    .await;
}

/// Based on RFC 5155 section B.6.
#[tokio::test]
async fn ds_child_zone_no_data_error() {
    subscribe();

    let (key, public_key) = generate_key();
    let catalog = example_zone_catalog(key);
    let (mut client, _honest_server) = setup_dnssec_client_server(catalog, &public_key).await;

    let query_name = Name::parse("example.", None).unwrap();
    let query_type = RecordType::DS;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answers().is_empty());

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Matches query.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
    )
    .await;
}

/// Regression test.  Given a response with missing NSEC3 records, Hickory would re-query the
/// missing records until the DNSSEC depth counter stopped the lookup chain.
#[tokio::test]
async fn validation_loop_test() {
    subscribe();

    let logs = LogWriter(Arc::new(Mutex::new(Vec::new())));
    let logs_clone = logs.clone();

    let writer = move || logs_clone.clone();

    let layer = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .with_ansi(false);

    let subscriber = tracing_subscriber::registry().with(layer);
    let dispatch = Dispatch::new(subscriber);

    let _guard = tracing::dispatcher::set_default(&dispatch);

    let (key, public_key) = generate_key();
    let catalog = example_zone_catalog(key);
    let (mut client, _honest_server) = setup_dnssec_client_server(catalog, &public_key).await;

    let query_name = Name::parse("a.c.x.w.example.", None).unwrap();
    let query_type = RecordType::A;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NXDomain);

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Exclude "next closer" name.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
    )
    .await;

    assert!(logs.contains(
        "stopping verification cycle in verify_default_rrset query_name=example. query_type=DNSKEY"
    ));
}

/// Modifies a response to remove a specific NSEC3 record, and confirms that the validating client
/// treats the response as bogus.
async fn test_exclude_nsec3(
    query_name: &Name,
    query_type: RecordType,
    original_response: &DnsResponse,
    dnskey_response: &DnsResponse,
    nsec3_owner_name: &str,
) {
    let zone = Name::parse("example.", None).unwrap();
    let nsec3_name = Name::parse(nsec3_owner_name, Some(&zone)).unwrap();

    let mut modified_response = original_response.clone();
    modified_response
        .authorities_mut()
        .retain(|record| record.name() != &nsec3_name);
    let new_count = modified_response.authorities().len().try_into().unwrap();
    modified_response.set_authority_count(new_count);
    assert!(
        modified_response.authorities().len() < original_response.authorities().len(),
        "failed to remove expected NSEC3 record and signature at {nsec3_owner_name}: {modified_response:?}"
    );

    let public_key = dnskey_response.answers()[0]
        .data()
        .as_dnssec()
        .unwrap()
        .as_dnskey()
        .unwrap()
        .public_key();

    let mock = MockHandler::new(
        query_name.into(),
        query_type,
        modified_response,
        dnskey_response.clone(),
    );
    let (mut client, _mock_server) = setup_dnssec_client_server(mock, public_key).await;

    let error = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap_err();
    let ProtoErrorKind::Dns(DnsError::Nsec { proof, .. }) = error.kind() else {
        panic!("wrong proto error kind {error}");
    };
    assert_eq!(proof, &Proof::Bogus);
}

/// Constructs a catalog based on the zone file described in RFC 5155 Appendix A.
fn example_zone_catalog(key: Box<dyn SigningKey>) -> Catalog {
    let origin = Name::parse("example.", None).unwrap();

    let handler = example_zone_handler(origin.clone(), key);

    let mut catalog = Catalog::new();
    catalog.upsert(origin.into(), vec![Arc::new(handler)]);
    catalog
}

/// Constructs a zone handler based on the zone file described in RFC 5155 Appendix A.
fn example_zone_handler(origin: Name, key: Box<dyn SigningKey>) -> InMemoryZoneHandler {
    let mut handler = InMemoryZoneHandler::empty(
        origin.clone(),
        ZoneType::Primary,
        AxfrPolicy::Deny,
        Some(NxProofKind::Nsec3 {
            algorithm: Nsec3HashAlgorithm::SHA1,
            salt: data_encoding::HEXLOWER_PERMISSIVE
                .decode(b"aabbccdd")
                .unwrap()
                .into(),
            iterations: 12,
            opt_out: true,
        }),
    );

    // Note that the serial will be incremented from 0 to 1 by `secure_zone_mut()`.
    handler.upsert_mut(
        Record::from_rdata(
            origin.clone(),
            3600,
            RData::SOA(SOA::new(
                Name::parse("ns1", Some(&origin)).unwrap(),
                Name::parse("bugs.x.w", Some(&origin)).unwrap(),
                0,
                3600,
                300,
                3600000,
                3600,
            )),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            origin.clone(),
            3600,
            RData::NS(NS(Name::parse("ns1", Some(&origin)).unwrap())),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            origin.clone(),
            3600,
            RData::NS(NS(Name::parse("ns2", Some(&origin)).unwrap())),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            origin.clone(),
            3600,
            RData::MX(MX::new(1, Name::parse("xx", Some(&origin)).unwrap())),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("2t7b4g4vsa5smi47k61mv5bv1a22bojr", Some(&origin)).unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 127))),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("a", Some(&origin)).unwrap(),
            3600,
            RData::NS(NS(Name::parse("ns1.a", Some(&origin)).unwrap())),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("a", Some(&origin)).unwrap(),
            3600,
            RData::NS(NS(Name::parse("ns2.a", Some(&origin)).unwrap())),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("a", Some(&origin)).unwrap(),
            3600,
            RData::DNSSEC(DNSSECRData::DS(DS::new(
                58470,
                #[allow(deprecated)]
                Algorithm::RSASHA1,
                #[allow(deprecated)]
                DigestType::SHA1,
                data_encoding::HEXUPPER_PERMISSIVE
                    .decode(b"3079F1593EBAD6DC121E202A8B766A6A4837206C")
                    .unwrap(),
            ))),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("ns1.a", Some(&origin)).unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 5))),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("ns2.a", Some(&origin)).unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 6))),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("ai", Some(&origin)).unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 9))),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("ai", Some(&origin)).unwrap(),
            3600,
            RData::HINFO(HINFO::new("KLH-10".to_owned(), "ITS".to_owned())),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("ai", Some(&origin)).unwrap(),
            3600,
            RData::AAAA(AAAA(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0xf00, 0xbaa9,
            ))),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("c", Some(&origin)).unwrap(),
            3600,
            RData::NS(NS(Name::parse("ns1.c", Some(&origin)).unwrap())),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("c", Some(&origin)).unwrap(),
            3600,
            RData::NS(NS(Name::parse("ns2.c", Some(&origin)).unwrap())),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("ns1.c", Some(&origin)).unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 7))),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("ns2.c", Some(&origin)).unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 8))),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("ns1", Some(&origin)).unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("ns2", Some(&origin)).unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 2))),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("*.w", Some(&origin)).unwrap(),
            3600,
            RData::MX(MX::new(1, Name::parse("ai", Some(&origin)).unwrap())),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("x.w", Some(&origin)).unwrap(),
            3600,
            RData::MX(MX::new(1, Name::parse("xx", Some(&origin)).unwrap())),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("x.y.w", Some(&origin)).unwrap(),
            3600,
            RData::MX(MX::new(1, Name::parse("xx", Some(&origin)).unwrap())),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("xx", Some(&origin)).unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 10))),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("xx", Some(&origin)).unwrap(),
            3600,
            RData::HINFO(HINFO::new("KLH-10".to_owned(), "TOPS-20".to_owned())),
        ),
        0,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("xx", Some(&origin)).unwrap(),
            3600,
            RData::AAAA(AAAA(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0xf00, 0xbaaa,
            ))),
        ),
        0,
    );

    // Add DNSKEY and sign zone
    handler
        .add_zone_signing_key_mut(SigSigner::dnssec(
            DNSKEY::from_key(&key.to_public_key().unwrap()),
            key,
            origin.clone(),
            Duration::from_secs(86400),
        ))
        .unwrap();
    handler.secure_zone_mut().unwrap();

    handler
}

/// Confirm that the generated NSEC3 chain matches the zone file from RFC 5155 Appendix A.
#[test]
fn example_zone_nsec3_chain() {
    let key = Ed25519SigningKey::from_pkcs8(&Ed25519SigningKey::generate_pkcs8().unwrap()).unwrap();
    let origin = Name::parse("example.", None).unwrap();
    let mut handler = example_zone_handler(origin.clone(), Box::new(key));

    let names = handler
        .records_get_mut()
        .keys()
        .map(|key| key.name.to_ascii())
        .collect::<HashSet<_>>();
    let expected = HashSet::from([
        "example.".to_owned(),
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.".to_owned(),
        "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.".to_owned(),
        "2vptu5timamqttgl4luu9kg21e0aor3s.example.".to_owned(),
        "35mthgpgcu1qg68fab165klnsnk3dpvl.example.".to_owned(),
        "a.example.".to_owned(),
        "ns1.a.example.".to_owned(),
        "ns2.a.example.".to_owned(),
        "ai.example.".to_owned(),
        "b4um86eghhds6nea196smvmlo4ors995.example.".to_owned(),
        "c.example.".to_owned(),
        "ns1.c.example.".to_owned(),
        "ns2.c.example.".to_owned(),
        "gjeqe526plbf1g8mklp59enfd789njgi.example.".to_owned(),
        "ji6neoaepv8b5o6k4ev33abha8ht9fgc.example.".to_owned(),
        "k8udemvp1j2f7eg6jebps17vp3n8i58h.example.".to_owned(),
        "kohar7mbb8dc2ce8a9qvl8hon4k53uhi.example.".to_owned(),
        "ns1.example.".to_owned(),
        "ns2.example.".to_owned(),
        "q04jkcevqvmu85r014c7dkba38o0ji5r.example.".to_owned(),
        "r53bq7cc2uvmubfu5ocmm6pers9tk9en.example.".to_owned(),
        "t644ebqk9bibcna874givr6joj62mlhv.example.".to_owned(),
        "*.w.example.".to_owned(),
        "x.w.example.".to_owned(),
        "x.y.w.example.".to_owned(),
        "xx.example.".to_owned(),
    ]);
    assert_eq!(names, expected);
}
