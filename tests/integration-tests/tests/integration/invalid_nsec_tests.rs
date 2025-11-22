#![cfg(feature = "__dnssec")]

//! These tests confirm that NSEC validation fails when omitting any required NSEC record from
//! responses.

use std::{sync::Arc, time::Duration};

use hickory_client::client::ClientHandle;
use hickory_integration::{
    generate_key,
    mock_request_handler::{MockHandler, fetch_dnskey},
    print_response, setup_dnssec_client_server,
};
use hickory_proto::{
    DnsError, ProtoErrorKind,
    dnssec::{
        Algorithm, DigestType, Proof, SigSigner, SigningKey,
        crypto::Ed25519SigningKey,
        rdata::{DNSKEY, DNSSECRData, DS, NSEC},
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
use test_support::subscribe;

/// Based on RFC 4035 section B.2.
#[tokio::test]
async fn name_error() {
    subscribe();

    let (key, public_key) = generate_key();
    let catalog = example_zone_catalog(key);
    let (mut client, _honest_server) = setup_dnssec_client_server(catalog, &public_key).await;

    let query_name = Name::parse("ml.example.", None).unwrap();
    let query_type = RecordType::A;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NXDomain);

    let nsec_count = response
        .all_sections()
        .filter(|record| record.record_type() == RecordType::NSEC)
        .count();
    assert_eq!(nsec_count, 2);

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Proves name does not exist.
    test_exclude_nsec(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        Name::parse("b.example.", None).unwrap(),
    )
    .await;

    // Proves covering wildcard name does not exist.
    test_exclude_nsec(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        Name::parse("example.", None).unwrap(),
    )
    .await;
}

/// Based on RFC 4035 section B.3.
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

    let nsec_count = response
        .all_sections()
        .filter(|record| record.record_type() == RecordType::NSEC)
        .count();
    assert_eq!(nsec_count, 1);

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Proves the requested RR type does not exist.
    test_exclude_nsec(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        Name::parse("ns1.example.", None).unwrap(),
    )
    .await;
}

/// Based on RFC 4035 section B.6.
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

    let nsec_count = response
        .authorities()
        .iter()
        .filter(|record| record.record_type() == RecordType::NSEC)
        .count();
    assert_eq!(nsec_count, 1);

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Proves that no closer match exists.
    test_exclude_nsec(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        Name::parse("x.y.w.example.", None).unwrap(),
    )
    .await;
}

/// Based on RFC 4035 section B.7.
#[ignore = "Authoritative response uses wrong response code"]
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

    let nsec_count = response
        .all_sections()
        .filter(|record| record.record_type() == RecordType::NSEC)
        .count();
    assert_eq!(nsec_count, 2);

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Proves that the matching wildcard name does not have the requested RR type.
    test_exclude_nsec(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        Name::parse("x.y.w.example.", None).unwrap(),
    )
    .await;

    // Proves that no closer match exists.
    test_exclude_nsec(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        Name::parse("*.w.example.", None).unwrap(),
    )
    .await;
}

/// Based on RFC 4035 section B.8.
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

    let nsec_count = response
        .all_sections()
        .filter(|record| record.record_type() == RecordType::NSEC)
        .count();
    assert_eq!(nsec_count, 1);

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Proves the requested RR type does not exist.
    test_exclude_nsec(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        Name::parse("example.", None).unwrap(),
    )
    .await;
}

/// Modifies a response to remove a specific NSEC record, and confirms that the validating client
/// treats the response as bogus.
async fn test_exclude_nsec(
    query_name: &Name,
    query_type: RecordType,
    original_response: &DnsResponse,
    dnskey_response: &DnsResponse,
    nsec_owner_name: Name,
) {
    let mut modified_response = original_response.clone();
    modified_response.authorities_mut().retain(|record| {
        record.name() != &nsec_owner_name || record.record_type() != RecordType::NSEC
    });
    let new_count = modified_response.authorities().len().try_into().unwrap();
    modified_response.set_authority_count(new_count);
    assert!(
        modified_response.authorities().len() < original_response.authorities().len(),
        "failed to remove expected NSEC record at {nsec_owner_name}: {modified_response:?}"
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

/// Constructs a catalog based on the zone file described in RFC 4035 Appendix A.
fn example_zone_catalog(key: Box<dyn SigningKey>) -> Catalog {
    let origin = Name::parse("example.", None).unwrap();

    let handler = example_zone_handler(origin.clone(), key);

    let mut catalog = Catalog::new();
    catalog.upsert(origin.into(), vec![Arc::new(handler)]);
    catalog
}

/// Constructs a zone handler based on the zone file described in RFC 4035 Appendix A.
fn example_zone_handler(origin: Name, key: Box<dyn SigningKey>) -> InMemoryZoneHandler {
    let mut handler = InMemoryZoneHandler::empty(
        origin.clone(),
        ZoneType::Primary,
        AxfrPolicy::Deny,
        Some(NxProofKind::Nsec),
    );

    // Note that the serial will be incremented to 1081539377 by `secure_zone_mut()`.
    const SERIAL: u32 = 1081539376;
    const TTL: u32 = 3600;

    handler.upsert_mut(
        Record::from_rdata(
            origin.clone(),
            TTL,
            RData::SOA(SOA::new(
                Name::parse("ns1", Some(&origin)).unwrap(),
                Name::parse("bugs.x.w", Some(&origin)).unwrap(),
                SERIAL,
                3600,
                300,
                3600000,
                TTL,
            )),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            origin.clone(),
            TTL,
            RData::NS(NS(Name::parse("ns1", Some(&origin)).unwrap())),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            origin.clone(),
            3600,
            RData::NS(NS(Name::parse("ns2", Some(&origin)).unwrap())),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            origin.clone(),
            TTL,
            RData::MX(MX::new(1, Name::parse("xx", Some(&origin)).unwrap())),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("a", Some(&origin)).unwrap(),
            TTL,
            RData::NS(NS(Name::parse("ns1.a", Some(&origin)).unwrap())),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("a", Some(&origin)).unwrap(),
            TTL,
            RData::NS(NS(Name::parse("ns2.a", Some(&origin)).unwrap())),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("a", Some(&origin)).unwrap(),
            TTL,
            RData::DNSSEC(DNSSECRData::DS(DS::new(
                57855,
                #[allow(deprecated)]
                Algorithm::RSASHA1,
                DigestType::SHA1,
                data_encoding::HEXUPPER_PERMISSIVE
                    .decode(b"B6DCD485719ADCA18E5F3D48A2331627FDD3636B")
                    .unwrap(),
            ))),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("ns1.a", Some(&origin)).unwrap(),
            TTL,
            RData::A(A::new(192, 0, 2, 5)),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("ns2.a", Some(&origin)).unwrap(),
            TTL,
            RData::A(A::new(192, 0, 2, 6)),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("ai", Some(&origin)).unwrap(),
            TTL,
            RData::A(A::new(192, 0, 2, 9)),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("ai", Some(&origin)).unwrap(),
            TTL,
            RData::HINFO(HINFO::new("KLH-10".to_string(), "ITS".to_string())),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("ai", Some(&origin)).unwrap(),
            TTL,
            RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0xf00, 0xbaa9)),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("b", Some(&origin)).unwrap(),
            TTL,
            RData::NS(NS(Name::parse("ns1.b", Some(&origin)).unwrap())),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("b", Some(&origin)).unwrap(),
            TTL,
            RData::NS(NS(Name::parse("ns2.b", Some(&origin)).unwrap())),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("ns1.b", Some(&origin)).unwrap(),
            TTL,
            RData::A(A::new(192, 0, 2, 7)),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("ns2.b", Some(&origin)).unwrap(),
            TTL,
            RData::A(A::new(192, 0, 2, 8)),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("ns1", Some(&origin)).unwrap(),
            TTL,
            RData::A(A::new(192, 0, 2, 1)),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("ns2", Some(&origin)).unwrap(),
            TTL,
            RData::A(A::new(192, 0, 2, 2)),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("*.w", Some(&origin)).unwrap(),
            TTL,
            RData::MX(MX::new(1, Name::parse("ai", Some(&origin)).unwrap())),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("x.w", Some(&origin)).unwrap(),
            TTL,
            RData::MX(MX::new(1, Name::parse("xx", Some(&origin)).unwrap())),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("x.y.w", Some(&origin)).unwrap(),
            TTL,
            RData::MX(MX::new(1, Name::parse("xx", Some(&origin)).unwrap())),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("xx", Some(&origin)).unwrap(),
            TTL,
            RData::A(A::new(192, 0, 2, 10)),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("xx", Some(&origin)).unwrap(),
            TTL,
            RData::HINFO(HINFO::new("KLH-10".to_string(), "TOPS-20".to_string())),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("xx", Some(&origin)).unwrap(),
            TTL,
            RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0xf00, 0xbaaa)),
        ),
        SERIAL,
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

/// Confirm that the generated NSEC chain matches the zone file from RFC 4035 Appendix A.
#[test]
fn example_zone_nsec_chain() {
    let key = Ed25519SigningKey::from_pkcs8(&Ed25519SigningKey::generate_pkcs8().unwrap()).unwrap();
    let origin = Name::parse("example.", None).unwrap();
    let mut handler = example_zone_handler(origin.clone(), Box::new(key));

    let mut nsecs = handler
        .records_get_mut()
        .iter()
        .filter_map(|(key, records)| {
            if key.record_type != RecordType::NSEC {
                return None;
            }
            let mut iterator = records.records(false);
            let record = iterator.next().unwrap();
            assert_eq!(iterator.next(), None);
            Some((
                record.name().clone(),
                record
                    .data()
                    .as_dnssec()
                    .unwrap()
                    .as_nsec()
                    .unwrap()
                    .clone(),
            ))
        })
        .collect::<Vec<_>>();
    nsecs.sort_by(|(left_name, _), (right_name, _)| left_name.cmp(right_name));

    let mut expected_name = nsecs.last().unwrap().1.next_domain_name();
    for (name, nsec) in nsecs.iter() {
        assert_eq!(name, expected_name, "NSEC chain is not complete {nsecs:#?}");
        expected_name = nsec.next_domain_name();
    }

    let expected_nsecs = vec![
        (
            Name::parse("example.", None).unwrap(),
            NSEC::new(
                Name::parse("a.example.", None).unwrap(),
                vec![
                    RecordType::NS,
                    RecordType::SOA,
                    RecordType::MX,
                    RecordType::RRSIG,
                    RecordType::NSEC,
                    RecordType::DNSKEY,
                ],
            ),
        ),
        (
            Name::parse("a.example.", None).unwrap(),
            NSEC::new(
                Name::parse("ai.example.", None).unwrap(),
                vec![
                    RecordType::NS,
                    RecordType::DS,
                    RecordType::RRSIG,
                    RecordType::NSEC,
                ],
            ),
        ),
        (
            Name::parse("ai.example.", None).unwrap(),
            NSEC::new(
                Name::parse("b.example.", None).unwrap(),
                vec![
                    RecordType::A,
                    RecordType::HINFO,
                    RecordType::AAAA,
                    RecordType::RRSIG,
                    RecordType::NSEC,
                ],
            ),
        ),
        (
            Name::parse("b.example.", None).unwrap(),
            NSEC::new(
                Name::parse("ns1.example.", None).unwrap(),
                vec![RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
            ),
        ),
        (
            Name::parse("ns1.example.", None).unwrap(),
            NSEC::new(
                Name::parse("ns2.example.", None).unwrap(),
                vec![RecordType::A, RecordType::RRSIG, RecordType::NSEC],
            ),
        ),
        (
            Name::parse("ns2.example.", None).unwrap(),
            NSEC::new(
                Name::parse("*.w.example.", None).unwrap(),
                vec![RecordType::A, RecordType::RRSIG, RecordType::NSEC],
            ),
        ),
        (
            Name::parse("*.w.example.", None).unwrap(),
            NSEC::new(
                Name::parse("x.w.example.", None).unwrap(),
                vec![RecordType::MX, RecordType::RRSIG, RecordType::NSEC],
            ),
        ),
        (
            Name::parse("x.w.example.", None).unwrap(),
            NSEC::new(
                Name::parse("x.y.w.example.", None).unwrap(),
                vec![RecordType::MX, RecordType::RRSIG, RecordType::NSEC],
            ),
        ),
        (
            Name::parse("x.y.w.example.", None).unwrap(),
            NSEC::new(
                Name::parse("xx.example.", None).unwrap(),
                vec![RecordType::MX, RecordType::RRSIG, RecordType::NSEC],
            ),
        ),
        (
            Name::parse("xx.example.", None).unwrap(),
            NSEC::new(
                Name::parse("example.", None).unwrap(),
                vec![
                    RecordType::A,
                    RecordType::HINFO,
                    RecordType::AAAA,
                    RecordType::RRSIG,
                    RecordType::NSEC,
                ],
            ),
        ),
    ];

    pretty_assertions::assert_eq!(nsecs, expected_nsecs);
}
