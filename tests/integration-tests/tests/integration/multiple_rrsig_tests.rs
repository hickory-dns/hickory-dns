#![cfg(feature = "__dnssec")]

//! These tests confirm that an RRset with more than one RRSIG validates if any one of them can be
//! verified, regardless of the order of the RRSIGs in the response.

use std::{sync::Arc, time::Duration};

use hickory_integration::{
    generate_key,
    mock_request_handler::{MockHandler, fetch_dnskey},
    print_response, setup_dnssec_client_server,
};
use hickory_net::client::ClientHandle;
use hickory_proto::{
    dnssec::{
        Algorithm, DnssecSigner, Proof, SigningKey,
        rdata::{DNSKEY, DNSSECRData, RRSIG},
    },
    op::{DnsResponse, ResponseCode},
    rr::{
        DNSClass, Name, RData, Record, RecordType,
        rdata::{A, NS, SOA},
    },
};
use hickory_server::{
    dnssec::NxProofKind,
    store::in_memory::InMemoryZoneHandler,
    zone_handler::{AxfrPolicy, Catalog, ZoneType},
};
use test_support::subscribe;

/// How to derive an RRSIG that can't be verified from a genuine one.
#[derive(Clone, Copy, Debug)]
enum BadRrsig {
    /// Algorithm not supported by hickory (ED448).
    UnsupportedAlgorithm,
    /// Key tag not present in the DNSKEY RRset.
    UnknownKeyTag,
    /// Signature does not match the RRset.
    CorruptSignature,
}

/// Position of the bad RRSIG relative to the genuine one.
#[derive(Clone, Copy, Debug)]
enum Position {
    Before,
    After,
}

#[tokio::test]
async fn unsupported_algorithm_rrsig_before_valid_rrsig() {
    test_extra_rrsig(BadRrsig::UnsupportedAlgorithm, Position::Before).await;
}

#[tokio::test]
async fn unsupported_algorithm_rrsig_after_valid_rrsig() {
    test_extra_rrsig(BadRrsig::UnsupportedAlgorithm, Position::After).await;
}

#[tokio::test]
async fn unknown_key_tag_rrsig_before_valid_rrsig() {
    test_extra_rrsig(BadRrsig::UnknownKeyTag, Position::Before).await;
}

#[tokio::test]
async fn unknown_key_tag_rrsig_after_valid_rrsig() {
    test_extra_rrsig(BadRrsig::UnknownKeyTag, Position::After).await;
}

#[tokio::test]
async fn corrupt_rrsig_before_valid_rrsig() {
    test_extra_rrsig(BadRrsig::CorruptSignature, Position::Before).await;
}

#[tokio::test]
async fn corrupt_rrsig_after_valid_rrsig() {
    test_extra_rrsig(BadRrsig::CorruptSignature, Position::After).await;
}

#[tokio::test]
async fn only_unverifiable_rrsigs() {
    subscribe();

    let (response, dnskey_response, genuine_rrsig) = honest_response().await;

    let mut modified_response = response.clone();
    modified_response
        .answers
        .retain(|record| record.record_type() != RecordType::RRSIG);
    modified_response.answers.push(derive_bad_rrsig(
        &genuine_rrsig,
        BadRrsig::UnsupportedAlgorithm,
    ));
    modified_response
        .answers
        .push(derive_bad_rrsig(&genuine_rrsig, BadRrsig::CorruptSignature));

    let response = query_mock(modified_response, dnskey_response).await;
    assert_proof(&response, Proof::Bogus);
}

async fn test_extra_rrsig(bad_rrsig: BadRrsig, position: Position) {
    subscribe();

    let (response, dnskey_response, genuine_rrsig) = honest_response().await;

    let mut modified_response = response.clone();
    let bad_rrsig = derive_bad_rrsig(&genuine_rrsig, bad_rrsig);
    let genuine_index = modified_response
        .answers
        .iter()
        .position(|record| record.record_type() == RecordType::RRSIG)
        .expect("genuine RRSIG not found in response");
    match position {
        Position::Before => modified_response.answers.insert(genuine_index, bad_rrsig),
        Position::After => modified_response
            .answers
            .insert(genuine_index + 1, bad_rrsig),
    }

    let response = query_mock(modified_response, dnskey_response).await;
    assert_proof(&response, Proof::Secure);
}

/// Queries the honest server for `www.example. IN A`, returning the response, the DNSKEY
/// response, and the RRSIG covering the A RRset.
async fn honest_response() -> (DnsResponse, DnsResponse, Record<RRSIG>) {
    let (key, public_key) = generate_key();
    let catalog = example_zone_catalog(key);
    let (mut client, _honest_server) =
        setup_dnssec_client_server(catalog, &public_key, zone_name().into()).await;

    let response = client
        .query(query_name(), DNSClass::IN, RecordType::A)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_proof(&response, Proof::Secure);

    let rrsigs = response
        .answers
        .iter()
        .filter_map(|record| {
            record.clone().map(|data| match data {
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => Some(rrsig),
                _ => None,
            })
        })
        .collect::<Vec<_>>();
    let [genuine_rrsig] = rrsigs.as_slice() else {
        panic!("expected exactly one RRSIG in the honest response: {rrsigs:?}");
    };

    let dnskey_response = fetch_dnskey(&mut client).await;
    (response, dnskey_response, genuine_rrsig.clone())
}

/// Serves `response` from a mock server and returns the validated response.
async fn query_mock(response: DnsResponse, dnskey_response: DnsResponse) -> DnsResponse {
    let RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) = &dnskey_response.answers[0].data else {
        panic!("expected DNSKEY in DNSKEY response: {dnskey_response:#?}");
    };

    let mock = MockHandler::new(
        query_name().into(),
        RecordType::A,
        response,
        dnskey_response.clone(),
    );
    let (mut client, _mock_server) =
        setup_dnssec_client_server(mock, dnskey.public_key(), zone_name().into()).await;

    let response = client
        .query(query_name(), DNSClass::IN, RecordType::A)
        .await
        .unwrap();
    print_response(&response);
    response
}

fn derive_bad_rrsig(genuine: &Record<RRSIG>, kind: BadRrsig) -> Record {
    let mut input = genuine.data.input().clone();
    let mut sig = genuine.data.sig().to_vec();
    match kind {
        BadRrsig::UnsupportedAlgorithm => input.algorithm = Algorithm::Unknown(16),
        BadRrsig::UnknownKeyTag => input.key_tag = input.key_tag.wrapping_add(1),
        BadRrsig::CorruptSignature => sig[0] = !sig[0],
    }

    Record::from_rdata(
        genuine.name.clone(),
        genuine.ttl,
        RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, sig))),
    )
}

fn assert_proof(response: &DnsResponse, expected: Proof) {
    let a_records = response
        .answers
        .iter()
        .filter(|record| record.record_type() == RecordType::A)
        .collect::<Vec<_>>();
    assert!(
        !a_records.is_empty(),
        "no A records in response: {response:#?}"
    );
    for record in a_records {
        assert_eq!(record.proof, expected, "unexpected proof for {record}");
    }
}

fn query_name() -> Name {
    Name::parse("www.example.", None).unwrap()
}

fn zone_name() -> Name {
    Name::parse("example.", None).unwrap()
}

/// Constructs a catalog with a minimal signed `example.` zone.
fn example_zone_catalog(key: Box<dyn SigningKey>) -> Catalog {
    let origin = zone_name();
    let mut handler: InMemoryZoneHandler = InMemoryZoneHandler::empty(
        origin.clone(),
        ZoneType::Primary,
        AxfrPolicy::Deny,
        Some(NxProofKind::Nsec),
    );

    const SERIAL: u32 = 1;
    const TTL: u32 = 3600;

    handler.upsert_mut(
        Record::from_rdata(
            origin.clone(),
            TTL,
            RData::SOA(SOA::new(
                Name::parse("ns1", Some(&origin)).unwrap(),
                Name::parse("hostmaster", Some(&origin)).unwrap(),
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
            Name::parse("ns1", Some(&origin)).unwrap(),
            TTL,
            RData::A(A::new(192, 0, 2, 1)),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("www", Some(&origin)).unwrap(),
            TTL,
            RData::A(A::new(192, 0, 2, 2)),
        ),
        SERIAL,
    );

    handler
        .add_zone_signing_key_mut(DnssecSigner::new(
            DNSKEY::from_key(&key.to_public_key().unwrap()),
            key,
            origin.clone(),
            Duration::from_secs(86400),
        ))
        .unwrap();
    handler.secure_zone_mut().unwrap();

    let mut catalog = Catalog::new();
    catalog.upsert(origin.into(), vec![Arc::new(handler)]);
    catalog
}
