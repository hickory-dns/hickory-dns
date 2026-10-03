//! Tests for [`DnssecDnsHandle`] against a mock upstream returning canned responses.

use core::mem;
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use futures_util::{
    future,
    stream::{self, Stream},
};
use time::OffsetDateTime;

use super::DnssecDnsHandle;
use crate::{
    error::NetError,
    proto::{
        dnssec::{
            DigestType, DnssecSigner, Proof, PublicKeyBuf, SigningKey, TrustAnchors,
            crypto::Ed25519SigningKey,
            rdata::{DNSKEY, DNSSECRData, DS, NSEC, RRSIG},
        },
        op::{DnsRequest, DnsRequestOptions, DnsResponse, Message, Query, ResponseCode},
        rr::{
            DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType,
            rdata::{A, NS, SOA},
        },
    },
    runtime::TokioRuntimeProvider,
    xfer::{DnsHandle, FirstAnswer},
};
use test_support::subscribe;

/// A server answering a DS query for an insecure zone with the child zone's own SOA record
/// (instead of the parent's) must not cause a validation loop, and the zone must be recognized
/// as insecure if its parent zone is insecure.
///
/// Regression test for <https://github.com/hickory-dns/hickory-dns/issues/3974>.
#[tokio::test]
async fn insecure_delegation_with_child_soa_in_ds_response() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Insecure);
    let child = Name::from_ascii("child.example.com.").unwrap();
    fixture.respond(&child, RecordType::DS, [], [unsigned_soa(&child)]);
    let (handle, queries) = fixture.build();

    let response = lookup_child_a(&handle).await.unwrap();
    assert_eq!(response.answers[0].proof, Proof::Insecure);
    assert_eq!(
        queries.count(&child, RecordType::DS),
        1,
        "the DS query for the child zone should only be sent once"
    );
}

/// A server answering a DS query for an insecure zone with an empty authority section must
/// still allow the zone to be recognized as insecure if its parent zone is insecure.
///
/// Regression test for <https://github.com/hickory-dns/hickory-dns/issues/3974>.
#[tokio::test]
async fn insecure_delegation_with_empty_ds_response() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Insecure);
    let child = Name::from_ascii("child.example.com.").unwrap();
    fixture.respond(&child, RecordType::DS, [], []);
    let (handle, _) = fixture.build();

    let response = lookup_child_a(&handle).await.unwrap();
    assert_eq!(response.answers[0].proof, Proof::Insecure);
}

/// The expected case: a DS query for an insecure zone is answered with the parent zone's SOA
/// record.
#[tokio::test]
async fn insecure_delegation_with_parent_soa_in_ds_response() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Insecure);
    let child = Name::from_ascii("child.example.com.").unwrap();
    let parent = Name::from_ascii("example.com.").unwrap();
    fixture.respond(&child, RecordType::DS, [], [unsigned_soa(&parent)]);
    let (handle, _) = fixture.build();

    let response = lookup_child_a(&handle).await.unwrap();
    assert_eq!(response.answers[0].proof, Proof::Insecure);
}

/// If the parent zone is secure, an unauthenticated DS response for the child zone must not be
/// accepted as proof of an insecure delegation, regardless of the SOA record it carries.
#[tokio::test]
async fn bogus_delegation_with_child_soa_in_ds_response() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Secure);
    let child = Name::from_ascii("child.example.com.").unwrap();
    fixture.respond(&child, RecordType::DS, [], [unsigned_soa(&child)]);
    let (handle, _) = fixture.build();

    let response = lookup_child_a(&handle).await.unwrap();
    assert_eq!(response.answers[0].proof, Proof::Bogus);
}

/// If the parent zone is secure, an empty DS response for the child zone must not be accepted
/// as proof of an insecure delegation.
#[tokio::test]
async fn bogus_delegation_with_empty_ds_response() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Secure);
    let child = Name::from_ascii("child.example.com.").unwrap();
    fixture.respond(&child, RecordType::DS, [], []);
    let (handle, _) = fixture.build();

    let response = lookup_child_a(&handle).await.unwrap();
    assert_eq!(response.answers[0].proof, Proof::Bogus);
}

/// A validating handle sets the CD bit on every query it sends upstream: the query being
/// validated, the DNSKEY and DS queries it makes through `lookup()`, and the NS queries that
/// `find_ds_records()` sends to the wrapped handle directly.
///
/// RFC 6840 section 5.9: validating resolvers SHOULD set the CD bit on every upstream query.
/// Regression test for <https://github.com/hickory-dns/hickory-dns/issues/3966>.
#[tokio::test]
async fn validating_queries_set_checking_disabled() -> Result<(), NetError> {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Insecure);
    let child = Name::from_ascii("child.example.com.")?;
    let parent = Name::from_ascii("example.com.")?;
    fixture.respond(&child, RecordType::DS, [], [unsigned_soa(&parent)]);
    let (handle, queries) = fixture.build();

    let response = lookup_child_a(&handle).await?;
    assert_eq!(
        response.answers.first().map(|record| record.proof),
        Some(Proof::Insecure)
    );

    let logged = mem::take(&mut *queries.0.lock().unwrap_or_else(PoisonError::into_inner));
    for record_type in [
        RecordType::A,
        RecordType::DNSKEY,
        RecordType::DS,
        RecordType::NS,
    ] {
        assert!(
            logged
                .iter()
                .any(|entry| entry.query.query_type == record_type),
            "expected at least one {record_type} query upstream"
        );
    }
    let cleared = logged
        .iter()
        .filter(|entry| !entry.checking_disabled)
        .map(|entry| &entry.query)
        .collect::<Vec<_>>();
    assert!(
        cleared.is_empty(),
        "queries sent upstream with CD=0: {cleared:?}"
    );
    Ok(())
}

async fn lookup_child_a(handle: &DnssecDnsHandle<MockHandle>) -> Result<DnsResponse, NetError> {
    let name = Name::from_ascii("www.child.example.com.").unwrap();
    handle
        .lookup(
            Query::new(name, RecordType::A),
            DnsRequestOptions::default(),
        )
        .first_answer()
        .await
}

/// A signed root zone and a signed `com.` zone, delegating to `example.com.`, which in turn
/// delegates to `child.example.com.`. Both `example.com.` and `child.example.com.` are unsigned
/// zones, and `www.child.example.com.` has an A record.
///
/// If the `parent` configuration value is [`Parent::Secure`], `com.` zone will include a DS
/// record for the `example.com.` zone, establishing a secure delegation, even though the
/// `example.com.` zone's records are unsigned.
struct MockHandleBuilder {
    root: DnssecSigner,
    responses: HashMap<(LowerName, RecordType), Message>,
}

impl MockHandleBuilder {
    fn new(parent: Parent) -> Self {
        let key =
            Ed25519SigningKey::from_pkcs8(&Ed25519SigningKey::generate_pkcs8().unwrap()).unwrap();
        let public_key = key.to_public_key().unwrap();
        let root = DnssecSigner::new(
            DNSKEY::from_key(&public_key),
            Box::new(key),
            Name::root(),
            Duration::from_secs(86400),
        );

        let mut new = Self {
            root,
            responses: HashMap::default(),
        };

        let key =
            Ed25519SigningKey::from_pkcs8(&Ed25519SigningKey::generate_pkcs8().unwrap()).unwrap();
        let com_public_key = key.to_public_key().unwrap();
        let com = DnssecSigner::new(
            DNSKEY::from_key(&com_public_key),
            Box::new(key),
            Name::from_ascii("com.").unwrap(),
            Duration::from_secs(86400),
        );

        let key =
            Ed25519SigningKey::from_pkcs8(&Ed25519SigningKey::generate_pkcs8().unwrap()).unwrap();
        let example_public_key = key.to_public_key().unwrap();
        let example = DnssecSigner::new(
            DNSKEY::from_key(&example_public_key),
            Box::new(key),
            Name::from_ascii("example.com.").unwrap(),
            Duration::from_secs(86400),
        );

        let child = Name::from_ascii("child.example.com.").unwrap();
        let www = Name::from_ascii("www.child.example.com.").unwrap();

        new.respond(
            &new.root.signer_name().clone(),
            RecordType::DNSKEY,
            sign([dnskey(&new.root)], &new.root),
            [],
        );
        new.respond(
            com.signer_name(),
            RecordType::DS,
            sign([ds(&com, &com_public_key)], &new.root),
            [],
        );
        new.respond(
            com.signer_name(),
            RecordType::DNSKEY,
            sign([dnskey(&com)], &com),
            [],
        );
        new.respond(
            example.signer_name(),
            RecordType::NS,
            [ns(example.signer_name())],
            [],
        );

        match parent {
            Parent::Insecure => {
                let mut authorities = sign([unsigned_soa(com.signer_name())], &com);
                authorities.extend(sign(
                    [Record::from_rdata(
                        example.signer_name().clone(),
                        TTL,
                        RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                            Name::from_ascii("example0.com.").unwrap(),
                            [RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
                        ))),
                    )],
                    &com,
                ));
                new.respond(example.signer_name(), RecordType::DS, [], authorities);
            }
            Parent::Secure => {
                new.respond(
                    example.signer_name(),
                    RecordType::DS,
                    sign([ds(&example, &example_public_key)], &com),
                    [],
                );
            }
        }

        new.respond(&child, RecordType::NS, [ns(&child)], []);
        new.respond(&www, RecordType::NS, [], []);
        new.respond(&www, RecordType::A, [a(&www)], []);
        new
    }

    fn respond(
        &mut self,
        name: &Name,
        record_type: RecordType,
        answers: impl IntoIterator<Item = Record>,
        authorities: impl IntoIterator<Item = Record>,
    ) {
        let mut message = Message::query();
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answers(answers);
        message.add_authorities(authorities);
        self.responses
            .insert((LowerName::from(name), record_type), message);
    }

    fn build(self) -> (DnssecDnsHandle<MockHandle>, QueryLog) {
        let Self { root, responses } = self;
        let queries = QueryLog::default();
        let handle = MockHandle {
            responses: Arc::new(responses),
            queries: queries.clone(),
        };

        let mut anchors = TrustAnchors::empty();
        anchors.insert(
            &root.key().to_public_key().unwrap(),
            LowerName::from(root.signer_name()),
        );

        (
            DnssecDnsHandle::with_trust_anchor(handle, Arc::new(anchors)),
            queries,
        )
    }
}

#[derive(Clone, Copy)]
enum Parent {
    Insecure,
    Secure,
}

/// Sign the given RRset with this zone's key, returning the records and their RRSIG.
fn sign(records: impl IntoIterator<Item = Record>, signer: &DnssecSigner) -> Vec<Record> {
    let mut records = records.into_iter().collect::<Vec<_>>();
    let first = records.first().expect("RRset must not be empty");
    let mut rrset = RecordSet::with_ttl(first.name.clone(), first.record_type(), TTL);
    for record in &records {
        rrset.insert(record.clone(), 0);
    }

    let inception = OffsetDateTime::now_utc() - Duration::from_secs(3600);
    let rrsig = RRSIG::from_rrset(&rrset, DNSClass::IN, inception, signer).unwrap();
    records.push(Record::from_rdata(
        first.name.clone(),
        TTL,
        RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
    ));
    records
}

fn ds(signer: &DnssecSigner, pub_key: &PublicKeyBuf) -> Record {
    let ds = DS::from_key(pub_key, signer.signer_name(), DigestType::SHA256).unwrap();
    Record::from_rdata(
        signer.signer_name().clone(),
        TTL,
        RData::DNSSEC(DNSSECRData::DS(ds)),
    )
}

fn dnskey(signer: &DnssecSigner) -> Record {
    Record::from_rdata(
        signer.signer_name().clone(),
        TTL,
        RData::DNSSEC(DNSSECRData::DNSKEY(signer.to_dnskey())),
    )
}

fn unsigned_soa(name: &Name) -> Record {
    Record::from_rdata(
        name.clone(),
        TTL,
        RData::SOA(SOA::new(
            Name::from_ascii("ns.")
                .unwrap()
                .append_domain(name)
                .unwrap(),
            Name::from_ascii("admin.")
                .unwrap()
                .append_domain(name)
                .unwrap(),
            1,
            3600,
            3600,
            3600,
            3600,
        )),
    )
}

fn ns(name: &Name) -> Record {
    Record::from_rdata(
        name.clone(),
        TTL,
        RData::NS(NS(Name::from_ascii("ns.")
            .unwrap()
            .append_domain(name)
            .unwrap())),
    )
}

fn a(name: &Name) -> Record {
    Record::from_rdata(name.clone(), TTL, RData::A(A(Ipv4Addr::new(192, 0, 2, 1))))
}

#[derive(Clone, Default)]
struct QueryLog(Arc<Mutex<Vec<LoggedQuery>>>);

/// A query the mock upstream received, with the CD bit of the request that carried it.
struct LoggedQuery {
    query: Query,
    checking_disabled: bool,
}

impl QueryLog {
    fn count(&self, name: &Name, record_type: RecordType) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|logged| &logged.query.name == name && logged.query.query_type == record_type)
            .count()
    }
}

#[derive(Clone)]
struct MockHandle {
    responses: Arc<HashMap<(LowerName, RecordType), Message>>,
    queries: QueryLog,
}

impl DnsHandle for MockHandle {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, NetError>> + Send>>;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        let query = request.queries[0].clone();
        self.queries
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(LoggedQuery {
                query: query.clone(),
                checking_disabled: request.metadata.checking_disabled,
            });

        let key = (LowerName::from(&query.name), query.query_type);
        let Some(message) = self.responses.get(&key) else {
            return Box::pin(stream::once(future::err(NetError::from(format!(
                "no canned response for {query}"
            )))));
        };

        let mut message = message.clone();
        message.metadata.id = request.metadata.id;
        message.add_query(query);
        let response = DnsResponse::from_message(message.into_response()).unwrap();
        Box::pin(stream::once(future::ok(response)))
    }
}

const TTL: u32 = 3600;
