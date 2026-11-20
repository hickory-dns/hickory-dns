//! Tests for [`DnssecDnsHandle`] against a mock upstream returning canned responses.

use core::future::Future;
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures_util::future;
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
    xfer::DnsHandle,
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

/// A DS trust anchor for the root zone must validate the root DNSKEY RRset, even though the root
/// has no parent to publish DS records.
#[tokio::test]
async fn root_ds_trust_anchor_validates_root_dnskey() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Insecure);
    let child = Name::from_ascii("child.example.com.").unwrap();
    let parent = Name::from_ascii("example.com.").unwrap();
    fixture.respond(&child, RecordType::DS, [], [unsigned_soa(&parent)]);
    let anchors = ds_anchor(&fixture.root.key().to_public_key().unwrap(), &Name::root());
    let (handle, queries) = fixture.build_with(anchors);

    // The insecure delegation proof is signed by `com.`, whose chain of trust ends at the root.
    let response = lookup_child_a(&handle).await.unwrap();
    assert_eq!(response.answers[0].proof, Proof::Insecure);
    assert_eq!(queries.count(&Name::root(), RecordType::DS), 0);
}

/// A DS trust anchor for a zone must validate the zone's DNSKEY RRset without asking anyone for
/// the zone's DS RRset. Nothing above the anchored zone is trusted here, so a DS response from
/// the parent could not be validated.
#[tokio::test]
async fn ds_trust_anchor_validates_without_ds_query() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Insecure);
    let child = Name::from_ascii("child.example.com.").unwrap();
    let parent = Name::from_ascii("example.com.").unwrap();
    let com = Name::from_ascii("com.").unwrap();
    fixture.respond(&child, RecordType::DS, [], [unsigned_soa(&parent)]);
    let anchors = ds_anchor(&fixture.com_public_key, &com);
    let (handle, queries) = fixture.build_with(anchors);

    let response = lookup_child_a(&handle).await.unwrap();
    assert_eq!(response.answers[0].proof, Proof::Insecure);
    assert_eq!(queries.count(&com, RecordType::DS), 0);
}

/// An unsigned RRset below a DS trust anchor is bogus, and the search for its zone cut must stop
/// at the anchored zone instead of continuing toward the root.
#[tokio::test]
async fn unsigned_rrset_below_ds_trust_anchor_is_bogus() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Insecure);
    let com = Name::from_ascii("com.").unwrap();
    let unsigned = Name::from_ascii("unsigned.com.").unwrap();
    fixture.respond(&unsigned, RecordType::A, [a(&unsigned)], []);
    fixture.respond(&unsigned, RecordType::NS, [], []);
    let anchors = ds_anchor(&fixture.com_public_key, &com);
    let (handle, queries) = fixture.build_with(anchors);

    let response = handle
        .lookup(
            Query::new(unsigned, RecordType::A),
            DnsRequestOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(response.answers[0].proof, Proof::Bogus);
    assert_eq!(
        queries.count(&com, RecordType::NS),
        0,
        "the zone cut search must stop at the anchored zone"
    );
}

/// Builds trust anchors holding only a DS record covering the given zone's key.
fn ds_anchor(public_key: &PublicKeyBuf, zone: &Name) -> TrustAnchors {
    let ds = DS::from_key(public_key, zone, DigestType::SHA256).unwrap();
    let mut anchors = TrustAnchors::empty();
    anchors.insert_ds(ds, LowerName::from(zone)).unwrap();
    anchors
}

async fn lookup_child_a(handle: &DnssecDnsHandle<MockHandle>) -> Result<DnsResponse, NetError> {
    let name = Name::from_ascii("www.child.example.com.").unwrap();
    handle
        .lookup(
            Query::new(name, RecordType::A),
            DnsRequestOptions::default(),
        )
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
    com_public_key: PublicKeyBuf,
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

        let key =
            Ed25519SigningKey::from_pkcs8(&Ed25519SigningKey::generate_pkcs8().unwrap()).unwrap();
        let com_public_key = key.to_public_key().unwrap();

        let mut new = Self {
            root,
            com_public_key: com_public_key.clone(),
            responses: HashMap::default(),
        };

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
        let mut anchors = TrustAnchors::empty();
        anchors.insert(
            &self.root.key().to_public_key().unwrap(),
            LowerName::from(self.root.signer_name()),
        );
        self.build_with(anchors)
    }

    /// Builds a handle trusting the given anchors instead of the root zone's DNSKEY.
    fn build_with(self, anchors: TrustAnchors) -> (DnssecDnsHandle<MockHandle>, QueryLog) {
        let queries = QueryLog::default();
        let handle = MockHandle {
            responses: Arc::new(self.responses),
            queries: queries.clone(),
        };

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
struct QueryLog(Arc<Mutex<Vec<Query>>>);

impl QueryLog {
    fn count(&self, name: &Name, record_type: RecordType) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|query| &query.name == name && query.query_type == record_type)
            .count()
    }
}

#[derive(Clone)]
struct MockHandle {
    responses: Arc<HashMap<(LowerName, RecordType), Message>>,
    queries: QueryLog,
}

impl DnsHandle for MockHandle {
    type Runtime = TokioRuntimeProvider;

    fn send(
        &self,
        request: DnsRequest,
    ) -> impl Future<Output = Result<DnsResponse, NetError>> + Send {
        let query = request.queries[0].clone();
        self.queries.0.lock().unwrap().push(query.clone());

        let key = (LowerName::from(&query.name), query.query_type);
        let Some(message) = self.responses.get(&key) else {
            return future::err(NetError::from(format!("no canned response for {query}")));
        };

        let mut message = message.clone();
        message.metadata.id = request.metadata.id;
        message.add_query(query);
        future::ok(DnsResponse::from_message(message.into_response()).unwrap())
    }
}

const TTL: u32 = 3600;
