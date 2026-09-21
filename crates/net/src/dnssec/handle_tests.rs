//! Tests for [`DnssecDnsHandle`] against a mock upstream returning canned responses.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    pin::Pin,
    sync::{Arc, Mutex},
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

    let fixture = Fixture::new(Parent::Insecure);
    let child = Name::from_ascii("child.example.com.").unwrap();
    let mut upstream = fixture.upstream();
    upstream.respond(&child, RecordType::DS, [], [unsigned_soa(&child)]);
    let (handle, queries) = upstream.build(&fixture);

    let response = lookup_child_a(&handle).await.unwrap();
    assert_eq!(response.answers[0].proof, Proof::Insecure);
    assert_eq!(
        queries.count(&child, RecordType::DS),
        1,
        "the DS query for the child zone should only be sent once"
    );
}

/// The expected case: a DS query for an insecure zone is answered with the parent zone's SOA
/// record.
#[tokio::test]
async fn insecure_delegation_with_parent_soa_in_ds_response() {
    subscribe();

    let fixture = Fixture::new(Parent::Insecure);
    let child = Name::from_ascii("child.example.com.").unwrap();
    let parent = Name::from_ascii("example.com.").unwrap();
    let mut upstream = fixture.upstream();
    upstream.respond(&child, RecordType::DS, [], [unsigned_soa(&parent)]);
    let (handle, _) = upstream.build(&fixture);

    let response = lookup_child_a(&handle).await.unwrap();
    assert_eq!(response.answers[0].proof, Proof::Insecure);
}

/// If the parent zone is secure, an unauthenticated DS response for the child zone must not be
/// accepted as proof of an insecure delegation, regardless of the SOA record it carries.
#[tokio::test]
async fn bogus_delegation_with_child_soa_in_ds_response() {
    subscribe();

    let fixture = Fixture::new(Parent::Secure);
    let child = Name::from_ascii("child.example.com.").unwrap();
    let mut upstream = fixture.upstream();
    upstream.respond(&child, RecordType::DS, [], [unsigned_soa(&child)]);
    let (handle, _) = upstream.build(&fixture);

    let response = lookup_child_a(&handle).await.unwrap();
    assert_eq!(response.answers[0].proof, Proof::Bogus);
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
/// If `example.com.` is [`Parent::Secure`], `com.` publishes a DS record for it, so its
/// delegation is secure even though its records are unsigned.
struct Fixture {
    root: Zone,
    com: Zone,
    example: Zone,
    parent: Parent,
}

#[derive(Clone, Copy)]
enum Parent {
    Insecure,
    Secure,
}

impl Fixture {
    fn new(parent: Parent) -> Self {
        Self {
            root: Zone::new(Name::root()),
            com: Zone::new(Name::from_ascii("com.").unwrap()),
            example: Zone::new(Name::from_ascii("example.com.").unwrap()),
            parent,
        }
    }

    fn upstream(&self) -> Upstream {
        let Self {
            root,
            com,
            example,
            parent,
        } = self;
        let child = Name::from_ascii("child.example.com.").unwrap();
        let www = Name::from_ascii("www.child.example.com.").unwrap();

        let mut upstream = Upstream::default();
        upstream.respond(
            &root.name,
            RecordType::DNSKEY,
            root.sign([root.dnskey()]),
            [],
        );
        upstream.respond(&com.name, RecordType::DS, root.sign([com.ds()]), []);
        upstream.respond(&com.name, RecordType::DNSKEY, com.sign([com.dnskey()]), []);

        upstream.respond(&example.name, RecordType::NS, [ns(&example.name)], []);
        match parent {
            Parent::Insecure => {
                let mut authorities = com.sign([com.soa()]);
                authorities.extend(com.sign([Record::from_rdata(
                    example.name.clone(),
                    TTL,
                    RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                        Name::from_ascii("example0.com.").unwrap(),
                        [RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
                    ))),
                )]));
                upstream.respond(&example.name, RecordType::DS, [], authorities);
            }
            Parent::Secure => {
                upstream.respond(&example.name, RecordType::DS, com.sign([example.ds()]), []);
            }
        }

        upstream.respond(&child, RecordType::NS, [ns(&child)], []);
        upstream.respond(&www, RecordType::NS, [], []);
        upstream.respond(&www, RecordType::A, [a(&www)], []);
        upstream
    }

    fn trust_anchors(&self) -> Arc<TrustAnchors> {
        let mut anchors = TrustAnchors::empty();
        anchors.insert(&self.root.public_key, LowerName::from(&self.root.name));
        Arc::new(anchors)
    }
}

/// Signing key material for one zone.
struct Zone {
    name: Name,
    signer: DnssecSigner,
    public_key: PublicKeyBuf,
}

impl Zone {
    fn new(name: Name) -> Self {
        let key =
            Ed25519SigningKey::from_pkcs8(&Ed25519SigningKey::generate_pkcs8().unwrap()).unwrap();
        let public_key = key.to_public_key().unwrap();
        let signer = DnssecSigner::new(
            DNSKEY::from_key(&public_key),
            Box::new(key),
            name.clone(),
            Duration::from_secs(86400),
        );
        Self {
            name,
            signer,
            public_key,
        }
    }

    fn dnskey(&self) -> Record {
        Record::from_rdata(
            self.name.clone(),
            TTL,
            RData::DNSSEC(DNSSECRData::DNSKEY(self.signer.to_dnskey())),
        )
    }

    fn ds(&self) -> Record {
        let ds = DS::from_key(&self.public_key, &self.name, DigestType::SHA256).unwrap();
        Record::from_rdata(self.name.clone(), TTL, RData::DNSSEC(DNSSECRData::DS(ds)))
    }

    fn soa(&self) -> Record {
        unsigned_soa(&self.name)
    }

    /// Sign the given RRset with this zone's key, returning the records and their RRSIG.
    fn sign(&self, records: impl IntoIterator<Item = Record>) -> Vec<Record> {
        let mut records = records.into_iter().collect::<Vec<_>>();
        let first = records.first().expect("RRset must not be empty");
        let mut rrset = RecordSet::with_ttl(first.name.clone(), first.record_type(), TTL);
        for record in &records {
            rrset.insert(record.clone(), 0);
        }

        let inception = OffsetDateTime::now_utc() - Duration::from_secs(3600);
        let rrsig = RRSIG::from_rrset(&rrset, DNSClass::IN, inception, &self.signer).unwrap();
        records.push(Record::from_rdata(
            first.name.clone(),
            TTL,
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
        ));
        records
    }
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

/// Canned responses for the mock upstream, keyed by query name and type.
#[derive(Default)]
struct Upstream {
    responses: HashMap<(LowerName, RecordType), Message>,
}

impl Upstream {
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
        for record in authorities {
            message.add_authority(record);
        }
        self.responses
            .insert((LowerName::from(name), record_type), message);
    }

    fn build(self, fixture: &Fixture) -> (DnssecDnsHandle<MockHandle>, QueryLog) {
        let queries = QueryLog::default();
        let handle = MockHandle {
            responses: Arc::new(self.responses),
            queries: queries.clone(),
        };
        (
            DnssecDnsHandle::with_trust_anchor(handle, fixture.trust_anchors()),
            queries,
        )
    }
}

#[derive(Clone, Default)]
struct QueryLog(Arc<Mutex<Vec<Query>>>);

impl QueryLog {
    fn count(&self, name: &Name, record_type: RecordType) -> usize {
        let mut count = 0;
        for query in self.0.lock().unwrap().iter() {
            if &query.name == name && query.query_type == record_type {
                count += 1;
            }
        }
        count
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
        self.queries.0.lock().unwrap().push(query.clone());

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
