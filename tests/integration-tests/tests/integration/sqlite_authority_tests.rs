#![cfg(feature = "sqlite")]

use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
#[cfg(feature = "__dnssec")]
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::*;

#[cfg(feature = "__dnssec")]
use hickory_proto::dnssec::rdata::DNSSECRData;
#[cfg(feature = "__dnssec")]
use hickory_proto::dnssec::rdata::tsig::{TsigAlgorithm, TsigError};
#[cfg(feature = "__dnssec")]
use hickory_proto::dnssec::tsig::TSigner;
use hickory_proto::op::{
    Edns, Header, LowerQuery, Message, MessageSignature, MessageSigner, MessageType, OpCode, Query,
    ResponseCode,
};
use hickory_proto::rr::rdata::opt::{EdnsOption, NSIDPayload};
use hickory_proto::rr::rdata::{A, AAAA, NS, TXT};
use hickory_proto::rr::{DNSClass, LowerName, Name, RData, Record, RecordType};
#[cfg(feature = "__dnssec")]
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder, EncodeMode};
use hickory_proto::xfer::Protocol;
use hickory_server::authority::{
    Authority, AxfrPolicy, LookupError, LookupOptions, MessageRequest, MessageResponseBuilder,
    ZoneType,
};
#[cfg(feature = "__dnssec")]
use hickory_server::dnssec::NxProofKind;
#[cfg(feature = "__dnssec")]
use hickory_server::server::Request;
use hickory_server::store::in_memory::InMemoryAuthority;
use hickory_server::store::sqlite::{Journal, SqliteAuthority};
use test_support::subscribe;

const TEST_HEADER: &Header = &Header::new(10, MessageType::Query, OpCode::Query);

fn create_example() -> SqliteAuthority {
    let mut authority = hickory_integration::example_authority::create_example();
    authority.set_axfr_policy(AxfrPolicy::AllowAll); // policy is applied in SqliteAuthority.
    SqliteAuthority::new(authority, AxfrPolicy::Deny, true, false)
}

#[cfg(feature = "__dnssec")]
fn create_secure_example() -> SqliteAuthority {
    let authority = hickory_integration::example_authority::create_secure_example();
    SqliteAuthority::new(authority, AxfrPolicy::Deny, true, true)
}

#[tokio::test]
async fn test_search() {
    subscribe();
    let example = create_example();
    let origin = example.origin().clone();

    let mut query = Query::new();
    query.set_name(origin.into());
    let request = Request::from_message(
        MessageRequest::mock(*TEST_HEADER, query),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let result = example
        .search(&request, LookupOptions::default())
        .await
        .0
        .unwrap();
    if !result.is_empty() {
        let record = result.iter().next().unwrap();
        assert_eq!(record.record_type(), RecordType::A);
        assert_eq!(record.dns_class(), DNSClass::IN);
        assert_eq!(record.data(), &RData::A(A::new(93, 184, 215, 14)));
    } else {
        panic!("expected a result"); // valid panic, in test
    }
}

/// this is a little more interesting b/c it requires a recursive lookup for the origin
#[tokio::test]
async fn test_search_www() {
    subscribe();
    let example = create_example();
    let www_name = Name::parse("www.example.com.", None).unwrap();

    let mut query = Query::new();
    query.set_name(www_name);
    let request = Request::from_message(
        MessageRequest::mock(*TEST_HEADER, query),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let result = example
        .search(&request, LookupOptions::default())
        .await
        .0
        .unwrap();
    if !result.is_empty() {
        let record = result.iter().next().unwrap();
        assert_eq!(record.record_type(), RecordType::A);
        assert_eq!(record.dns_class(), DNSClass::IN);
        assert_eq!(record.data(), &RData::A(A::new(93, 184, 215, 14)));
    } else {
        panic!("expected a result"); // valid panic, in test
    }
}

#[tokio::test]
async fn test_authority() {
    subscribe();

    let authority = create_example();

    assert_eq!(
        authority
            .soa()
            .await
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .dns_class(),
        DNSClass::IN
    );

    assert!(
        !authority
            .lookup(authority.origin(), RecordType::NS, LookupOptions::default())
            .await
            .unwrap()
            .was_empty()
    );

    let mut lookup: Vec<_> = authority
        .ns(LookupOptions::default())
        .await
        .unwrap()
        .iter()
        .cloned()
        .collect();
    lookup.sort();

    assert_eq!(
        *lookup.first().unwrap(),
        Record::from_rdata(
            authority.origin().clone().into(),
            86400,
            RData::NS(NS(Name::parse("a.iana-servers.net.", None).unwrap())),
        )
        .set_dns_class(DNSClass::IN)
        .clone()
    );
    assert_eq!(
        *lookup.last().unwrap(),
        Record::from_rdata(
            authority.origin().clone().into(),
            86400,
            RData::NS(NS(Name::parse("b.iana-servers.net.", None).unwrap())),
        )
        .set_dns_class(DNSClass::IN)
        .clone()
    );

    assert!(
        !authority
            .lookup(
                authority.origin(),
                RecordType::TXT,
                LookupOptions::default()
            )
            .await
            .unwrap()
            .was_empty()
    );

    let mut lookup: Vec<_> = authority
        .lookup(
            authority.origin(),
            RecordType::TXT,
            LookupOptions::default(),
        )
        .await
        .unwrap()
        .iter()
        .cloned()
        .collect();
    lookup.sort();

    assert_eq!(
        *lookup.first().unwrap(),
        Record::from_rdata(
            authority.origin().clone().into(),
            60,
            RData::TXT(TXT::new(vec![
                "$Id: example.com 4415 2015-08-24 \
                 20:12:23Z davids $"
                    .to_string(),
            ])),
        )
        .set_dns_class(DNSClass::IN)
        .clone()
    );

    assert_eq!(
        *authority
            .lookup(authority.origin(), RecordType::A, LookupOptions::default())
            .await
            .unwrap()
            .iter()
            .next()
            .unwrap(),
        Record::from_rdata(
            authority.origin().clone().into(),
            86400,
            RData::A(A::new(93, 184, 215, 14)),
        )
        .set_dns_class(DNSClass::IN)
        .clone()
    );
}

#[cfg(feature = "__dnssec")]
#[tokio::test]
async fn test_authorize_update() {
    use hickory_proto::serialize::binary::BinEncodable;

    subscribe();

    let authority = create_example();

    let mut message = Message::query();
    message.set_op_code(OpCode::Update);
    message.add_query(Query::default());

    let bytes = message.to_bytes().unwrap();
    let request =
        Request::from_bytes(bytes, SocketAddr::from(([127, 0, 0, 1], 53)), Protocol::Udp).unwrap();

    assert_eq!(
        authority.authorize_update(&request).await.0,
        Err(ResponseCode::Refused)
    );

    // TODO: this will nee to be more complex as additional policies are added
    // authority.set_allow_update(true);
    // assert!(authority.authorize(&message).is_ok());
}

#[tokio::test]
async fn test_prerequisites() {
    subscribe();
    let not_zone = Name::from_str("not.a.domain.com").unwrap();
    let not_in_zone = Name::from_str("not.example.com").unwrap();

    let mut authority = create_example();
    authority.set_allow_update(true);

    // first check the initial negatives, ttl = 0, and the zone is the same
    assert_eq!(
        authority
            .verify_prerequisites(&[Record::update0(not_in_zone.clone(), 86400, RecordType::A)
                .set_dns_class(DNSClass::IN)
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority
            .verify_prerequisites(&[Record::update0(not_zone, 0, RecordType::A)
                .set_dns_class(DNSClass::IN)
                .clone()],)
            .await,
        Err(ResponseCode::NotZone)
    );

    // *   ANY      ANY      empty    Name is in use
    assert!(
        authority
            .verify_prerequisites(&[Record::update0(
                authority.origin().clone().into(),
                0,
                RecordType::ANY,
            )
            .set_dns_class(DNSClass::ANY)
            .clone()])
            .await
            .is_ok()
    );
    assert_eq!(
        authority
            .verify_prerequisites(&[Record::from_rdata(
                not_in_zone.clone(),
                0,
                RData::Update0(RecordType::ANY)
            )
            .set_dns_class(DNSClass::ANY)
            .clone()],)
            .await,
        Err(ResponseCode::NXDomain)
    );

    // *   ANY      rrset    empty    RRset exists (value independent)
    assert!(
        authority
            .verify_prerequisites(&[Record::update0(
                authority.origin().clone().into(),
                0,
                RecordType::A,
            )
            .set_dns_class(DNSClass::ANY)
            .clone()])
            .await
            .is_ok()
    );
    assert_eq!(
        authority
            .verify_prerequisites(&[Record::update0(not_in_zone.clone(), 0, RecordType::A,)
                .set_dns_class(DNSClass::ANY)
                .clone()],)
            .await,
        Err(ResponseCode::NXRRSet)
    );

    // *   NONE     ANY      empty    Name is not in use
    assert!(
        authority
            .verify_prerequisites(&[Record::update0(not_in_zone.clone(), 0, RecordType::ANY,)
                .set_dns_class(DNSClass::NONE)
                .clone()])
            .await
            .is_ok()
    );
    assert_eq!(
        authority
            .verify_prerequisites(&[Record::update0(
                authority.origin().clone().into(),
                0,
                RecordType::ANY,
            )
            .set_dns_class(DNSClass::NONE)
            .clone()],)
            .await,
        Err(ResponseCode::YXDomain)
    );

    // *   NONE     rrset    empty    RRset does not exist
    assert!(
        authority
            .verify_prerequisites(&[Record::update0(not_in_zone.clone(), 0, RecordType::A,)
                .set_dns_class(DNSClass::NONE)
                .clone()])
            .await
            .is_ok()
    );
    assert_eq!(
        authority
            .verify_prerequisites(&[Record::update0(
                authority.origin().clone().into(),
                0,
                RecordType::A,
            )
            .set_dns_class(DNSClass::NONE)
            .clone()],)
            .await,
        Err(ResponseCode::YXRRSet)
    );

    // *   zone     rrset    rr       RRset exists (value dependent)
    assert!(
        authority
            .verify_prerequisites(&[Record::from_rdata(
                authority.origin().clone().into(),
                0,
                RData::A(A::new(93, 184, 215, 14)),
            )
            .set_dns_class(DNSClass::IN)
            .clone()])
            .await
            .is_ok()
    );
    // wrong class
    assert_eq!(
        authority
            .verify_prerequisites(&[Record::from_rdata(
                authority.origin().clone().into(),
                0,
                RData::A(A::new(93, 184, 215, 14)),
            )
            .set_dns_class(DNSClass::CH)
            .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    // wrong Name
    assert_eq!(
        authority
            .verify_prerequisites(&[Record::from_rdata(
                not_in_zone,
                0,
                RData::A(A::new(93, 184, 216, 24)),
            )
            .set_dns_class(DNSClass::IN)
            .clone()],)
            .await,
        Err(ResponseCode::NXRRSet)
    );
    // wrong IP
    assert_eq!(
        authority
            .verify_prerequisites(&[Record::from_rdata(
                authority.origin().clone().into(),
                0,
                RData::A(A::new(93, 184, 216, 24)),
            )
            .set_dns_class(DNSClass::IN)
            .clone()],)
            .await,
        Err(ResponseCode::NXRRSet)
    );
}

#[tokio::test]
async fn test_pre_scan() {
    subscribe();

    let up_name = Name::from_str("www.example.com").unwrap();
    let not_zone = Name::from_str("not.zone.com").unwrap();

    let authority = create_example();

    assert_eq!(
        authority
            .pre_scan(&[
                Record::from_rdata(not_zone, 86400, RData::A(A::new(93, 184, 216, 24)),)
                    .set_dns_class(DNSClass::IN)
                    .clone()
            ],)
            .await,
        Err(ResponseCode::NotZone)
    );

    assert_eq!(
        authority
            .pre_scan(&[Record::update0(up_name.clone(), 86400, RecordType::ANY,)
                .set_dns_class(DNSClass::IN)
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority
            .pre_scan(&[Record::update0(up_name.clone(), 86400, RecordType::AXFR,)
                .set_dns_class(DNSClass::IN)
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority
            .pre_scan(&[Record::update0(up_name.clone(), 86400, RecordType::IXFR,)
                .set_dns_class(DNSClass::IN)
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert!(
        authority
            .pre_scan(&[Record::from_rdata(
                up_name.clone(),
                86400,
                RData::A(A::new(93, 184, 216, 24)),
            )
            .set_dns_class(DNSClass::IN)
            .clone()])
            .await
            .is_ok()
    );
    assert!(
        authority
            .pre_scan(&[Record::update0(up_name.clone(), 86400, RecordType::A,)
                .set_dns_class(DNSClass::IN)
                .clone()])
            .await
            .is_ok()
    );

    assert_eq!(
        authority
            .pre_scan(&[Record::from_rdata(
                up_name.clone(),
                86400,
                RData::A(A::new(93, 184, 216, 24)),
            )
            .set_dns_class(DNSClass::ANY)
            .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority
            .pre_scan(&[
                Record::from_rdata(up_name.clone(), 0, RData::A(A::new(93, 184, 216, 24)),)
                    .set_dns_class(DNSClass::ANY)
                    .clone()
            ],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority
            .pre_scan(&[Record::update0(up_name.clone(), 0, RecordType::AXFR,)
                .set_dns_class(DNSClass::ANY)
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority
            .pre_scan(&[Record::update0(up_name.clone(), 0, RecordType::IXFR,)
                .set_dns_class(DNSClass::ANY)
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert!(
        authority
            .pre_scan(&[Record::update0(up_name.clone(), 0, RecordType::ANY,)
                .set_dns_class(DNSClass::ANY)
                .clone()])
            .await
            .is_ok()
    );
    assert!(
        authority
            .pre_scan(&[Record::update0(up_name.clone(), 0, RecordType::A,)
                .set_dns_class(DNSClass::ANY)
                .clone()])
            .await
            .is_ok()
    );

    assert_eq!(
        authority
            .pre_scan(&[Record::update0(up_name.clone(), 86400, RecordType::A,)
                .set_dns_class(DNSClass::NONE)
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority
            .pre_scan(&[Record::update0(up_name.clone(), 0, RecordType::ANY,)
                .set_dns_class(DNSClass::NONE)
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority
            .pre_scan(&[Record::update0(up_name.clone(), 0, RecordType::AXFR,)
                .set_dns_class(DNSClass::NONE)
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority
            .pre_scan(&[Record::update0(up_name.clone(), 0, RecordType::IXFR,)
                .set_dns_class(DNSClass::NONE)
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert!(
        authority
            .pre_scan(&[Record::update0(up_name.clone(), 0, RecordType::A,)
                .set_dns_class(DNSClass::NONE)
                .clone()])
            .await
            .is_ok()
    );
    assert!(
        authority
            .pre_scan(&[
                Record::from_rdata(up_name.clone(), 0, RData::A(A::new(93, 184, 216, 24)),)
                    .set_dns_class(DNSClass::NONE)
                    .clone()
            ])
            .await
            .is_ok()
    );

    assert_eq!(
        authority
            .pre_scan(&[Record::update0(up_name, 86400, RecordType::A,)
                .set_dns_class(DNSClass::CH)
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
}

#[tokio::test]
async fn test_update() {
    subscribe();
    let new_name = Name::from_str("new.example.com.").unwrap();
    let www_name = Name::from_str("www.example.com.").unwrap();
    let mut authority = create_example();
    let serial = authority.serial().await;

    authority.set_allow_update(true);

    let mut original_vec: Vec<Record> = vec![
        Record::from_rdata(
            www_name.clone(),
            86400,
            RData::TXT(TXT::new(vec!["v=spf1 -all".to_string()])),
        )
        .set_dns_class(DNSClass::IN)
        .clone(),
        Record::from_rdata(www_name.clone(), 86400, RData::A(A::new(93, 184, 215, 14)))
            .set_dns_class(DNSClass::IN)
            .clone(),
        Record::from_rdata(
            www_name.clone(),
            86400,
            RData::AAAA(AAAA::new(
                0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
            )),
        )
        .set_dns_class(DNSClass::IN)
        .clone(),
    ];

    original_vec.sort();

    {
        // assert that the correct set of records is there.
        let mut www_rrset: Vec<Record> = authority
            .lookup(
                &www_name.clone().into(),
                RecordType::ANY,
                LookupOptions::default(),
            )
            .await
            .unwrap()
            .iter()
            .cloned()
            .collect();
        www_rrset.sort();

        assert_eq!(www_rrset, original_vec);

        // assert new record doesn't exist
        assert!(
            authority
                .lookup(
                    &new_name.clone().into(),
                    RecordType::ANY,
                    LookupOptions::default()
                )
                .await
                .unwrap()
                .was_empty()
        );
    }

    //
    //  zone     rrset    rr       Add to an RRset
    let add_record =
        &[
            Record::from_rdata(new_name.clone(), 86400, RData::A(A::new(93, 184, 216, 24)))
                .set_dns_class(DNSClass::IN)
                .clone(),
        ];
    assert!(
        authority
            .update_records(add_record, true,)
            .await
            .expect("update failed",)
    );
    assert_eq!(
        authority
            .lookup(
                &new_name.clone().into(),
                RecordType::ANY,
                LookupOptions::default()
            )
            .await
            .unwrap()
            .iter()
            .collect::<Vec<_>>(),
        add_record.iter().collect::<Vec<&Record>>()
    );
    assert_eq!(serial + 1, authority.serial().await);

    let add_www_record =
        &[
            Record::from_rdata(www_name.clone(), 86400, RData::A(A::new(10, 0, 0, 1)))
                .set_dns_class(DNSClass::IN)
                .clone(),
        ];
    assert!(
        authority
            .update_records(add_www_record, true,)
            .await
            .expect("update failed",)
    );
    assert_eq!(serial + 2, authority.serial().await);

    {
        let mut www_rrset: Vec<_> = authority
            .lookup(
                &www_name.clone().into(),
                RecordType::ANY,
                LookupOptions::default(),
            )
            .await
            .unwrap()
            .iter()
            .cloned()
            .collect();
        www_rrset.sort();

        let mut plus_10 = original_vec.clone();
        plus_10.push(add_www_record[0].clone());
        plus_10.sort();
        assert_eq!(www_rrset, plus_10);
    }

    //
    //  NONE     rrset    rr       Delete an RR from an RRset
    let del_record =
        &[
            Record::from_rdata(new_name.clone(), 86400, RData::A(A::new(93, 184, 216, 24)))
                .set_dns_class(DNSClass::NONE)
                .clone(),
        ];
    assert!(
        authority
            .update_records(del_record, true,)
            .await
            .expect("update failed",)
    );
    assert_eq!(serial + 3, authority.serial().await);
    {
        let lookup = authority
            .lookup(&new_name.into(), RecordType::ANY, LookupOptions::default())
            .await
            .unwrap();

        println!("after delete of specific record: {lookup:?}");
        assert!(lookup.was_empty());
    }

    // remove one from www
    let del_record = &[
        Record::from_rdata(www_name.clone(), 86400, RData::A(A::new(10, 0, 0, 1)))
            .set_dns_class(DNSClass::NONE)
            .clone(),
    ];
    assert!(
        authority
            .update_records(del_record, true,)
            .await
            .expect("update failed",)
    );
    assert_eq!(serial + 4, authority.serial().await);
    {
        let mut www_rrset: Vec<_> = authority
            .lookup(
                &www_name.clone().into(),
                RecordType::ANY,
                LookupOptions::default(),
            )
            .await
            .unwrap()
            .iter()
            .cloned()
            .collect();
        www_rrset.sort();

        assert_eq!(www_rrset, original_vec);
    }

    //
    //  ANY      rrset    empty    Delete an RRset
    let del_record = &[Record::update0(www_name.clone(), 86400, RecordType::A)
        .set_dns_class(DNSClass::ANY)
        .clone()];
    assert!(
        authority
            .update_records(del_record, true,)
            .await
            .expect("update failed",)
    );
    assert_eq!(serial + 5, authority.serial().await);
    let mut removed_a_vec: Vec<_> = vec![
        Record::from_rdata(
            www_name.clone(),
            86400,
            RData::TXT(TXT::new(vec!["v=spf1 -all".to_string()])),
        )
        .set_dns_class(DNSClass::IN)
        .clone(),
        Record::from_rdata(
            www_name.clone(),
            86400,
            RData::AAAA(AAAA::new(
                0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
            )),
        )
        .set_dns_class(DNSClass::IN)
        .clone(),
    ];
    removed_a_vec.sort();

    {
        let mut www_rrset: Vec<Record> = authority
            .lookup(
                &www_name.clone().into(),
                RecordType::ANY,
                LookupOptions::default(),
            )
            .await
            .unwrap()
            .iter()
            .cloned()
            .collect();
        www_rrset.sort();

        assert_eq!(www_rrset, removed_a_vec);
    }

    //
    //  ANY      ANY      empty    Delete all RRsets from a name
    println!("deleting all records");
    let del_record = &[Record::update0(www_name.clone(), 86400, RecordType::ANY)
        .set_dns_class(DNSClass::ANY)
        .clone()];

    assert!(
        authority
            .update_records(del_record, true,)
            .await
            .expect("update failed",)
    );

    assert!(
        authority
            .lookup(&www_name.into(), RecordType::ANY, LookupOptions::default())
            .await
            .unwrap()
            .was_empty()
    );

    assert_eq!(serial + 6, authority.serial().await);
}

#[cfg(feature = "__dnssec")]
#[tokio::test]
async fn test_update_tsig_valid() {
    subscribe();

    // First, we construct a test TSIG signer.
    let signer = test_tsig_signer(Name::from_str("test-tsig-key").unwrap());

    // Next we construct an authority, configured to allow updates authenticated with the signer.
    let mut authority = create_example();
    authority.set_allow_update(true);
    authority.set_tsig_signers(vec![signer.clone()]);

    // We want to add a new A record for a name. Let's first verify it doesn't exist yet.
    let new_name = Name::from_str("new.example.com.").unwrap();
    let res = authority
        .lookup(
            &new_name.clone().into(),
            RecordType::ANY,
            LookupOptions::default(),
        )
        .await
        .unwrap();
    assert!(res.was_empty());

    // Now we construct an update message to add a new A record for the name.
    let mut message = test_update_message(new_name.clone());

    // Before we serialize it into a MessageRequest, we need to sign it.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .unwrap();
    let (sig, _) = (&signer as &dyn MessageSigner)
        .sign_message(&message, now as u32)
        .unwrap();
    // Save the MAC of the request so we can verify the response.
    let MessageSignature::Tsig(tsig_rr) = sig.clone() else {
        panic!("unexpected message signature type");
    };
    let tsig_rr = tsig_rr
        .data()
        .as_dnssec()
        .and_then(DNSSECRData::as_tsig)
        .unwrap();
    let request_mac = tsig_rr.mac();
    message.set_signature(sig);

    // TODO(@cpu): add and use a MessageRequestBuilder type?
    // Round-trip the Message bytes into a MessageRequest.
    let bytes = message.to_bytes().unwrap();
    let request =
        Request::from_bytes(bytes, SocketAddr::from(([127, 0, 0, 1], 53)), Protocol::Udp).unwrap();

    // The update should succeed.
    let (resp, resp_signer) = authority.update(&request).await;
    assert!(resp.unwrap());

    // We should have produced a resp_signer.
    let resp_signer = resp_signer.expect("missing expected TSIG response signer");

    // Build an initial unsigned response for the update.
    // The catalog handles this in normal operation, but we're testing at the level of the
    // SqliteAuthority and so have to do this ourselves. Provide a response EDNS
    // with an option to ensure the response signature handles this correctly.
    let mut edns = Edns::new();
    edns.options_mut().insert(EdnsOption::NSID(
        NSIDPayload::new([0xC0, 0xFF, 0xEE]).unwrap(),
    ));
    let response = MessageResponseBuilder::new(request.raw_queries(), Some(edns.clone()));
    let mut response_header = Header::new(request.id(), MessageType::Response, OpCode::Update);
    response_header.set_response_code(ResponseCode::NoError);
    let mut response = response.build_no_records(response_header);

    // Serialize the unsigned response to get the TBS bytes to sign with the signer.
    let mut tbs_response_buf = Vec::with_capacity(512);
    let mut encoder = BinEncoder::with_mode(&mut tbs_response_buf, EncodeMode::Normal);
    let mut response_header = Header::new(request.id(), MessageType::Response, OpCode::Update);
    response_header.set_response_code(ResponseCode::NoError);
    let tbs_response = MessageResponseBuilder::new(request.raw_queries(), Some(edns))
        .build_no_records(response_header);
    tbs_response.destructive_emit(&mut encoder).unwrap();

    // Update the response with the produced signature.
    let resp_sig = resp_signer.sign(&tbs_response_buf).unwrap();
    response.set_signature(resp_sig.clone());

    // Serialize the now-signed response.
    let mut response_buf = Vec::with_capacity(512);
    let mut encoder = BinEncoder::with_mode(&mut response_buf, EncodeMode::Normal);
    response.destructive_emit(&mut encoder).unwrap();

    // We should be able to verify the signature and confirm the signing time is within the
    // validity range based on the fudge factor.
    let (_, _, range) = signer
        .verify_message_byte(&response_buf, Some(request_mac), true)
        .unwrap();
    assert!(range.contains(&now));

    // And we should now be able to look up the new record.
    let new_name = Name::from_str("new.example.com.").unwrap();
    let res = authority
        .lookup(
            &new_name.clone().into(),
            RecordType::ANY,
            LookupOptions::default(),
        )
        .await
        .unwrap();
    let records = res.iter().collect::<Vec<&Record>>();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].name(), &new_name);
    let RData::A(a) = records[0].data() else {
        panic!("unexpected record data");
    };
    assert_eq!(a.0, IpAddr::from([192, 168, 1, 10]));
}

#[cfg(feature = "__dnssec")]
#[tokio::test]
async fn test_update_tsig_invalid_unknown_signer() {
    subscribe();

    // Create an authority, configured to allow updates authenticated with a test signer.
    let mut authority = create_example();
    authority.set_allow_update(true);
    authority.set_tsig_signers(vec![test_tsig_signer(
        Name::from_str("test-tsig-key").unwrap(),
    )]);

    // Now, construct an update message but sign it with a **different** TSIG signer that
    // has a different key name.
    let new_name = Name::from_str("new.example.com.").unwrap();
    let mut message = test_update_message(new_name.clone());
    let bad_signer = test_tsig_signer(Name::from_str("some-other-tsig-key").unwrap());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .unwrap();
    let (sig, _) = (&bad_signer as &dyn MessageSigner)
        .sign_message(&message, now as u32)
        .unwrap();
    message.set_signature(sig);

    // TODO(@cpu): add and use a MessageRequestBuilder type?
    // Round-trip the Message bytes into a MessageRequest.
    let bytes = message.to_bytes().unwrap();
    let request =
        Request::from_bytes(bytes, SocketAddr::from(([127, 0, 0, 1], 53)), Protocol::Udp).unwrap();

    let (res, resp_signer) = authority.update(&request).await;

    // The update should have been rejected as not authorized.
    assert_eq!(res, Err(ResponseCode::NotAuth));

    // We should have received a response signer that when invoked, produces an
    // unsigned TSIG RR with the expected TSIG error RCODE.
    let resp_signer = resp_signer.expect("missing expected response signer");
    // We don't need to pass in a response here - it's not used for this error case.
    let Ok(MessageSignature::Tsig(tsig_rr)) = resp_signer.sign(&[]) else {
        panic!("unexpected result from resp_signer");
    };
    let tsig_rr = tsig_rr
        .data()
        .as_dnssec()
        .and_then(DNSSECRData::as_tsig)
        .unwrap();

    // The TSIG RR should be unsigned.
    assert_eq!(tsig_rr.mac(), &[]);
    // The TSIG RR should have the expected TSIG error RCODE.
    assert_eq!(tsig_rr.error(), &Some(TsigError::BadKey));
}

#[cfg(feature = "__dnssec")]
#[tokio::test]
async fn test_update_tsig_invalid_sig() {
    subscribe();

    // Create an authority, configured to allow updates authenticated with a test signer.
    let signer_name = Name::from_str("test-tsig-key").unwrap();
    let mut authority = create_example();
    authority.set_allow_update(true);
    authority.set_tsig_signers(vec![test_tsig_signer(signer_name.clone())]);

    // Now, construct an update message but sign it with a **different** TSIG signer that
    // has a different MAC key but the same key name.
    let new_name = Name::from_str("new.example.com.").unwrap();
    let mut message = test_update_message(new_name.clone());
    let bad_signer = TSigner::new(
        [0_u8; 32].to_vec(),
        TsigAlgorithm::HmacSha256,
        signer_name,
        300,
    )
    .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .unwrap();
    let (sig, _) = (&bad_signer as &dyn MessageSigner)
        .sign_message(&message, now as u32)
        .unwrap();
    message.set_signature(sig);

    // TODO(@cpu): add and use a MessageRequestBuilder type?
    // Round-trip the Message bytes into a MessageRequest.
    let bytes = message.to_bytes().unwrap();
    let request =
        Request::from_bytes(bytes, SocketAddr::from(([127, 0, 0, 1], 53)), Protocol::Udp).unwrap();

    let (res, resp_signer) = authority.update(&request).await;

    // The update should have been rejected as not authorized.
    assert_eq!(res, Err(ResponseCode::NotAuth));

    // We should have received a response signer that when invoked, produces an
    // unsigned TSIG RR with the expected TSIG error RCODE.
    let resp_signer = resp_signer.expect("missing expected response signer");
    // We don't need to pass in a response here - it's not used for this error case.
    let Ok(MessageSignature::Tsig(tsig_rr)) = resp_signer.sign(&[]) else {
        panic!("unexpected result from resp_signer");
    };
    let tsig_rr = tsig_rr
        .data()
        .as_dnssec()
        .and_then(DNSSECRData::as_tsig)
        .unwrap();

    // The TSIG RR should be unsigned.
    assert_eq!(tsig_rr.mac(), &[]);
    // The TSIG RR should have the expected TSIG error RCODE.
    assert_eq!(tsig_rr.error(), &Some(TsigError::BadSig));
}

#[cfg(feature = "__dnssec")]
#[tokio::test]
async fn test_update_tsig_invalid_stale_sig() {
    subscribe();

    // Create an authority, configured to allow updates authenticated with a test signer.
    let signer = test_tsig_signer(Name::from_labels(["test-tsig-key"]).unwrap());
    let mut authority = create_example();
    authority.set_allow_update(true);
    authority.set_tsig_signers(vec![signer.clone()]);

    // Now, construct an update message and sign it with the correct signer, but providing a
    // timestamp that's too far in the past based on the authority signer's fudge value.
    let new_name = Name::from_str("new.example.com.").unwrap();
    let mut message = test_update_message(new_name.clone());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .unwrap();
    let too_stale = now - (signer.fudge() as u64) - 1;
    let (sig, _) = (&signer as &dyn MessageSigner)
        .sign_message(&message, too_stale as u32)
        .unwrap();
    // Save the MAC of the request so we can verify the response.
    let MessageSignature::Tsig(tsig_rr) = sig.clone() else {
        panic!("unexpected message signature type");
    };
    let tsig_rr = tsig_rr
        .data()
        .as_dnssec()
        .and_then(DNSSECRData::as_tsig)
        .unwrap();
    let request_mac = tsig_rr.mac();
    message.set_signature(sig);

    // TODO(@cpu): add and use a MessageRequestBuilder type?
    // Round-trip the Message bytes into a MessageRequest.
    let bytes = message.to_bytes().unwrap();
    let request =
        Request::from_bytes(bytes, SocketAddr::from(([127, 0, 0, 1], 53)), Protocol::Udp).unwrap();

    // The update should have been rejected as not authorized.
    let (resp, resp_signer) = authority.update(&request).await;
    assert_eq!(resp, Err(ResponseCode::NotAuth));

    // We should have produced a resp_signer.
    let resp_signer = resp_signer.expect("missing expected TSIG response signer");

    // Build an initial unsigned response for the update.
    // The catalog handles this in normal operation, but we're testing at the level of the
    // SqliteAuthority and so have to do this ourselves.
    let response = MessageResponseBuilder::new(request.raw_queries(), None);
    let mut response_header = Header::new(request.id(), MessageType::Response, OpCode::Update);
    response_header.set_response_code(ResponseCode::NotAuth);
    let mut response = response.build_no_records(response_header);

    // Serialize the unsigned response to get the TBS bytes to sign with the signer.
    let mut tbs_response_buf = Vec::with_capacity(512);
    let mut encoder = BinEncoder::with_mode(&mut tbs_response_buf, EncodeMode::Normal);
    let mut response_header = Header::new(request.id(), MessageType::Response, OpCode::Update);
    response_header.set_response_code(ResponseCode::NotAuth);
    let tbs_response =
        MessageResponseBuilder::new(request.raw_queries(), None).build_no_records(response_header);
    tbs_response.destructive_emit(&mut encoder).unwrap();

    // Update the response with the produced signature.
    let resp_sig = resp_signer.sign(&tbs_response_buf).unwrap();
    let MessageSignature::Tsig(rr) = resp_sig.clone() else {
        panic!("unexpected response message signature type");
    };
    let tsig_rr = rr
        .data()
        .as_dnssec()
        .and_then(DNSSECRData::as_tsig)
        .unwrap();
    response.set_signature(resp_sig);

    // Serialize the now-signed response.
    let mut response_buf = Vec::with_capacity(512);
    let mut encoder = BinEncoder::with_mode(&mut response_buf, EncodeMode::Normal);
    response.destructive_emit(&mut encoder).unwrap();

    // We should be able to verify the signature and confirm the signing time is within the
    // validity range based on the fudge factor.
    let (_, _, range) = signer
        .verify_message_byte(&response_buf, Some(request_mac), true)
        .unwrap();
    assert!(range.contains(&now));

    // The TSIG RR should indicate the correct TSIG error RCODE based on our
    // request TSIG being expired.
    assert_eq!(tsig_rr.error(), &Some(TsigError::BadTime))
}

#[cfg(feature = "__dnssec")]
fn test_tsig_signer(key_name: Name) -> TSigner {
    // openssl rand -hex 32
    let test_key = vec![
        0x7a, 0xbc, 0x3d, 0x45, 0xf2, 0x01, 0x9e, 0x8b, 0xc5, 0x67, 0x12, 0x34, 0xab, 0xcd, 0xef,
        0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xab, 0xcd,
        0xef, 0x01,
    ];

    TSigner::new(test_key, TsigAlgorithm::HmacSha256, key_name, 300).unwrap()
}

#[cfg(feature = "__dnssec")]
fn test_update_message(name: Name) -> Message {
    let mut q = Query::default();
    q.set_name(name.clone());
    q.set_query_class(DNSClass::IN);
    q.set_query_type(RecordType::SOA);

    let mut add_rec = Record::from_rdata(name, 3600, RData::A(A::new(192, 168, 1, 10)));
    add_rec.set_dns_class(DNSClass::IN);

    let mut message = Message::query();
    message
        .set_op_code(OpCode::Update)
        .add_query(q)
        .add_authority(add_rec);
    message
}

#[cfg(feature = "__dnssec")]
#[tokio::test]
#[allow(clippy::uninlined_format_args)]
async fn test_zone_signing() {
    use hickory_proto::{dnssec::rdata::RRSIG, rr::RecordData};

    subscribe();

    let authority = create_secure_example();

    let results = authority
        .lookup(
            authority.origin(),
            RecordType::AXFR,
            LookupOptions::for_dnssec(true),
        )
        .await
        .unwrap();

    assert!(
        results
            .iter()
            .any(|r| r.record_type() == RecordType::DNSKEY),
        "must contain a DNSKEY"
    );

    let results = authority
        .lookup(
            authority.origin(),
            RecordType::AXFR,
            LookupOptions::for_dnssec(true),
        )
        .await
        .unwrap();

    for record in &results {
        if record.record_type() == RecordType::RRSIG {
            continue;
        }
        if record.record_type() == RecordType::DNSKEY {
            continue;
        }

        let inner_results = authority
            .lookup(
                authority.origin(),
                RecordType::AXFR,
                LookupOptions::for_dnssec(true),
            )
            .await
            .unwrap();

        // validate all records have associated RRSIGs after signing
        assert!(
            inner_results
                .iter()
                .filter_map(|r| {
                    match r.record_type() {
                        RecordType::RRSIG if r.name() == record.name() => {
                            RRSIG::try_borrow(r.data())
                        }
                        _ => None,
                    }
                })
                .any(|rrsig| rrsig.input().type_covered == record.record_type()),
            "record type not covered: {:?}",
            record
        );
    }
}

#[cfg(feature = "__dnssec")]
#[tokio::test]
async fn test_get_nsec() {
    subscribe();
    let name = Name::from_str("zzz.example.com.").unwrap();
    let authority = create_secure_example();
    let lower_name = LowerName::from(name.clone());

    let results = authority
        .get_nsec_records(&lower_name, LookupOptions::for_dnssec(true))
        .await
        .unwrap();

    for record in &results {
        assert!(*record.name() < name);
    }
}

#[tokio::test]
async fn test_journal() {
    subscribe();
    // test that this message can be inserted
    let conn = Connection::open_in_memory().expect("could not create in memory DB");
    let mut journal = Journal::new(conn).unwrap();
    journal.schema_up().unwrap();

    let mut authority = create_example();
    authority.set_journal(journal).await;
    authority.persist_to_journal().await.unwrap();

    let new_name = Name::from_str("new.example.com.").unwrap();
    let delete_name = Name::from_str("www.example.com.").unwrap();
    let new_record =
        Record::from_rdata(new_name.clone(), 0, RData::A(A::new(10, 11, 12, 13))).clone();
    let delete_record =
        Record::from_rdata(delete_name.clone(), 0, RData::A(A::new(93, 184, 215, 14)))
            .set_dns_class(DNSClass::NONE)
            .clone();
    authority
        .update_records(&[new_record.clone(), delete_record], true)
        .await
        .unwrap();

    // assert that the correct set of records is there.
    let new_rrset: Vec<Record> = authority
        .lookup(
            &new_name.clone().into(),
            RecordType::A,
            LookupOptions::default(),
        )
        .await
        .unwrap()
        .iter()
        .cloned()
        .collect();
    assert!(new_rrset.iter().all(|r| *r == new_record));
    let lower_delete_name = LowerName::from(delete_name);

    let delete_rrset = authority
        .lookup(&lower_delete_name, RecordType::A, LookupOptions::default())
        .await
        .unwrap();
    assert!(delete_rrset.was_empty());

    // that record should have been recorded... let's reload the journal and see if we get it.
    let in_memory = InMemoryAuthority::empty(
        authority.origin().clone().into(),
        ZoneType::Primary,
        AxfrPolicy::Deny,
        #[cfg(feature = "__dnssec")]
        Some(NxProofKind::Nsec),
    );

    let mut recovered_authority = SqliteAuthority::new(in_memory, AxfrPolicy::Deny, false, false);
    recovered_authority
        .recover_with_journal(
            authority
                .journal()
                .await
                .as_ref()
                .expect("journal not Some"),
        )
        .await
        .expect("recovery");

    // assert that the correct set of records is there.
    let new_rrset: Vec<Record> = recovered_authority
        .lookup(&new_name.into(), RecordType::A, LookupOptions::default())
        .await
        .unwrap()
        .iter()
        .cloned()
        .collect();
    assert!(new_rrset.iter().all(|r| *r == new_record));

    let delete_rrset = authority
        .lookup(&lower_delete_name, RecordType::A, LookupOptions::default())
        .await
        .unwrap();
    assert!(delete_rrset.was_empty());
}

#[tokio::test]
async fn test_recovery() {
    subscribe();
    // test that this message can be inserted
    let conn = Connection::open_in_memory().expect("could not create in memory DB");
    let mut journal = Journal::new(conn).unwrap();
    journal.schema_up().unwrap();

    let mut authority = create_example();
    authority.set_journal(journal).await;
    authority.persist_to_journal().await.unwrap();

    let journal = authority.journal().await;
    let journal = journal
        .as_ref()
        .expect("test should have associated journal");
    let in_memory = InMemoryAuthority::empty(
        authority.origin().clone().into(),
        ZoneType::Primary,
        AxfrPolicy::Deny,
        #[cfg(feature = "__dnssec")]
        Some(NxProofKind::Nsec),
    );

    let mut recovered_authority = SqliteAuthority::new(in_memory, AxfrPolicy::Deny, false, false);

    recovered_authority
        .recover_with_journal(journal)
        .await
        .expect("recovery");

    assert_eq!(
        recovered_authority.records().await.len(),
        authority.records().await.len()
    );

    assert!(
        recovered_authority
            .soa()
            .await
            .unwrap()
            .iter()
            .zip(authority.soa().await.unwrap().iter())
            .all(|(r1, r2)| r1 == r2)
    );

    let recovered_records = recovered_authority.records().await;
    let records = authority.records().await;

    assert!(recovered_records.iter().all(|(rr_key, rr_set)| {
        let other_rr_set = records
            .get(rr_key)
            .unwrap_or_else(|| panic!("key doesn't exist: {rr_key:?}"));
        rr_set
            .records_without_rrsigs()
            .zip(other_rr_set.records_without_rrsigs())
            .all(|(record, other_record)| {
                record.ttl() == other_record.ttl() && record.data() == other_record.data()
            })
    },));

    assert!(records.iter().all(|(rr_key, rr_set)| {
        let other_rr_set = recovered_records
            .get(rr_key)
            .unwrap_or_else(|| panic!("key doesn't exist: {rr_key:?}"));
        rr_set
            .records_without_rrsigs()
            .zip(other_rr_set.records_without_rrsigs())
            .all(|(record, other_record)| {
                record.ttl() == other_record.ttl() && record.data() == other_record.data()
            })
    }));
}

#[tokio::test]
async fn test_axfr_allow_all() {
    subscribe();
    let mut authority = create_example();
    authority.set_axfr_policy(AxfrPolicy::AllowAll);

    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(Name::from_str("example.com.").unwrap(), RecordType::AXFR),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let result = authority
        .search(&request, LookupOptions::default())
        .await
        .0
        .unwrap();

    // just update this if the count goes up in the authority
    assert_eq!(result.iter().count(), 12);
}

#[tokio::test]
async fn test_axfr_deny_all() {
    subscribe();
    let mut authority = create_example();
    authority.set_axfr_policy(AxfrPolicy::Deny);

    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(Name::from_str("example.com.").unwrap(), RecordType::AXFR),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let err = authority
        .search(&request, LookupOptions::default())
        .await
        .0
        .unwrap_err();
    assert!(matches!(
        err,
        LookupError::ResponseCode(ResponseCode::NotAuth)
    ))
}

#[cfg(feature = "__dnssec")]
#[tokio::test]
async fn test_axfr_deny_unsigned() {
    subscribe();
    let mut authority = create_example();
    authority.set_axfr_policy(AxfrPolicy::AllowSigned);

    let query = LowerQuery::from(Query::query(
        Name::from_str("example.com.").unwrap(),
        RecordType::AXFR,
    ));
    let request = Request::from_message(
        MessageRequest::mock(*TEST_HEADER, query),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let err = authority
        .search(&request, LookupOptions::default())
        .await
        .0
        .unwrap_err();
    assert!(matches!(
        err,
        LookupError::ResponseCode(ResponseCode::NotAuth)
    ))
}

#[tokio::test]
async fn test_axfr_allow_tsig_signed() {
    subscribe();

    let signer = test_tsig_signer(Name::from_str("test-tsig-key").unwrap());

    let mut authority = create_example();
    authority.set_axfr_policy(AxfrPolicy::AllowSigned);
    authority.set_tsig_signers(vec![signer.clone()]);

    let query = Query::query(Name::from_str("example.com.").unwrap(), RecordType::AXFR);
    let mut message = Message::query();
    message.add_query(query);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .unwrap();

    let (sig, _) = (&signer as &dyn MessageSigner)
        .sign_message(&message, now as u32)
        .unwrap();
    message.set_signature(sig);

    // Round-trip the Message bytes into a MessageRequest.
    let bytes = message.to_bytes().unwrap();
    let request =
        Request::from_bytes(bytes, SocketAddr::from(([127, 0, 0, 1], 53)), Protocol::Udp).unwrap();

    let (resp, resp_signer) = authority.search(&request, LookupOptions::default()).await;

    // We should get results back.
    assert_eq!(resp.unwrap().iter().count(), 12);
    // And there should be a signer returned. See `test_update_tsig_valid` for
    // testing that the response signer works as expected - the logic is the same
    // between updates + AXFR.
    assert!(resp_signer.is_some());
}
