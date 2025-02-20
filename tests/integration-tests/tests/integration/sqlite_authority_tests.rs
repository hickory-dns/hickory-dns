#![cfg(feature = "sqlite")]

use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::str::FromStr;

use hickory_proto::rr::LowerName;
use rusqlite::*;

use hickory_proto::op::{Header, LowerQuery, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, NS, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::xfer::Protocol;
use hickory_server::authority::LookupOptions;
use hickory_server::authority::{Authority, ZoneType};
#[cfg(feature = "__dnssec")]
use hickory_server::dnssec::NxProofKind;
use hickory_server::server::RequestInfo;
use hickory_server::store::in_memory::InMemoryAuthority;
use hickory_server::store::sqlite::{Journal, SqliteAuthority};
use test_support::subscribe;

const TEST_HEADER: &Header = &Header::new();

fn create_example() -> SqliteAuthority {
    let authority = hickory_integration::example_authority::create_example();
    SqliteAuthority::new(authority, true, false)
}

#[cfg(feature = "__dnssec")]
fn create_secure_example() -> SqliteAuthority {
    let authority = hickory_integration::example_authority::create_secure_example();
    SqliteAuthority::new(authority, true, true)
}

#[tokio::test]
async fn test_search() {
    subscribe();
    let example = create_example();
    let origin = example.origin().clone();

    let mut query: Query = Query::new();
    query.set_name(origin.into());
    let query = LowerQuery::from(query);
    let request_info = RequestInfo::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let result = example
        .search(request_info, LookupOptions::default())
        .await
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

    let mut query: Query = Query::new();
    query.set_name(www_name);
    let query = LowerQuery::from(query);
    let request_info = RequestInfo::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let result = example
        .search(request_info, LookupOptions::default())
        .await
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
async fn test_authorize() {
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
    use hickory_server::authority::MessageRequest;

    subscribe();

    let authority = create_example();

    let mut message = Message::new();
    message
        .set_id(10)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Update);
    message.add_query(Query::default());

    let bytes = message.to_bytes().unwrap();
    let message = MessageRequest::from_bytes(&bytes).unwrap();

    assert_eq!(
        authority.authorize(&message).await,
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
                .any(|rrsig| rrsig.type_covered() == record.record_type()),
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
        false,
        #[cfg(feature = "__dnssec")]
        Some(NxProofKind::Nsec),
    );

    let mut recovered_authority = SqliteAuthority::new(in_memory, false, false);
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
#[allow(clippy::blocks_in_conditions)]
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
        false,
        #[cfg(feature = "__dnssec")]
        Some(NxProofKind::Nsec),
    );

    let mut recovered_authority = SqliteAuthority::new(in_memory, false, false);

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
            .unwrap_or_else(|| panic!("key doesn't exist: {:?}", rr_key));
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
            .unwrap_or_else(|| panic!("key doesn't exist: {:?}", rr_key));
        rr_set
            .records_without_rrsigs()
            .zip(other_rr_set.records_without_rrsigs())
            .all(|(record, other_record)| {
                record.ttl() == other_record.ttl() && record.data() == other_record.data()
            })
    }));
}

#[tokio::test]
async fn test_axfr() {
    subscribe();
    let mut authority = create_example();
    authority.set_allow_axfr(true);

    let query = LowerQuery::from(Query::query(
        Name::from_str("example.com.").unwrap(),
        RecordType::AXFR,
    ));
    let request_info = RequestInfo::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let result = authority
        .search(request_info, LookupOptions::default())
        .await
        .unwrap();

    // just update this if the count goes up in the authority
    assert_eq!(result.iter().count(), 12);
}

#[tokio::test]
async fn test_refused_axfr() {
    subscribe();
    let mut authority = create_example();
    authority.set_allow_axfr(false);

    let query = LowerQuery::from(Query::query(
        Name::from_str("example.com.").unwrap(),
        RecordType::AXFR,
    ));
    let request_info = RequestInfo::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let result = authority
        .search(request_info, LookupOptions::default())
        .await;

    // just update this if the count goes up in the authority
    assert!(result.unwrap_err().is_refused());
}
