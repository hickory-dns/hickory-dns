extern crate rusqlite;
extern crate trust_dns;
extern crate trust_dns_integration;
extern crate trust_dns_server;

use std::collections::BTreeMap;
use std::net::*;

use rusqlite::*;

use trust_dns::rr::*;
use trust_dns::rr::dnssec::*;
use trust_dns::rr::rdata::*;
use trust_dns::op::*;
use trust_dns_server::authority::*;

use trust_dns_integration::authority::{create_example, create_secure_example};

#[test]
fn test_search() {
    let example = create_example();
    let origin = example.origin().clone();

    let mut query: Query = Query::new();
    query.set_name(origin.clone());

    let result = example.search(&query, false, SupportedAlgorithms::new());
    if !result.is_empty() {
        assert_eq!(result.iter().next().unwrap().rr_type(), RecordType::A);
        assert_eq!(result.iter().next().unwrap().dns_class(), DNSClass::IN);
        assert_eq!(
            result.iter().next().unwrap().rdata(),
            &RData::A(Ipv4Addr::new(93, 184, 216, 34))
        );
    } else {
        panic!("expected a result"); // valid panic, in test
    }
}

/// this is a litte more interesting b/c it requires a recursive lookup for the origin
#[test]
fn test_search_www() {
    let example = create_example();
    let www_name = Name::parse("www.example.com.", None).unwrap();

    let mut query: Query = Query::new();
    query.set_name(www_name.clone());

    let result = example.search(&query, false, SupportedAlgorithms::new());
    if !result.is_empty() {
        assert_eq!(result.iter().next().unwrap().rr_type(), RecordType::A);
        assert_eq!(result.iter().next().unwrap().dns_class(), DNSClass::IN);
        assert_eq!(
            result.iter().next().unwrap().rdata(),
            &RData::A(Ipv4Addr::new(93, 184, 216, 34))
        );
    } else {
        panic!("expected a result"); // valid panic, in test
    }
}

#[test]
fn test_authority() {
    let authority: Authority = create_example();

    assert_eq!(
        authority.soa().iter().next().unwrap().dns_class(),
        DNSClass::IN
    );

    assert!(!authority
        .lookup(
            authority.origin(),
            RecordType::NS,
            false,
            SupportedAlgorithms::new()
        )
        .is_empty());

    let mut lookup: Vec<_> = authority.ns(false, SupportedAlgorithms::new()).unwrap();
    lookup.sort();

    assert_eq!(
        **lookup.first().unwrap(),
        Record::new()
            .set_name(authority.origin().clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::NS)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()))
            .clone()
    );
    assert_eq!(
        **lookup.last().unwrap(),
        Record::new()
            .set_name(authority.origin().clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::NS)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()))
            .clone()
    );

    assert!(!authority
        .lookup(
            authority.origin(),
            RecordType::TXT,
            false,
            SupportedAlgorithms::new()
        )
        .is_empty());

    let mut lookup: Vec<_> = authority
        .lookup(
            authority.origin(),
            RecordType::TXT,
            false,
            SupportedAlgorithms::new(),
        )
        .unwrap();
    lookup.sort();

    assert_eq!(
        **lookup.first().unwrap(),
        Record::new()
            .set_name(authority.origin().clone())
            .set_ttl(60)
            .set_rr_type(RecordType::TXT)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::TXT(TXT::new(vec![
                "$Id: example.com 4415 2015-08-24 \
                 20:12:23Z davids $"
                    .to_string(),
            ])))
            .clone()
    );

    assert_eq!(
        *authority
            .lookup(
                authority.origin(),
                RecordType::A,
                false,
                SupportedAlgorithms::new()
            )
            .iter()
            .next()
            .unwrap(),
        Record::new()
            .set_name(authority.origin().clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 34)))
            .clone()
    );
}

#[test]
fn test_authorize() {
    let authority: Authority = create_example();

    let mut message = Message::new();
    message
        .set_id(10)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Update);

    assert_eq!(authority.authorize(&message), Err(ResponseCode::Refused));

    // TODO: this will nee to be more complex as additional policies are added
    // authority.set_allow_update(true);
    // assert!(authority.authorize(&message).is_ok());
}

#[test]
fn test_prerequisites() {
    let not_zone = Name::from_labels(vec!["not", "a", "domain", "com"]);
    let not_in_zone = Name::from_labels(vec!["not", "example", "com"]);

    let mut authority: Authority = create_example();
    authority.set_allow_update(true);

    // first check the initial negatives, ttl = 0, and the zone is the same
    assert_eq!(
        authority.verify_prerequisites(&[
            Record::new()
                .set_name(not_in_zone.clone())
                .set_ttl(86400)
                .set_rr_type(RecordType::A)
                .set_dns_class(DNSClass::IN)
                .set_rdata(RData::NULL(NULL::new()))
                .clone()
        ],),
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority.verify_prerequisites(&[
            Record::new()
                .set_name(not_zone.clone())
                .set_ttl(0)
                .set_rr_type(RecordType::A)
                .set_dns_class(DNSClass::IN)
                .set_rdata(RData::NULL(NULL::new()))
                .clone()
        ],),
        Err(ResponseCode::NotZone)
    );

    // *   ANY      ANY      empty    Name is in use
    assert!(
        authority
            .verify_prerequisites(&[
                Record::new()
                    .set_name(authority.origin().clone())
                    .set_ttl(0)
                    .set_dns_class(DNSClass::ANY)
                    .set_rr_type(RecordType::ANY)
                    .set_rdata(RData::NULL(NULL::new()))
                    .clone()
            ])
            .is_ok()
    );
    assert_eq!(
        authority.verify_prerequisites(&[
            Record::new()
                .set_name(not_in_zone.clone())
                .set_ttl(0)
                .set_dns_class(DNSClass::ANY)
                .set_rr_type(RecordType::ANY)
                .set_rdata(RData::NULL(NULL::new()))
                .clone()
        ],),
        Err(ResponseCode::NXDomain)
    );

    // *   ANY      rrset    empty    RRset exists (value independent)
    assert!(
        authority
            .verify_prerequisites(&[
                Record::new()
                    .set_name(authority.origin().clone())
                    .set_ttl(0)
                    .set_dns_class(DNSClass::ANY)
                    .set_rr_type(RecordType::A)
                    .set_rdata(RData::NULL(NULL::new()))
                    .clone()
            ])
            .is_ok()
    );
    assert_eq!(
        authority.verify_prerequisites(&[
            Record::new()
                .set_name(not_in_zone.clone())
                .set_ttl(0)
                .set_dns_class(DNSClass::ANY)
                .set_rr_type(RecordType::A)
                .set_rdata(RData::NULL(NULL::new()))
                .clone()
        ],),
        Err(ResponseCode::NXRRSet)
    );

    // *   NONE     ANY      empty    Name is not in use
    assert!(
        authority
            .verify_prerequisites(&[
                Record::new()
                    .set_name(not_in_zone.clone())
                    .set_ttl(0)
                    .set_dns_class(DNSClass::NONE)
                    .set_rr_type(RecordType::ANY)
                    .set_rdata(RData::NULL(NULL::new()))
                    .clone()
            ])
            .is_ok()
    );
    assert_eq!(
        authority.verify_prerequisites(&[
            Record::new()
                .set_name(authority.origin().clone())
                .set_ttl(0)
                .set_dns_class(DNSClass::NONE)
                .set_rr_type(RecordType::ANY)
                .set_rdata(RData::NULL(NULL::new()))
                .clone()
        ],),
        Err(ResponseCode::YXDomain)
    );

    // *   NONE     rrset    empty    RRset does not exist
    assert!(
        authority
            .verify_prerequisites(&[
                Record::new()
                    .set_name(not_in_zone.clone())
                    .set_ttl(0)
                    .set_dns_class(DNSClass::NONE)
                    .set_rr_type(RecordType::A)
                    .set_rdata(RData::NULL(NULL::new()))
                    .clone()
            ])
            .is_ok()
    );
    assert_eq!(
        authority.verify_prerequisites(&[
            Record::new()
                .set_name(authority.origin().clone())
                .set_ttl(0)
                .set_dns_class(DNSClass::NONE)
                .set_rr_type(RecordType::A)
                .set_rdata(RData::NULL(NULL::new()))
                .clone()
        ],),
        Err(ResponseCode::YXRRSet)
    );

    // *   zone     rrset    rr       RRset exists (value dependent)
    assert!(
        authority
            .verify_prerequisites(&[
                Record::new()
                    .set_name(authority.origin().clone())
                    .set_ttl(0)
                    .set_dns_class(DNSClass::IN)
                    .set_rr_type(RecordType::A)
                    .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 34)))
                    .clone()
            ])
            .is_ok()
    );
    // wrong class
    assert_eq!(
        authority.verify_prerequisites(&[
            Record::new()
                .set_name(authority.origin().clone())
                .set_ttl(0)
                .set_dns_class(DNSClass::CH)
                .set_rr_type(RecordType::A)
                .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 34)))
                .clone()
        ],),
        Err(ResponseCode::FormErr)
    );
    // wrong Name
    assert_eq!(
        authority.verify_prerequisites(&[
            Record::new()
                .set_name(not_in_zone.clone())
                .set_ttl(0)
                .set_dns_class(DNSClass::IN)
                .set_rr_type(RecordType::A)
                .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
                .clone()
        ],),
        Err(ResponseCode::NXRRSet)
    );
    // wrong IP
    assert_eq!(
        authority.verify_prerequisites(&[
            Record::new()
                .set_name(authority.origin().clone())
                .set_ttl(0)
                .set_dns_class(DNSClass::IN)
                .set_rr_type(RecordType::A)
                .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
                .clone()
        ],),
        Err(ResponseCode::NXRRSet)
    );
}

#[test]
fn test_pre_scan() {
    let up_name = Name::from_labels(vec!["www", "example", "com"]);
    let not_zone = Name::from_labels(vec!["not", "zone", "com"]);

    let authority: Authority = create_example();

    assert_eq!(
        authority.pre_scan(&[
            Record::new()
                .set_name(not_zone.clone())
                .set_ttl(86400)
                .set_rr_type(RecordType::A)
                .set_dns_class(DNSClass::IN)
                .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
                .clone()
        ],),
        Err(ResponseCode::NotZone)
    );

    assert_eq!(
        authority.pre_scan(&[
            Record::new()
                .set_name(up_name.clone())
                .set_ttl(86400)
                .set_rr_type(RecordType::ANY)
                .set_dns_class(DNSClass::IN)
                .set_rdata(RData::NULL(NULL::new()))
                .clone()
        ],),
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority.pre_scan(&[
            Record::new()
                .set_name(up_name.clone())
                .set_ttl(86400)
                .set_rr_type(RecordType::AXFR)
                .set_dns_class(DNSClass::IN)
                .set_rdata(RData::NULL(NULL::new()))
                .clone()
        ],),
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority.pre_scan(&[
            Record::new()
                .set_name(up_name.clone())
                .set_ttl(86400)
                .set_rr_type(RecordType::IXFR)
                .set_dns_class(DNSClass::IN)
                .set_rdata(RData::NULL(NULL::new()))
                .clone()
        ],),
        Err(ResponseCode::FormErr)
    );
    assert!(
        authority
            .pre_scan(&[
                Record::new()
                    .set_name(up_name.clone())
                    .set_ttl(86400)
                    .set_rr_type(RecordType::A)
                    .set_dns_class(DNSClass::IN)
                    .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
                    .clone()
            ])
            .is_ok()
    );
    assert!(
        authority
            .pre_scan(&[
                Record::new()
                    .set_name(up_name.clone())
                    .set_ttl(86400)
                    .set_rr_type(RecordType::A)
                    .set_dns_class(DNSClass::IN)
                    .set_rdata(RData::NULL(NULL::new()))
                    .clone()
            ])
            .is_ok()
    );

    assert_eq!(
        authority.pre_scan(&[
            Record::new()
                .set_name(up_name.clone())
                .set_ttl(86400)
                .set_rr_type(RecordType::A)
                .set_dns_class(DNSClass::ANY)
                .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
                .clone()
        ],),
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority.pre_scan(&[
            Record::new()
                .set_name(up_name.clone())
                .set_ttl(0)
                .set_rr_type(RecordType::A)
                .set_dns_class(DNSClass::ANY)
                .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
                .clone()
        ],),
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority.pre_scan(&[
            Record::new()
                .set_name(up_name.clone())
                .set_ttl(0)
                .set_rr_type(RecordType::AXFR)
                .set_dns_class(DNSClass::ANY)
                .set_rdata(RData::NULL(NULL::new()))
                .clone()
        ],),
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority.pre_scan(&[
            Record::new()
                .set_name(up_name.clone())
                .set_ttl(0)
                .set_rr_type(RecordType::IXFR)
                .set_dns_class(DNSClass::ANY)
                .set_rdata(RData::NULL(NULL::new()))
                .clone()
        ],),
        Err(ResponseCode::FormErr)
    );
    assert!(
        authority
            .pre_scan(&[
                Record::new()
                    .set_name(up_name.clone())
                    .set_ttl(0)
                    .set_rr_type(RecordType::ANY)
                    .set_dns_class(DNSClass::ANY)
                    .set_rdata(RData::NULL(NULL::new()))
                    .clone()
            ])
            .is_ok()
    );
    assert!(
        authority
            .pre_scan(&[
                Record::new()
                    .set_name(up_name.clone())
                    .set_ttl(0)
                    .set_rr_type(RecordType::A)
                    .set_dns_class(DNSClass::ANY)
                    .set_rdata(RData::NULL(NULL::new()))
                    .clone()
            ])
            .is_ok()
    );

    assert_eq!(
        authority.pre_scan(&[
            Record::new()
                .set_name(up_name.clone())
                .set_ttl(86400)
                .set_rr_type(RecordType::A)
                .set_dns_class(DNSClass::NONE)
                .set_rdata(RData::NULL(NULL::new()))
                .clone()
        ],),
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority.pre_scan(&[
            Record::new()
                .set_name(up_name.clone())
                .set_ttl(0)
                .set_rr_type(RecordType::ANY)
                .set_dns_class(DNSClass::NONE)
                .set_rdata(RData::NULL(NULL::new()))
                .clone()
        ],),
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority.pre_scan(&[
            Record::new()
                .set_name(up_name.clone())
                .set_ttl(0)
                .set_rr_type(RecordType::AXFR)
                .set_dns_class(DNSClass::NONE)
                .set_rdata(RData::NULL(NULL::new()))
                .clone()
        ],),
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority.pre_scan(&[
            Record::new()
                .set_name(up_name.clone())
                .set_ttl(0)
                .set_rr_type(RecordType::IXFR)
                .set_dns_class(DNSClass::NONE)
                .set_rdata(RData::NULL(NULL::new()))
                .clone()
        ],),
        Err(ResponseCode::FormErr)
    );
    assert!(
        authority
            .pre_scan(&[
                Record::new()
                    .set_name(up_name.clone())
                    .set_ttl(0)
                    .set_rr_type(RecordType::A)
                    .set_dns_class(DNSClass::NONE)
                    .set_rdata(RData::NULL(NULL::new()))
                    .clone()
            ])
            .is_ok()
    );
    assert!(
        authority
            .pre_scan(&[
                Record::new()
                    .set_name(up_name.clone())
                    .set_ttl(0)
                    .set_rr_type(RecordType::A)
                    .set_dns_class(DNSClass::NONE)
                    .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
                    .clone()
            ])
            .is_ok()
    );

    assert_eq!(
        authority.pre_scan(&[
            Record::new()
                .set_name(up_name.clone())
                .set_ttl(86400)
                .set_rr_type(RecordType::A)
                .set_dns_class(DNSClass::CH)
                .set_rdata(RData::NULL(NULL::new()))
                .clone()
        ],),
        Err(ResponseCode::FormErr)
    );
}

#[test]
fn test_update() {
    let new_name = Name::from_labels(vec!["new", "example", "com"]);
    let www_name = Name::from_labels(vec!["www", "example", "com"]);
    let mut authority: Authority = create_example();
    let serial = authority.serial();

    authority.set_allow_update(true);

    let mut original_vec: Vec<Record> = vec![
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::TXT)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::TXT(TXT::new(vec!["v=spf1 -all".to_string()])))
            .clone(),
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 34)))
            .clone(),
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::AAAA)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::AAAA(Ipv6Addr::new(
                0x2606,
                0x2800,
                0x220,
                0x1,
                0x248,
                0x1893,
                0x25c8,
                0x1946,
            )))
            .clone(),
    ];

    original_vec.sort();

    {
        // assert that the correct set of records is there.
        let mut www_rrset: Vec<&Record> = authority
            .lookup(
                &www_name,
                RecordType::ANY,
                false,
                SupportedAlgorithms::new(),
            )
            .unwrap();
        www_rrset.sort();

        assert_eq!(www_rrset, original_vec.iter().collect::<Vec<&Record>>());

        // assert new record doesn't exist
        assert!(
            authority
                .lookup(
                    &new_name,
                    RecordType::ANY,
                    false,
                    SupportedAlgorithms::new()
                )
                .is_empty()
        );
    }

    //
    //  zone     rrset    rr       Add to an RRset
    let add_record = &[
        Record::new()
            .set_name(new_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
            .clone(),
    ];
    assert!(
        authority
            .update_records(add_record, true,)
            .expect("update failed",)
    );
    assert_eq!(
        authority
            .lookup(
                &new_name,
                RecordType::ANY,
                false,
                SupportedAlgorithms::new()
            )
            .unwrap(),
        add_record.iter().collect::<Vec<&Record>>()
    );
    assert_eq!(serial + 1, authority.serial());

    let add_www_record = &[
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::A(Ipv4Addr::new(10, 0, 0, 1)))
            .clone(),
    ];
    assert!(
        authority
            .update_records(add_www_record, true,)
            .expect("update failed",)
    );
    assert_eq!(serial + 2, authority.serial());

    {
        let mut www_rrset = authority
            .lookup(
                &www_name,
                RecordType::ANY,
                false,
                SupportedAlgorithms::new(),
            )
            .unwrap();
        www_rrset.sort();

        let mut plus_10 = original_vec.clone();
        plus_10.push(add_www_record[0].clone());
        plus_10.sort();
        assert_eq!(www_rrset, plus_10.iter().collect::<Vec<&Record>>());
    }

    //
    //  NONE     rrset    rr       Delete an RR from an RRset
    let del_record = &[
        Record::new()
            .set_name(new_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::NONE)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
            .clone(),
    ];
    assert!(
        authority
            .update_records(del_record, true,)
            .expect("update failed",)
    );
    assert_eq!(serial + 3, authority.serial());
    {
        println!(
            "after delete of specific record: {:?}",
            authority.lookup(
                &new_name,
                RecordType::ANY,
                false,
                SupportedAlgorithms::new(),
            )
        );
        assert!(
            authority
                .lookup(
                    &new_name,
                    RecordType::ANY,
                    false,
                    SupportedAlgorithms::new()
                )
                .is_empty()
        );
    }

    // remove one from www
    let del_record = &[
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::NONE)
            .set_rdata(RData::A(Ipv4Addr::new(10, 0, 0, 1)))
            .clone(),
    ];
    assert!(
        authority
            .update_records(del_record, true,)
            .expect("update failed",)
    );
    assert_eq!(serial + 4, authority.serial());
    {
        let mut www_rrset = authority
            .lookup(
                &www_name,
                RecordType::ANY,
                false,
                SupportedAlgorithms::new(),
            )
            .unwrap();
        www_rrset.sort();

        assert_eq!(www_rrset, original_vec.iter().collect::<Vec<&Record>>());
    }

    //
    //  ANY      rrset    empty    Delete an RRset
    let del_record = &[
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::ANY)
            .set_rdata(RData::NULL(NULL::new()))
            .clone(),
    ];
    assert!(
        authority
            .update_records(del_record, true,)
            .expect("update failed",)
    );
    assert_eq!(serial + 5, authority.serial());
    let mut removed_a_vec: Vec<_> = vec![
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::TXT)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::TXT(TXT::new(vec!["v=spf1 -all".to_string()])))
            .clone(),
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::AAAA)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::AAAA(Ipv6Addr::new(
                0x2606,
                0x2800,
                0x220,
                0x1,
                0x248,
                0x1893,
                0x25c8,
                0x1946,
            )))
            .clone(),
    ];
    removed_a_vec.sort();

    {
        let mut www_rrset = authority
            .lookup(
                &www_name,
                RecordType::ANY,
                false,
                SupportedAlgorithms::new(),
            )
            .unwrap();
        www_rrset.sort();

        assert_eq!(www_rrset, removed_a_vec.iter().collect::<Vec<&Record>>());
    }

    //
    //  ANY      ANY      empty    Delete all RRsets from a name
    println!("deleting all records");
    let del_record = &[
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::ANY)
            .set_dns_class(DNSClass::ANY)
            .set_rdata(RData::NULL(NULL::new()))
            .clone(),
    ];
    assert!(
        authority
            .update_records(del_record, true,)
            .expect("update failed",)
    );
    assert!(
        authority
            .lookup(
                &www_name,
                RecordType::ANY,
                false,
                SupportedAlgorithms::new()
            )
            .is_empty()
    );
    assert_eq!(serial + 6, authority.serial());
}

#[test]
fn test_zone_signing() {
    let authority: Authority = create_secure_example();

    let results = authority.lookup(
        &authority.origin(),
        RecordType::AXFR,
        true,
        SupportedAlgorithms::all(),
    );

    assert!(
        results.iter().any(|r| {
            r.rr_type() == RecordType::DNSSEC(DNSSECRecordType::DNSKEY)
        }),
        "must contain a DNSKEY"
    );

    for record in results.iter() {
        if record.rr_type() == RecordType::DNSSEC(DNSSECRecordType::RRSIG) {
            continue;
        }
        if record.rr_type() == RecordType::DNSSEC(DNSSECRecordType::DNSKEY) {
            continue;
        }

        // validate all records have associated RRSIGs after signing
        assert!(
            results.iter().any(|r| {
                r.rr_type() == RecordType::DNSSEC(DNSSECRecordType::RRSIG)
                    && r.name() == record.name()
                    && if let &RData::DNSSEC(DNSSECRData::SIG(ref rrsig)) = r.rdata() {
                        rrsig.type_covered() == record.rr_type()
                    } else {
                        false
                    }
            }),
            "record type not covered: {:?}",
            record
        );
    }
}

#[test]
fn test_get_nsec() {
    let name = Name::from_labels(vec!["zzz", "example", "com"]);
    let authority: Authority = create_secure_example();

    let results = authority.get_nsec_records(&name, true, SupportedAlgorithms::all());

    for record in results.iter() {
        assert!(record.name() < &name);
    }
}

#[test]
fn test_journal() {
    // test that this message can be inserted
    let conn = Connection::open_in_memory().expect("could not create in memory DB");
    let mut journal = Journal::new(conn).unwrap();
    journal.schema_up().unwrap();

    let mut authority = create_example();
    authority.set_journal(journal);
    authority.persist_to_journal().unwrap();

    let new_name = Name::from_labels(vec!["new", "example", "com"]);
    let delete_name = Name::from_labels(vec!["www", "example", "com"]);
    let new_record = Record::new()
        .set_name(new_name.clone())
        .set_rdata(RData::A(Ipv4Addr::new(10, 11, 12, 13)))
        .clone();
    let delete_record = Record::new()
        .set_name(delete_name.clone())
        .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 34)))
        .set_dns_class(DNSClass::NONE)
        .clone();
    authority
        .update_records(&[new_record.clone(), delete_record], true)
        .unwrap();

    // assert that the correct set of records is there.
    let new_rrset: Vec<&Record> = authority
        .lookup(&new_name, RecordType::A, false, SupportedAlgorithms::new())
        .unwrap();
    assert!(new_rrset.iter().all(|r| *r == &new_record));

    let delete_rrset = authority.lookup(
        &delete_name,
        RecordType::A,
        false,
        SupportedAlgorithms::new(),
    );
    assert!(delete_rrset.is_empty());

    // that record should have been recorded... let's reload the journal and see if we get it.
    let mut recovered_authority = Authority::new(
        authority.origin().clone(),
        BTreeMap::new(),
        ZoneType::Master,
        false,
        false,
    );
    recovered_authority
        .recover_with_journal(authority.journal().expect("journal not Some"))
        .expect("recovery");

    // assert that the correct set of records is there.
    let new_rrset: Vec<&Record> = recovered_authority
        .lookup(&new_name, RecordType::A, false, SupportedAlgorithms::new())
        .unwrap();
    assert!(new_rrset.iter().all(|r| *r == &new_record));

    let delete_rrset = authority.lookup(
        &delete_name,
        RecordType::A,
        false,
        SupportedAlgorithms::new(),
    );
    assert!(delete_rrset.is_empty());
}

#[test]
fn test_recovery() {
    // test that this message can be inserted
    let conn = Connection::open_in_memory().expect("could not create in memory DB");
    let mut journal = Journal::new(conn).unwrap();
    journal.schema_up().unwrap();

    let mut authority = create_example();
    authority.set_journal(journal);
    authority.persist_to_journal().unwrap();

    let journal = authority.journal().unwrap();
    let mut recovered_authority = Authority::new(
        authority.origin().clone(),
        BTreeMap::new(),
        ZoneType::Master,
        false,
        false,
    );

    recovered_authority
        .recover_with_journal(journal)
        .expect("recovery");

    assert_eq!(
        recovered_authority.records().len(),
        authority.records().len()
    );
    assert_eq!(recovered_authority.soa(), authority.soa());
    assert!(recovered_authority.records().iter().all(
        |(rr_key, rr_set)| {
            let other_rr_set = authority
                .records()
                .get(rr_key)
                .expect(&format!("key doesn't exist: {:?}", rr_key));
            rr_set
                .iter()
                .zip(other_rr_set.iter())
                .all(|(record, other_record)| {
                    record.ttl() == other_record.ttl() && record.rdata() == other_record.rdata()
                })
        },
    ));

    assert!(authority.records().iter().all(|(rr_key, rr_set)| {
        let other_rr_set = recovered_authority
            .records()
            .get(rr_key)
            .expect(&format!("key doesn't exist: {:?}", rr_key));
        rr_set
            .iter()
            .zip(other_rr_set.iter())
            .all(|(record, other_record)| {
                record.ttl() == other_record.ttl() && record.rdata() == other_record.rdata()
            })
    }));
}
