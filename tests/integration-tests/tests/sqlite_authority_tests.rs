extern crate futures;
extern crate rusqlite;
extern crate trust_dns;
extern crate trust_dns_integration;
extern crate trust_dns_server;

use std::net::*;
use std::str::FromStr;

use futures::future::Future;
use futures::executor::block_on;

use rusqlite::*;

use trust_dns::op::*;
use trust_dns::rr::dnssec::*;
use trust_dns::rr::rdata::*;
use trust_dns::rr::*;

use trust_dns_server::authority::{Authority, ZoneType};
use trust_dns_server::store::in_memory::InMemoryAuthority;
use trust_dns_server::store::sqlite::{Journal, SqliteAuthority};

fn create_example() -> SqliteAuthority {
    let authority = trust_dns_integration::authority::create_example();
    SqliteAuthority::new(authority, true, false)
}

#[cfg(feature = "dnssec")]
fn create_secure_example() -> SqliteAuthority {
    let authority = trust_dns_integration::authority::create_secure_example();
    SqliteAuthority::new(authority, true, true)
}

#[test]
fn test_search() {
    let example = create_example();
    let origin = example.origin().clone();

    let mut query: Query = Query::new();
    query.set_name(origin.clone().into());
    let query = LowerQuery::from(query);

    let result = block_on(example
        .search(&query, false, SupportedAlgorithms::new()))
        .unwrap();
    if !result.is_empty() {
        let record = result.iter().next().unwrap();
        assert_eq!(record.rr_type(), RecordType::A);
        assert_eq!(record.dns_class(), DNSClass::IN);
        assert_eq!(record.rdata(), &RData::A(Ipv4Addr::new(93, 184, 216, 34)));
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
    let query = LowerQuery::from(query);

    let result = block_on(example
        .search(&query, false, SupportedAlgorithms::new()))
        .unwrap();
    if !result.is_empty() {
        let record = result.iter().next().unwrap();
        assert_eq!(record.rr_type(), RecordType::A);
        assert_eq!(record.dns_class(), DNSClass::IN);
        assert_eq!(record.rdata(), &RData::A(Ipv4Addr::new(93, 184, 216, 34)));
    } else {
        panic!("expected a result"); // valid panic, in test
    }
}

#[test]
fn test_authority() {
    let authority = create_example();

    assert_eq!(
        block_on(authority
            .soa())
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .dns_class(),
        DNSClass::IN
    );

    assert!(!block_on(authority
        .lookup(
            authority.origin(),
            RecordType::NS,
            false,
            SupportedAlgorithms::new()
        ))
        .unwrap()
        .was_empty());

    let mut lookup: Vec<_> = block_on(authority
        .ns(false, SupportedAlgorithms::new()))
        .unwrap()
        .iter()
        .cloned()
        .collect();
    lookup.sort();

    assert_eq!(
        *lookup.first().unwrap(),
        Record::new()
            .set_name(authority.origin().clone().into())
            .set_ttl(86400)
            .set_rr_type(RecordType::NS)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()))
            .clone()
    );
    assert_eq!(
        *lookup.last().unwrap(),
        Record::new()
            .set_name(authority.origin().clone().into())
            .set_ttl(86400)
            .set_rr_type(RecordType::NS)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()))
            .clone()
    );

    assert!(!block_on(authority
        .lookup(
            authority.origin(),
            RecordType::TXT,
            false,
            SupportedAlgorithms::new()
        ))
        .unwrap()
        .was_empty());

    let mut lookup: Vec<_> = block_on(authority
        .lookup(
            authority.origin(),
            RecordType::TXT,
            false,
            SupportedAlgorithms::new(),
        ))
        .unwrap()
        .iter()
        .cloned()
        .collect();
    lookup.sort();

    assert_eq!(
        *lookup.first().unwrap(),
        Record::new()
            .set_name(authority.origin().clone().into())
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
        *block_on(authority
            .lookup(
                authority.origin(),
                RecordType::A,
                false,
                SupportedAlgorithms::new()
            ))
            .unwrap()
            .iter()
            .next()
            .unwrap(),
        Record::new()
            .set_name(authority.origin().clone().into())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 34)))
            .clone()
    );
}

#[cfg(feature = "dnssec")]
#[test]
fn test_authorize() {
    use trust_dns::serialize::binary::{BinDecodable, BinEncodable};
    use trust_dns_server::authority::MessageRequest;

    let authority = create_example();

    let mut message = Message::new();
    message
        .set_id(10)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Update);

    let bytes = message.to_bytes().unwrap();
    let message = MessageRequest::from_bytes(&bytes).unwrap();

    assert_eq!(authority.authorize(&message), Err(ResponseCode::Refused));

    // TODO: this will nee to be more complex as additional policies are added
    // authority.set_allow_update(true);
    // assert!(authority.authorize(&message).is_ok());
}

#[test]
fn test_prerequisites() {
    let not_zone = Name::from_str("not.a.domain.com").unwrap();
    let not_in_zone = Name::from_str("not.example.com").unwrap();

    let mut authority = create_example();
    authority.set_allow_update(true);

    // first check the initial negatives, ttl = 0, and the zone is the same
    assert_eq!(
        authority.verify_prerequisites(&[Record::new()
            .set_name(not_in_zone.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()],),
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority.verify_prerequisites(&[Record::new()
            .set_name(not_zone.clone())
            .set_ttl(0)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()],),
        Err(ResponseCode::NotZone)
    );

    // *   ANY      ANY      empty    Name is in use
    assert!(authority
        .verify_prerequisites(&[Record::new()
            .set_name(authority.origin().clone().into())
            .set_ttl(0)
            .set_dns_class(DNSClass::ANY)
            .set_rr_type(RecordType::ANY)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()])
        .is_ok());
    assert_eq!(
        authority.verify_prerequisites(&[Record::new()
            .set_name(not_in_zone.clone())
            .set_ttl(0)
            .set_dns_class(DNSClass::ANY)
            .set_rr_type(RecordType::ANY)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()],),
        Err(ResponseCode::NXDomain)
    );

    // *   ANY      rrset    empty    RRset exists (value independent)
    assert!(authority
        .verify_prerequisites(&[Record::new()
            .set_name(authority.origin().clone().into())
            .set_ttl(0)
            .set_dns_class(DNSClass::ANY)
            .set_rr_type(RecordType::A)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()])
        .is_ok());
    assert_eq!(
        authority.verify_prerequisites(&[Record::new()
            .set_name(not_in_zone.clone())
            .set_ttl(0)
            .set_dns_class(DNSClass::ANY)
            .set_rr_type(RecordType::A)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()],),
        Err(ResponseCode::NXRRSet)
    );

    // *   NONE     ANY      empty    Name is not in use
    assert!(authority
        .verify_prerequisites(&[Record::new()
            .set_name(not_in_zone.clone())
            .set_ttl(0)
            .set_dns_class(DNSClass::NONE)
            .set_rr_type(RecordType::ANY)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()])
        .is_ok());
    assert_eq!(
        authority.verify_prerequisites(&[Record::new()
            .set_name(authority.origin().clone().into())
            .set_ttl(0)
            .set_dns_class(DNSClass::NONE)
            .set_rr_type(RecordType::ANY)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()],),
        Err(ResponseCode::YXDomain)
    );

    // *   NONE     rrset    empty    RRset does not exist
    assert!(authority
        .verify_prerequisites(&[Record::new()
            .set_name(not_in_zone.clone())
            .set_ttl(0)
            .set_dns_class(DNSClass::NONE)
            .set_rr_type(RecordType::A)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()])
        .is_ok());
    assert_eq!(
        authority.verify_prerequisites(&[Record::new()
            .set_name(authority.origin().clone().into())
            .set_ttl(0)
            .set_dns_class(DNSClass::NONE)
            .set_rr_type(RecordType::A)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()],),
        Err(ResponseCode::YXRRSet)
    );

    // *   zone     rrset    rr       RRset exists (value dependent)
    assert!(authority
        .verify_prerequisites(&[Record::new()
            .set_name(authority.origin().clone().into())
            .set_ttl(0)
            .set_dns_class(DNSClass::IN)
            .set_rr_type(RecordType::A)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 34)))
            .clone()])
        .is_ok());
    // wrong class
    assert_eq!(
        authority.verify_prerequisites(&[Record::new()
            .set_name(authority.origin().clone().into())
            .set_ttl(0)
            .set_dns_class(DNSClass::CH)
            .set_rr_type(RecordType::A)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 34)))
            .clone()],),
        Err(ResponseCode::FormErr)
    );
    // wrong Name
    assert_eq!(
        authority.verify_prerequisites(&[Record::new()
            .set_name(not_in_zone.clone())
            .set_ttl(0)
            .set_dns_class(DNSClass::IN)
            .set_rr_type(RecordType::A)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
            .clone()],),
        Err(ResponseCode::NXRRSet)
    );
    // wrong IP
    assert_eq!(
        authority.verify_prerequisites(&[Record::new()
            .set_name(authority.origin().clone().into())
            .set_ttl(0)
            .set_dns_class(DNSClass::IN)
            .set_rr_type(RecordType::A)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
            .clone()],),
        Err(ResponseCode::NXRRSet)
    );
}

#[test]
fn test_pre_scan() {
    let up_name = Name::from_str("www.example.com").unwrap();
    let not_zone = Name::from_str("not.zone.com").unwrap();

    let authority = create_example();

    assert_eq!(
        authority.pre_scan(&[Record::new()
            .set_name(not_zone.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
            .clone()],),
        Err(ResponseCode::NotZone)
    );

    assert_eq!(
        authority.pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::ANY)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()],),
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority.pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::AXFR)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()],),
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority.pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::IXFR)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()],),
        Err(ResponseCode::FormErr)
    );
    assert!(authority
        .pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
            .clone()])
        .is_ok());
    assert!(authority
        .pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()])
        .is_ok());

    assert_eq!(
        authority.pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::ANY)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
            .clone()],),
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority.pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(0)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::ANY)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
            .clone()],),
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority.pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(0)
            .set_rr_type(RecordType::AXFR)
            .set_dns_class(DNSClass::ANY)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()],),
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority.pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(0)
            .set_rr_type(RecordType::IXFR)
            .set_dns_class(DNSClass::ANY)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()],),
        Err(ResponseCode::FormErr)
    );
    assert!(authority
        .pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(0)
            .set_rr_type(RecordType::ANY)
            .set_dns_class(DNSClass::ANY)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()])
        .is_ok());
    assert!(authority
        .pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(0)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::ANY)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()])
        .is_ok());

    assert_eq!(
        authority.pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::NONE)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()],),
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority.pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(0)
            .set_rr_type(RecordType::ANY)
            .set_dns_class(DNSClass::NONE)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()],),
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority.pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(0)
            .set_rr_type(RecordType::AXFR)
            .set_dns_class(DNSClass::NONE)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()],),
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority.pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(0)
            .set_rr_type(RecordType::IXFR)
            .set_dns_class(DNSClass::NONE)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()],),
        Err(ResponseCode::FormErr)
    );
    assert!(authority
        .pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(0)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::NONE)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()])
        .is_ok());
    assert!(authority
        .pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(0)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::NONE)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
            .clone()])
        .is_ok());

    assert_eq!(
        authority.pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::CH)
            .set_rdata(RData::NULL(NULL::new()))
            .clone()],),
        Err(ResponseCode::FormErr)
    );
}

#[test]
fn test_update() {
    let new_name = Name::from_str("new.example.com").unwrap();
    let www_name = Name::from_str("www.example.com").unwrap();
    let mut authority = create_example();
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
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            )))
            .clone(),
    ];

    original_vec.sort();

    {
        // assert that the correct set of records is there.
        let mut www_rrset: Vec<Record> = block_on(authority
            .lookup(
                &www_name.clone().into(),
                RecordType::ANY,
                false,
                SupportedAlgorithms::new(),
            ))
            .unwrap()
            .iter()
            .cloned()
            .collect();
        www_rrset.sort();

        assert_eq!(www_rrset, original_vec);

        // assert new record doesn't exist
        assert!(block_on(authority
            .lookup(
                &new_name.clone().into(),
                RecordType::ANY,
                false,
                SupportedAlgorithms::new()
            ))
            .unwrap()
            .was_empty());
    }

    //
    //  zone     rrset    rr       Add to an RRset
    let add_record = &[Record::new()
        .set_name(new_name.clone())
        .set_ttl(86400)
        .set_rr_type(RecordType::A)
        .set_dns_class(DNSClass::IN)
        .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
        .clone()];
    assert!(authority
        .update_records(add_record, true,)
        .expect("update failed",));
    assert_eq!(block_on(
        authority
            .lookup(
                &new_name.clone().into(),
                RecordType::ANY,
                false,
                SupportedAlgorithms::new()
            ))
            .unwrap()
            .iter()
            .collect::<Vec<_>>(),
        add_record.iter().collect::<Vec<&Record>>()
    );
    assert_eq!(serial + 1, authority.serial());

    let add_www_record = &[Record::new()
        .set_name(www_name.clone())
        .set_ttl(86400)
        .set_rr_type(RecordType::A)
        .set_dns_class(DNSClass::IN)
        .set_rdata(RData::A(Ipv4Addr::new(10, 0, 0, 1)))
        .clone()];
    assert!(authority
        .update_records(add_www_record, true,)
        .expect("update failed",));
    assert_eq!(serial + 2, authority.serial());

    {
        let mut www_rrset: Vec<_> = block_on(authority
            .lookup(
                &www_name.clone().into(),
                RecordType::ANY,
                false,
                SupportedAlgorithms::new(),
            ))
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
    let del_record = &[Record::new()
        .set_name(new_name.clone())
        .set_ttl(86400)
        .set_rr_type(RecordType::A)
        .set_dns_class(DNSClass::NONE)
        .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
        .clone()];
    assert!(authority
        .update_records(del_record, true,)
        .expect("update failed",));
    assert_eq!(serial + 3, authority.serial());
    {
        let lookup = block_on(authority
            .lookup(
                &new_name.into(),
                RecordType::ANY,
                false,
                SupportedAlgorithms::new()
            ))
            .unwrap();

        println!(
            "after delete of specific record: {:?}",
            lookup
        );
        assert!(lookup.was_empty());
    }

    // remove one from www
    let del_record = &[Record::new()
        .set_name(www_name.clone())
        .set_ttl(86400)
        .set_rr_type(RecordType::A)
        .set_dns_class(DNSClass::NONE)
        .set_rdata(RData::A(Ipv4Addr::new(10, 0, 0, 1)))
        .clone()];
    assert!(authority
        .update_records(del_record, true,)
        .expect("update failed",));
    assert_eq!(serial + 4, authority.serial());
    {
        let mut www_rrset: Vec<_> = block_on(authority
            .lookup(
                &www_name.clone().into(),
                RecordType::ANY,
                false,
                SupportedAlgorithms::new(),
            ))
            .unwrap()
            .iter()
            .cloned()
            .collect();
        www_rrset.sort();

        assert_eq!(www_rrset, original_vec);
    }

    //
    //  ANY      rrset    empty    Delete an RRset
    let del_record = &[Record::new()
        .set_name(www_name.clone())
        .set_ttl(86400)
        .set_rr_type(RecordType::A)
        .set_dns_class(DNSClass::ANY)
        .set_rdata(RData::NULL(NULL::new()))
        .clone()];
    assert!(authority
        .update_records(del_record, true,)
        .expect("update failed",));
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
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            )))
            .clone(),
    ];
    removed_a_vec.sort();

    {
        let mut www_rrset: Vec<Record> = block_on(authority
            .lookup(
                &www_name.clone().into(),
                RecordType::ANY,
                false,
                SupportedAlgorithms::new(),
            ))
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
    let del_record = &[Record::new()
        .set_name(www_name.clone())
        .set_ttl(86400)
        .set_rr_type(RecordType::ANY)
        .set_dns_class(DNSClass::ANY)
        .set_rdata(RData::NULL(NULL::new()))
        .clone()];
    
    assert!(authority
        .update_records(del_record, true,)
        .expect("update failed",));
    
    assert!(block_on(authority
        .lookup(
            &www_name.into(),
            RecordType::ANY,
            false,
            SupportedAlgorithms::new()
        ))
        .unwrap()
        .was_empty());
    
    assert_eq!(serial + 6, authority.serial());
}

#[cfg(feature = "dnssec")]
#[test]
fn test_zone_signing() {
    let authority = create_secure_example();

    let results = authority
        .lookup(
            &authority.origin(),
            RecordType::AXFR,
            true,
            SupportedAlgorithms::all(),
        )
        .wait()
        .unwrap();

    assert!(
        results
            .iter()
            .any(|r| r.rr_type() == RecordType::DNSSEC(DNSSECRecordType::DNSKEY)),
        "must contain a DNSKEY"
    );

    let results = authority
        .lookup(
            &authority.origin(),
            RecordType::AXFR,
            true,
            SupportedAlgorithms::all(),
        )
        .wait()
        .unwrap();

    for record in &results {
        if record.rr_type() == RecordType::DNSSEC(DNSSECRecordType::RRSIG) {
            continue;
        }
        if record.rr_type() == RecordType::DNSSEC(DNSSECRecordType::DNSKEY) {
            continue;
        }

        let inner_results = authority
            .lookup(
                &authority.origin(),
                RecordType::AXFR,
                true,
                SupportedAlgorithms::all(),
            )
            .wait()
            .unwrap();

        // validate all records have associated RRSIGs after signing
        assert!(
            inner_results.iter().any(|r| r.rr_type()
                == RecordType::DNSSEC(DNSSECRecordType::RRSIG)
                && r.name() == record.name()
                && if let RData::DNSSEC(DNSSECRData::SIG(ref rrsig)) = *r.rdata() {
                    rrsig.type_covered() == record.rr_type()
                } else {
                    false
                }),
            "record type not covered: {:?}",
            record
        );
    }
}

#[cfg(feature = "dnssec")]
#[test]
fn test_get_nsec() {
    let name = Name::from_str("zzz.example.com").unwrap();
    let authority = create_secure_example();
    let lower_name = LowerName::from(name.clone());

    let results = authority
        .get_nsec_records(&lower_name, true, SupportedAlgorithms::all())
        .wait()
        .unwrap();

    for record in &results {
        assert!(*record.name() < name);
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

    let new_name = Name::from_str("new.example.com").unwrap();
    let delete_name = Name::from_str("www.example.com").unwrap();
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
    let new_rrset: Vec<Record> = block_on(authority
        .lookup(
            &new_name.clone().into(),
            RecordType::A,
            false,
            SupportedAlgorithms::new(),
        ))
        .unwrap()
        .iter()
        .cloned()
        .collect();
    assert!(new_rrset.iter().all(|r| *r == new_record));
    let lower_delete_name = LowerName::from(delete_name.clone());

    let delete_rrset = block_on(authority
        .lookup(
            &lower_delete_name,
            RecordType::A,
            false,
            SupportedAlgorithms::new(),
        ))
        .unwrap();
    assert!(delete_rrset.was_empty());

    // that record should have been recorded... let's reload the journal and see if we get it.
    let in_memory =
        InMemoryAuthority::empty(authority.origin().clone().into(), ZoneType::Master, false);

    let mut recovered_authority = SqliteAuthority::new(in_memory, false, false);
    recovered_authority
        .recover_with_journal(authority.journal().expect("journal not Some"))
        .expect("recovery");

    // assert that the correct set of records is there.
    let new_rrset: Vec<Record> = block_on(recovered_authority
        .lookup(
            &new_name.into(),
            RecordType::A,
            false,
            SupportedAlgorithms::new(),
        ))
        .unwrap()
        .iter()
        .cloned()
        .collect();
    assert!(new_rrset.iter().all(|r| *r == new_record));

    let delete_rrset = block_on(authority
        .lookup(
            &lower_delete_name,
            RecordType::A,
            false,
            SupportedAlgorithms::new(),
        ))
        .unwrap();
    assert!(delete_rrset.was_empty());
}

#[test]
#[allow(clippy::block_in_if_condition_stmt)]
fn test_recovery() {
    // test that this message can be inserted
    let conn = Connection::open_in_memory().expect("could not create in memory DB");
    let mut journal = Journal::new(conn).unwrap();
    journal.schema_up().unwrap();

    let mut authority = create_example();
    authority.set_journal(journal);
    authority.persist_to_journal().unwrap();

    let journal = authority.journal().unwrap();
    let in_memory =
        InMemoryAuthority::empty(authority.origin().clone().into(), ZoneType::Master, false);

    let mut recovered_authority = SqliteAuthority::new(in_memory, false, false);

    recovered_authority
        .recover_with_journal(journal)
        .expect("recovery");

    assert_eq!(
        recovered_authority.records().len(),
        authority.records().len()
    );
    
    assert!(block_on(recovered_authority
        .soa())
        .unwrap()
        .iter()
        .zip(block_on(authority.soa()).unwrap().iter())
        .all(|(r1, r2)| r1 == r2));
    
    assert!(recovered_authority
        .records()
        .iter()
        .all(|(rr_key, rr_set)| {
            let other_rr_set = authority
                .records()
                .get(rr_key)
                .unwrap_or_else(|| panic!("key doesn't exist: {:?}", rr_key));
            rr_set
                .records_without_rrsigs()
                .zip(other_rr_set.records_without_rrsigs())
                .all(|(record, other_record)| {
                    record.ttl() == other_record.ttl() && record.rdata() == other_record.rdata()
                })
        },));

    assert!(authority.records().iter().all(|(rr_key, rr_set)| {
        let other_rr_set = recovered_authority
            .records()
            .get(rr_key)
            .unwrap_or_else(|| panic!("key doesn't exist: {:?}", rr_key));
        rr_set
            .records_without_rrsigs()
            .zip(other_rr_set.records_without_rrsigs())
            .all(|(record, other_record)| {
                record.ttl() == other_record.ttl() && record.rdata() == other_record.rdata()
            })
    }));
}

#[test]
fn test_axfr() {
    let mut authority = create_example();
    authority.set_allow_axfr(true);

    // query: &'q LowerQuery,
    //         is_secure: bool,
    //         supported_algorithms: SupportedAlgorithms,

    let query = LowerQuery::from(Query::query(
        Name::from_str("example.com.").unwrap(),
        RecordType::AXFR,
    ));
    let result = block_on(authority
        .search(&query, false, SupportedAlgorithms::new()))
        .unwrap();

    // just update this if the count goes up in the authority
    assert_eq!(result.iter().count(), 12);
}

#[test]
fn test_refused_axfr() {
    let mut authority = create_example();
    authority.set_allow_axfr(false);

    let query = LowerQuery::from(Query::query(
        Name::from_str("example.com.").unwrap(),
        RecordType::AXFR,
    ));
    let result = block_on(authority
        .search(&query, false, SupportedAlgorithms::new()));

    // just update this if the count goes up in the authority
    assert!(result.unwrap_err().is_refused());
}
