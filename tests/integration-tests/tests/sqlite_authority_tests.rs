#![cfg(feature = "sqlite")]

use std::net::*;
use std::str::FromStr;

use rusqlite::*;

use trust_dns_client::op::*;
use trust_dns_client::rr::dnssec::*;
use trust_dns_client::rr::rdata::*;
use trust_dns_client::rr::*;

use trust_dns_server::authority::LookupOptions;
use trust_dns_server::authority::{Authority, ZoneType};
use trust_dns_server::server::Protocol;
use trust_dns_server::server::RequestInfo;
use trust_dns_server::store::in_memory::InMemoryAuthority;
use trust_dns_server::store::sqlite::{Journal, SqliteAuthority};

const TEST_HEADER: &Header = &Header::new();

fn create_example() -> SqliteAuthority {
    let authority = trust_dns_integration::example_authority::create_example();
    SqliteAuthority::new(authority, true, false)
}

#[cfg(feature = "dnssec")]
fn create_secure_example() -> SqliteAuthority {
    let authority = trust_dns_integration::example_authority::create_secure_example();
    SqliteAuthority::new(authority, true, true)
}

#[tokio::test]
async fn test_search() {
    let example = create_example();
    let origin = example.origin().clone();

    let mut query: Query = Query::new();
    query.set_name(origin.into());
    let query = LowerQuery::from(query);
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
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
        assert_eq!(record.rr_type(), RecordType::A);
        assert_eq!(record.dns_class(), DNSClass::IN);
        assert_eq!(
            record.data().unwrap(),
            &RData::A(Ipv4Addr::new(93, 184, 216, 34))
        );
    } else {
        panic!("expected a result"); // valid panic, in test
    }
}

/// this is a litte more interesting b/c it requires a recursive lookup for the origin
#[tokio::test]
async fn test_search_www() {
    let example = create_example();
    let www_name = Name::parse("www.example.com.", None).unwrap();

    let mut query: Query = Query::new();
    query.set_name(www_name);
    let query = LowerQuery::from(query);
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
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
        assert_eq!(record.rr_type(), RecordType::A);
        assert_eq!(record.dns_class(), DNSClass::IN);
        assert_eq!(
            record.data().unwrap(),
            &RData::A(Ipv4Addr::new(93, 184, 216, 34))
        );
    } else {
        panic!("expected a result"); // valid panic, in test
    }
}

#[tokio::test]
async fn test_authority() {
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

    assert!(!authority
        .lookup(authority.origin(), RecordType::NS, LookupOptions::default())
        .await
        .unwrap()
        .was_empty());

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
        Record::new()
            .set_name(authority.origin().clone().into())
            .set_ttl(86400)
            .set_rr_type(RecordType::NS)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::NS(
                Name::parse("a.iana-servers.net.", None).unwrap()
            )))
            .clone()
    );
    assert_eq!(
        *lookup.last().unwrap(),
        Record::new()
            .set_name(authority.origin().clone().into())
            .set_ttl(86400)
            .set_rr_type(RecordType::NS)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::NS(
                Name::parse("b.iana-servers.net.", None).unwrap()
            )))
            .clone()
    );

    assert!(!authority
        .lookup(
            authority.origin(),
            RecordType::TXT,
            LookupOptions::default()
        )
        .await
        .unwrap()
        .was_empty());

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
        Record::new()
            .set_name(authority.origin().clone().into())
            .set_ttl(60)
            .set_rr_type(RecordType::TXT)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::TXT(TXT::new(vec![
                "$Id: example.com 4415 2015-08-24 \
                 20:12:23Z davids $"
                    .to_string(),
            ]))))
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
        Record::new()
            .set_name(authority.origin().clone().into())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::A(Ipv4Addr::new(93, 184, 216, 34))))
            .clone()
    );
}

#[cfg(feature = "dnssec")]
#[tokio::test]
async fn test_authorize() {
    use trust_dns_client::serialize::binary::{BinDecodable, BinEncodable};
    use trust_dns_server::authority::MessageRequest;

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
    let not_zone = Name::from_str("not.a.domain.com").unwrap();
    let not_in_zone = Name::from_str("not.example.com").unwrap();

    let mut authority = create_example();
    authority.set_allow_update(true);

    // first check the initial negatives, ttl = 0, and the zone is the same
    assert_eq!(
        authority
            .verify_prerequisites(&[Record::new()
                .set_name(not_in_zone.clone())
                .set_ttl(86400)
                .set_rr_type(RecordType::A)
                .set_dns_class(DNSClass::IN)
                .set_data(Some(RData::NULL(NULL::new())))
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority
            .verify_prerequisites(&[Record::new()
                .set_name(not_zone)
                .set_ttl(0)
                .set_rr_type(RecordType::A)
                .set_dns_class(DNSClass::IN)
                .set_data(Some(RData::NULL(NULL::new())))
                .clone()],)
            .await,
        Err(ResponseCode::NotZone)
    );

    // *   ANY      ANY      empty    Name is in use
    assert!(authority
        .verify_prerequisites(&[Record::new()
            .set_name(authority.origin().clone().into())
            .set_ttl(0)
            .set_dns_class(DNSClass::ANY)
            .set_rr_type(RecordType::ANY)
            .set_data(Some(RData::NULL(NULL::new())))
            .clone()])
        .await
        .is_ok());
    assert_eq!(
        authority
            .verify_prerequisites(&[Record::new()
                .set_name(not_in_zone.clone())
                .set_ttl(0)
                .set_dns_class(DNSClass::ANY)
                .set_rr_type(RecordType::ANY)
                .set_data(Some(RData::NULL(NULL::new())))
                .clone()],)
            .await,
        Err(ResponseCode::NXDomain)
    );

    // *   ANY      rrset    empty    RRset exists (value independent)
    assert!(authority
        .verify_prerequisites(&[Record::new()
            .set_name(authority.origin().clone().into())
            .set_ttl(0)
            .set_dns_class(DNSClass::ANY)
            .set_rr_type(RecordType::A)
            .set_data(Some(RData::NULL(NULL::new())))
            .clone()])
        .await
        .is_ok());
    assert_eq!(
        authority
            .verify_prerequisites(&[Record::new()
                .set_name(not_in_zone.clone())
                .set_ttl(0)
                .set_dns_class(DNSClass::ANY)
                .set_rr_type(RecordType::A)
                .set_data(Some(RData::NULL(NULL::new())))
                .clone()],)
            .await,
        Err(ResponseCode::NXRRSet)
    );

    // *   NONE     ANY      empty    Name is not in use
    assert!(authority
        .verify_prerequisites(&[Record::new()
            .set_name(not_in_zone.clone())
            .set_ttl(0)
            .set_dns_class(DNSClass::NONE)
            .set_rr_type(RecordType::ANY)
            .set_data(Some(RData::NULL(NULL::new())))
            .clone()])
        .await
        .is_ok());
    assert_eq!(
        authority
            .verify_prerequisites(&[Record::new()
                .set_name(authority.origin().clone().into())
                .set_ttl(0)
                .set_dns_class(DNSClass::NONE)
                .set_rr_type(RecordType::ANY)
                .set_data(Some(RData::NULL(NULL::new())))
                .clone()],)
            .await,
        Err(ResponseCode::YXDomain)
    );

    // *   NONE     rrset    empty    RRset does not exist
    assert!(authority
        .verify_prerequisites(&[Record::new()
            .set_name(not_in_zone.clone())
            .set_ttl(0)
            .set_dns_class(DNSClass::NONE)
            .set_rr_type(RecordType::A)
            .set_data(Some(RData::NULL(NULL::new())))
            .clone()])
        .await
        .is_ok());
    assert_eq!(
        authority
            .verify_prerequisites(&[Record::new()
                .set_name(authority.origin().clone().into())
                .set_ttl(0)
                .set_dns_class(DNSClass::NONE)
                .set_rr_type(RecordType::A)
                .set_data(Some(RData::NULL(NULL::new())))
                .clone()],)
            .await,
        Err(ResponseCode::YXRRSet)
    );

    // *   zone     rrset    rr       RRset exists (value dependent)
    assert!(authority
        .verify_prerequisites(&[Record::new()
            .set_name(authority.origin().clone().into())
            .set_ttl(0)
            .set_dns_class(DNSClass::IN)
            .set_rr_type(RecordType::A)
            .set_data(Some(RData::A(Ipv4Addr::new(93, 184, 216, 34))))
            .clone()])
        .await
        .is_ok());
    // wrong class
    assert_eq!(
        authority
            .verify_prerequisites(&[Record::new()
                .set_name(authority.origin().clone().into())
                .set_ttl(0)
                .set_dns_class(DNSClass::CH)
                .set_rr_type(RecordType::A)
                .set_data(Some(RData::A(Ipv4Addr::new(93, 184, 216, 34))))
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    // wrong Name
    assert_eq!(
        authority
            .verify_prerequisites(&[Record::new()
                .set_name(not_in_zone)
                .set_ttl(0)
                .set_dns_class(DNSClass::IN)
                .set_rr_type(RecordType::A)
                .set_data(Some(RData::A(Ipv4Addr::new(93, 184, 216, 24))))
                .clone()],)
            .await,
        Err(ResponseCode::NXRRSet)
    );
    // wrong IP
    assert_eq!(
        authority
            .verify_prerequisites(&[Record::new()
                .set_name(authority.origin().clone().into())
                .set_ttl(0)
                .set_dns_class(DNSClass::IN)
                .set_rr_type(RecordType::A)
                .set_data(Some(RData::A(Ipv4Addr::new(93, 184, 216, 24))))
                .clone()],)
            .await,
        Err(ResponseCode::NXRRSet)
    );
}

#[tokio::test]
async fn test_pre_scan() {
    let up_name = Name::from_str("www.example.com").unwrap();
    let not_zone = Name::from_str("not.zone.com").unwrap();

    let authority = create_example();

    assert_eq!(
        authority
            .pre_scan(&[Record::new()
                .set_name(not_zone)
                .set_ttl(86400)
                .set_rr_type(RecordType::A)
                .set_dns_class(DNSClass::IN)
                .set_data(Some(RData::A(Ipv4Addr::new(93, 184, 216, 24))))
                .clone()],)
            .await,
        Err(ResponseCode::NotZone)
    );

    assert_eq!(
        authority
            .pre_scan(&[Record::new()
                .set_name(up_name.clone())
                .set_ttl(86400)
                .set_rr_type(RecordType::ANY)
                .set_dns_class(DNSClass::IN)
                .set_data(Some(RData::NULL(NULL::new())))
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority
            .pre_scan(&[Record::new()
                .set_name(up_name.clone())
                .set_ttl(86400)
                .set_rr_type(RecordType::AXFR)
                .set_dns_class(DNSClass::IN)
                .set_data(Some(RData::NULL(NULL::new())))
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority
            .pre_scan(&[Record::new()
                .set_name(up_name.clone())
                .set_ttl(86400)
                .set_rr_type(RecordType::IXFR)
                .set_dns_class(DNSClass::IN)
                .set_data(Some(RData::NULL(NULL::new())))
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert!(authority
        .pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::A(Ipv4Addr::new(93, 184, 216, 24))))
            .clone()])
        .await
        .is_ok());
    assert!(authority
        .pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::NULL(NULL::new())))
            .clone()])
        .await
        .is_ok());

    assert_eq!(
        authority
            .pre_scan(&[Record::new()
                .set_name(up_name.clone())
                .set_ttl(86400)
                .set_rr_type(RecordType::A)
                .set_dns_class(DNSClass::ANY)
                .set_data(Some(RData::A(Ipv4Addr::new(93, 184, 216, 24))))
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority
            .pre_scan(&[Record::new()
                .set_name(up_name.clone())
                .set_ttl(0)
                .set_rr_type(RecordType::A)
                .set_dns_class(DNSClass::ANY)
                .set_data(Some(RData::A(Ipv4Addr::new(93, 184, 216, 24))))
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority
            .pre_scan(&[Record::new()
                .set_name(up_name.clone())
                .set_ttl(0)
                .set_rr_type(RecordType::AXFR)
                .set_dns_class(DNSClass::ANY)
                .set_data(Some(RData::NULL(NULL::new())))
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority
            .pre_scan(&[Record::new()
                .set_name(up_name.clone())
                .set_ttl(0)
                .set_rr_type(RecordType::IXFR)
                .set_dns_class(DNSClass::ANY)
                .set_data(Some(RData::NULL(NULL::new())))
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert!(authority
        .pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(0)
            .set_rr_type(RecordType::ANY)
            .set_dns_class(DNSClass::ANY)
            .set_data(Some(RData::NULL(NULL::new())))
            .clone()])
        .await
        .is_ok());
    assert!(authority
        .pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(0)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::ANY)
            .set_data(Some(RData::NULL(NULL::new())))
            .clone()])
        .await
        .is_ok());

    assert_eq!(
        authority
            .pre_scan(&[Record::new()
                .set_name(up_name.clone())
                .set_ttl(86400)
                .set_rr_type(RecordType::A)
                .set_dns_class(DNSClass::NONE)
                .set_data(Some(RData::NULL(NULL::new())))
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority
            .pre_scan(&[Record::new()
                .set_name(up_name.clone())
                .set_ttl(0)
                .set_rr_type(RecordType::ANY)
                .set_dns_class(DNSClass::NONE)
                .set_data(Some(RData::NULL(NULL::new())))
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority
            .pre_scan(&[Record::new()
                .set_name(up_name.clone())
                .set_ttl(0)
                .set_rr_type(RecordType::AXFR)
                .set_dns_class(DNSClass::NONE)
                .set_data(Some(RData::NULL(NULL::new())))
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        authority
            .pre_scan(&[Record::new()
                .set_name(up_name.clone())
                .set_ttl(0)
                .set_rr_type(RecordType::IXFR)
                .set_dns_class(DNSClass::NONE)
                .set_data(Some(RData::NULL(NULL::new())))
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
    assert!(authority
        .pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(0)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::NONE)
            .set_data(Some(RData::NULL(NULL::new())))
            .clone()])
        .await
        .is_ok());
    assert!(authority
        .pre_scan(&[Record::new()
            .set_name(up_name.clone())
            .set_ttl(0)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::NONE)
            .set_data(Some(RData::A(Ipv4Addr::new(93, 184, 216, 24))))
            .clone()])
        .await
        .is_ok());

    assert_eq!(
        authority
            .pre_scan(&[Record::new()
                .set_name(up_name)
                .set_ttl(86400)
                .set_rr_type(RecordType::A)
                .set_dns_class(DNSClass::CH)
                .set_data(Some(RData::NULL(NULL::new())))
                .clone()],)
            .await,
        Err(ResponseCode::FormErr)
    );
}

#[tokio::test]
async fn test_update() {
    let new_name = Name::from_str("new.example.com").unwrap();
    let www_name = Name::from_str("www.example.com").unwrap();
    let mut authority = create_example();
    let serial = authority.serial().await;

    authority.set_allow_update(true);

    let mut original_vec: Vec<Record> = vec![
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::TXT)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::TXT(TXT::new(vec!["v=spf1 -all".to_string()]))))
            .clone(),
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::A(Ipv4Addr::new(93, 184, 216, 34))))
            .clone(),
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::AAAA)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::AAAA(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            ))))
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
        assert!(authority
            .lookup(
                &new_name.clone().into(),
                RecordType::ANY,
                LookupOptions::default()
            )
            .await
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
        .set_data(Some(RData::A(Ipv4Addr::new(93, 184, 216, 24))))
        .clone()];
    assert!(authority
        .update_records(add_record, true,)
        .await
        .expect("update failed",));
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

    let add_www_record = &[Record::new()
        .set_name(www_name.clone())
        .set_ttl(86400)
        .set_rr_type(RecordType::A)
        .set_dns_class(DNSClass::IN)
        .set_data(Some(RData::A(Ipv4Addr::new(10, 0, 0, 1))))
        .clone()];
    assert!(authority
        .update_records(add_www_record, true,)
        .await
        .expect("update failed",));
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
    let del_record = &[Record::new()
        .set_name(new_name.clone())
        .set_ttl(86400)
        .set_rr_type(RecordType::A)
        .set_dns_class(DNSClass::NONE)
        .set_data(Some(RData::A(Ipv4Addr::new(93, 184, 216, 24))))
        .clone()];
    assert!(authority
        .update_records(del_record, true,)
        .await
        .expect("update failed",));
    assert_eq!(serial + 3, authority.serial().await);
    {
        let lookup = authority
            .lookup(&new_name.into(), RecordType::ANY, LookupOptions::default())
            .await
            .unwrap();

        println!("after delete of specific record: {:?}", lookup);
        assert!(lookup.was_empty());
    }

    // remove one from www
    let del_record = &[Record::new()
        .set_name(www_name.clone())
        .set_ttl(86400)
        .set_rr_type(RecordType::A)
        .set_dns_class(DNSClass::NONE)
        .set_data(Some(RData::A(Ipv4Addr::new(10, 0, 0, 1))))
        .clone()];
    assert!(authority
        .update_records(del_record, true,)
        .await
        .expect("update failed",));
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
    let del_record = &[Record::new()
        .set_name(www_name.clone())
        .set_ttl(86400)
        .set_rr_type(RecordType::A)
        .set_dns_class(DNSClass::ANY)
        .set_data(Some(RData::NULL(NULL::new())))
        .clone()];
    assert!(authority
        .update_records(del_record, true,)
        .await
        .expect("update failed",));
    assert_eq!(serial + 5, authority.serial().await);
    let mut removed_a_vec: Vec<_> = vec![
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::TXT)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::TXT(TXT::new(vec!["v=spf1 -all".to_string()]))))
            .clone(),
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::AAAA)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::AAAA(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            ))))
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
    let del_record = &[Record::new()
        .set_name(www_name.clone())
        .set_ttl(86400)
        .set_rr_type(RecordType::ANY)
        .set_dns_class(DNSClass::ANY)
        .set_data(Some(RData::NULL(NULL::new())))
        .clone()];

    assert!(authority
        .update_records(del_record, true,)
        .await
        .expect("update failed",));

    assert!(authority
        .lookup(&www_name.into(), RecordType::ANY, LookupOptions::default())
        .await
        .unwrap()
        .was_empty());

    assert_eq!(serial + 6, authority.serial().await);
}

#[cfg(feature = "dnssec")]
#[tokio::test]
async fn test_zone_signing() {
    let authority = create_secure_example();

    let results = authority
        .lookup(
            authority.origin(),
            RecordType::AXFR,
            LookupOptions::for_dnssec(true, SupportedAlgorithms::all()),
        )
        .await
        .unwrap();

    assert!(
        results.iter().any(|r| r.rr_type() == RecordType::DNSKEY),
        "must contain a DNSKEY"
    );

    let results = authority
        .lookup(
            authority.origin(),
            RecordType::AXFR,
            LookupOptions::for_dnssec(true, SupportedAlgorithms::all()),
        )
        .await
        .unwrap();

    for record in &results {
        if record.rr_type() == RecordType::RRSIG {
            continue;
        }
        if record.rr_type() == RecordType::DNSKEY {
            continue;
        }

        let inner_results = authority
            .lookup(
                authority.origin(),
                RecordType::AXFR,
                LookupOptions::for_dnssec(true, SupportedAlgorithms::all()),
            )
            .await
            .unwrap();

        // validate all records have associated RRSIGs after signing
        assert!(
            inner_results
                .iter()
                .any(|r| r.rr_type() == RecordType::RRSIG
                    && r.name() == record.name()
                    && if let RData::DNSSEC(DNSSECRData::SIG(ref rrsig)) = *r.data().unwrap() {
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
#[tokio::test]
async fn test_get_nsec() {
    let name = Name::from_str("zzz.example.com").unwrap();
    let authority = create_secure_example();
    let lower_name = LowerName::from(name.clone());

    let results = authority
        .get_nsec_records(
            &lower_name,
            LookupOptions::for_dnssec(true, SupportedAlgorithms::all()),
        )
        .await
        .unwrap();

    for record in &results {
        assert!(*record.name() < name);
    }
}

#[tokio::test]
async fn test_journal() {
    // test that this message can be inserted
    let conn = Connection::open_in_memory().expect("could not create in memory DB");
    let mut journal = Journal::new(conn).unwrap();
    journal.schema_up().unwrap();

    let mut authority = create_example();
    authority.set_journal(journal).await;
    authority.persist_to_journal().await.unwrap();

    let new_name = Name::from_str("new.example.com").unwrap();
    let delete_name = Name::from_str("www.example.com").unwrap();
    let new_record = Record::new()
        .set_name(new_name.clone())
        .set_record_type(RecordType::A)
        .set_data(Some(RData::A(Ipv4Addr::new(10, 11, 12, 13))))
        .clone();
    let delete_record = Record::new()
        .set_name(delete_name.clone())
        .set_record_type(RecordType::A)
        .set_data(Some(RData::A(Ipv4Addr::new(93, 184, 216, 34))))
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
    let in_memory =
        InMemoryAuthority::empty(authority.origin().clone().into(), ZoneType::Primary, false);

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
#[allow(clippy::blocks_in_if_conditions)]
async fn test_recovery() {
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
    let in_memory =
        InMemoryAuthority::empty(authority.origin().clone().into(), ZoneType::Primary, false);

    let mut recovered_authority = SqliteAuthority::new(in_memory, false, false);

    recovered_authority
        .recover_with_journal(journal)
        .await
        .expect("recovery");

    assert_eq!(
        recovered_authority.records().await.len(),
        authority.records().await.len()
    );

    assert!(recovered_authority
        .soa()
        .await
        .unwrap()
        .iter()
        .zip(authority.soa().await.unwrap().iter())
        .all(|(r1, r2)| r1 == r2));

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
    let mut authority = create_example();
    authority.set_allow_axfr(true);

    // query: &'q LowerQuery,
    //         is_secure: bool,
    //         supported_algorithms: SupportedAlgorithms,

    let query = LowerQuery::from(Query::query(
        Name::from_str("example.com.").unwrap(),
        RecordType::AXFR,
    ));
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
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
    let mut authority = create_example();
    authority.set_allow_axfr(false);

    let query = LowerQuery::from(Query::query(
        Name::from_str("example.com.").unwrap(),
        RecordType::AXFR,
    ));
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
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
