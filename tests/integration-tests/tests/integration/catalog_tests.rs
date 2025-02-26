use std::{str::FromStr, sync::Arc};

use hickory_proto::{
    op::*,
    rr::{rdata::*, *},
    serialize::binary::{BinDecodable, BinEncodable},
    xfer::Protocol,
};
#[cfg(feature = "__dnssec")]
use hickory_server::dnssec::NxProofKind;
use hickory_server::{
    authority::{Authority, Catalog, MessageRequest, ZoneType},
    server::Request,
    store::in_memory::InMemoryAuthority,
};

use hickory_integration::{example_authority::create_example, *};
use test_support::subscribe;

#[allow(clippy::unreadable_literal)]
pub fn create_records(records: &mut InMemoryAuthority) {
    let origin: Name = records.origin().into();
    records.upsert_mut(
        Record::from_rdata(
            origin.clone(),
            3600,
            RData::SOA(SOA::new(
                Name::parse("sns.dns.icann.org.", None).unwrap(),
                Name::parse("noc.dns.icann.org.", None).unwrap(),
                2015082403,
                7200,
                3600,
                1209600,
                3600,
            )),
        )
        .set_dns_class(DNSClass::IN)
        .clone(),
        0,
    );

    records.upsert_mut(
        Record::from_rdata(
            origin.clone(),
            86400,
            RData::NS(NS(Name::parse("a.iana-servers.net.", None).unwrap())),
        )
        .set_dns_class(DNSClass::IN)
        .clone(),
        0,
    );
    records.upsert_mut(
        Record::from_rdata(
            origin.clone(),
            86400,
            RData::NS(NS(Name::parse("b.iana-servers.net.", None).unwrap())),
        )
        .set_dns_class(DNSClass::IN)
        .clone(),
        0,
    );

    records.upsert_mut(
        Record::from_rdata(origin.clone(), 86400, RData::A(A::new(94, 184, 216, 34)))
            .set_dns_class(DNSClass::IN)
            .clone(),
        0,
    );
    records.upsert_mut(
        Record::from_rdata(
            origin,
            86400,
            RData::AAAA(AAAA::new(
                0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
            )),
        )
        .set_dns_class(DNSClass::IN)
        .clone(),
        0,
    );

    let www_name: Name = Name::parse("www.test.com.", None).unwrap();
    records.upsert_mut(
        Record::from_rdata(www_name.clone(), 86400, RData::A(A::new(94, 184, 216, 34)))
            .set_dns_class(DNSClass::IN)
            .clone(),
        0,
    );
    records.upsert_mut(
        Record::from_rdata(
            www_name,
            86400,
            RData::AAAA(AAAA::new(
                0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
            )),
        )
        .set_dns_class(DNSClass::IN)
        .clone(),
        0,
    );
}

#[allow(clippy::unreadable_literal)]
pub fn create_test() -> InMemoryAuthority {
    let origin: Name = Name::parse("test.com.", None).unwrap();

    let mut records = InMemoryAuthority::empty(
        origin.clone(),
        ZoneType::Primary,
        false,
        #[cfg(feature = "__dnssec")]
        Some(NxProofKind::Nsec),
    );

    create_records(&mut records);

    records
}

#[tokio::test]
async fn test_catalog_lookup() {
    subscribe();

    let example = create_example();
    let test = create_test();
    let origin = example.origin().clone();
    let test_origin = test.origin().clone();

    let mut catalog = Catalog::new();
    catalog.upsert(origin.clone(), vec![Arc::new(example)]);
    catalog.upsert(test_origin.clone(), vec![Arc::new(test)]);

    let mut question: Message = Message::new();

    let mut query: Query = Query::new();
    query.set_name(origin.into());

    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req = MessageRequest::from_bytes(&question_bytes).unwrap();
    let question_req = Request::new(question_req, ([127, 0, 0, 1], 5553).into(), Protocol::Udp);

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(&question_req, None, response_handler.clone())
        .await;
    let result = response_handler.into_message().await;

    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.message_type(), MessageType::Response);
    assert!(result.header().authoritative());

    let answers: &[Record] = result.answers();

    assert!(!answers.is_empty());
    assert_eq!(answers.first().unwrap().record_type(), RecordType::A);
    assert_eq!(
        answers.first().unwrap().data(),
        &RData::A(A::new(93, 184, 215, 14))
    );

    let ns = result.name_servers();
    assert!(ns.is_empty());

    // other zone
    let mut question: Message = Message::new();
    let mut query: Query = Query::new();
    query.set_name(test_origin.into());

    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req = MessageRequest::from_bytes(&question_bytes).unwrap();
    let question_req = Request::new(question_req, ([127, 0, 0, 1], 5553).into(), Protocol::Udp);

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(&question_req, None, response_handler.clone())
        .await;
    let result = response_handler.into_message().await;

    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.message_type(), MessageType::Response);
    assert!(result.header().authoritative());

    let answers: &[Record] = result.answers();

    assert!(!answers.is_empty());
    assert_eq!(answers.first().unwrap().record_type(), RecordType::A);
    assert_eq!(
        answers.first().unwrap().data(),
        &RData::A(A::new(94, 184, 216, 34))
    );
}

#[tokio::test]
async fn test_catalog_lookup_soa() {
    subscribe();

    let example = create_example();
    let test = create_test();
    let origin = example.origin().clone();
    let test_origin = test.origin().clone();

    let mut catalog = Catalog::new();
    catalog.upsert(origin.clone(), vec![Arc::new(example)]);
    catalog.upsert(test_origin, vec![Arc::new(test)]);

    let mut question: Message = Message::new();

    let mut query: Query = Query::new();
    query.set_name(origin.into());
    query.set_query_type(RecordType::SOA);

    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req = MessageRequest::from_bytes(&question_bytes).unwrap();
    let question_req = Request::new(question_req, ([127, 0, 0, 1], 5553).into(), Protocol::Udp);

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(&question_req, None, response_handler.clone())
        .await;
    let result = response_handler.into_message().await;

    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.message_type(), MessageType::Response);
    assert!(result.header().authoritative());

    let answers: &[Record] = result.answers();

    assert!(!answers.is_empty());
    assert_eq!(answers.first().unwrap().record_type(), RecordType::SOA);
    assert_eq!(
        answers.first().unwrap().data(),
        &RData::SOA(SOA::new(
            Name::parse("sns.dns.icann.org.", None).unwrap(),
            Name::parse("noc.dns.icann.org.", None).unwrap(),
            2015082403,
            7200,
            3600,
            1209600,
            3600,
        ))
    );

    // assert SOA requests get NS records
    let mut ns: Vec<Record> = result.name_servers().to_vec();
    ns.sort();

    assert_eq!(ns.len(), 2);
    assert_eq!(ns.first().unwrap().record_type(), RecordType::NS);
    assert_eq!(
        ns.first().unwrap().data(),
        &RData::NS(NS(Name::parse("a.iana-servers.net.", None).unwrap()))
    );
    assert_eq!(ns.last().unwrap().record_type(), RecordType::NS);
    assert_eq!(
        ns.last().unwrap().data(),
        &RData::NS(NS(Name::parse("b.iana-servers.net.", None).unwrap()))
    );
}

#[tokio::test]
#[allow(clippy::unreadable_literal)]
async fn test_catalog_nx_soa() {
    subscribe();

    let example = create_example();
    let origin = example.origin().clone();

    let mut catalog = Catalog::new();
    catalog.upsert(origin, vec![Arc::new(example)]);

    let mut question: Message = Message::new();

    let mut query: Query = Query::new();
    query.set_name(Name::parse("nx.example.com.", None).unwrap());

    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req = MessageRequest::from_bytes(&question_bytes).unwrap();
    let question_req = Request::new(question_req, ([127, 0, 0, 1], 5553).into(), Protocol::Udp);

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(&question_req, None, response_handler.clone())
        .await;
    let result = response_handler.into_message().await;

    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.message_type(), MessageType::Response);
    assert!(result.header().authoritative());

    let ns: &[Record] = result.name_servers();

    assert_eq!(ns.len(), 1);
    assert_eq!(ns.first().unwrap().record_type(), RecordType::SOA);
    assert_eq!(
        ns.first().unwrap().data(),
        &RData::SOA(SOA::new(
            Name::parse("sns.dns.icann.org.", None).unwrap(),
            Name::parse("noc.dns.icann.org.", None).unwrap(),
            2015082403,
            7200,
            3600,
            1209600,
            3600,
        ))
    );
}

#[tokio::test]
async fn test_non_authoritive_nx_refused() {
    subscribe();

    let example = create_example();
    let origin = example.origin().clone();

    let mut catalog = Catalog::new();
    catalog.upsert(origin, vec![Arc::new(example)]);

    let mut question: Message = Message::new();

    let mut query: Query = Query::new();
    query.set_name(Name::parse("com.", None).unwrap());
    query.set_query_type(RecordType::SOA);

    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req = MessageRequest::from_bytes(&question_bytes).unwrap();
    let question_req = Request::new(question_req, ([127, 0, 0, 1], 5553).into(), Protocol::Udp);

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(&question_req, None, response_handler.clone())
        .await;
    let result = response_handler.into_message().await;

    assert_eq!(result.response_code(), ResponseCode::Refused);
    assert_eq!(result.message_type(), MessageType::Response);
    assert!(!result.header().authoritative());

    assert_eq!(result.name_servers().len(), 0);
    assert_eq!(result.answers().len(), 0);
    assert_eq!(result.additionals().len(), 0);
}

#[tokio::test]
#[allow(clippy::unreadable_literal)]
async fn test_axfr() {
    subscribe();

    let mut test = create_test();
    test.set_allow_axfr(true);

    let origin = test.origin().clone();
    let soa = Record::from_rdata(
        origin.clone().into(),
        3600,
        RData::SOA(SOA::new(
            Name::parse("sns.dns.icann.org.", None).unwrap(),
            Name::parse("noc.dns.icann.org.", None).unwrap(),
            2015082403,
            7200,
            3600,
            1209600,
            3600,
        )),
    )
    .set_dns_class(DNSClass::IN)
    .clone();

    let mut catalog = Catalog::new();
    catalog.upsert(origin.clone(), vec![Arc::new(test)]);

    let mut query: Query = Query::new();
    query.set_name(origin.clone().into());
    query.set_query_type(RecordType::AXFR);

    let mut question: Message = Message::new();
    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req = MessageRequest::from_bytes(&question_bytes).unwrap();
    let question_req = Request::new(question_req, ([127, 0, 0, 1], 5553).into(), Protocol::Udp);

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(&question_req, None, response_handler.clone())
        .await;
    let result = response_handler.into_message().await;

    let mut answers: Vec<Record> = result.answers().to_vec();

    assert_eq!(answers.first().expect("no records found?"), &soa);
    assert_eq!(answers.last().expect("no records found?"), &soa);

    answers.sort();

    let www_name: Name = Name::parse("www.test.com.", None).unwrap();
    let mut expected_set = vec![
        Record::from_rdata(
            origin.clone().into(),
            3600,
            RData::SOA(SOA::new(
                Name::parse("sns.dns.icann.org.", None).unwrap(),
                Name::parse("noc.dns.icann.org.", None).unwrap(),
                2015082403,
                7200,
                3600,
                1209600,
                3600,
            )),
        )
        .set_dns_class(DNSClass::IN)
        .clone(),
        Record::from_rdata(
            origin.clone().into(),
            86400,
            RData::NS(NS(Name::parse("a.iana-servers.net.", None).unwrap())),
        )
        .set_dns_class(DNSClass::IN)
        .clone(),
        Record::from_rdata(
            origin.clone().into(),
            86400,
            RData::NS(NS(Name::parse("b.iana-servers.net.", None).unwrap())),
        )
        .set_dns_class(DNSClass::IN)
        .clone(),
        Record::from_rdata(
            origin.clone().into(),
            86400,
            RData::A(A::new(94, 184, 216, 34)),
        )
        .set_dns_class(DNSClass::IN)
        .clone(),
        Record::from_rdata(
            origin.clone().into(),
            86400,
            RData::AAAA(AAAA::new(
                0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
            )),
        )
        .set_dns_class(DNSClass::IN)
        .clone(),
        Record::from_rdata(www_name.clone(), 86400, RData::A(A::new(94, 184, 216, 34)))
            .set_dns_class(DNSClass::IN)
            .clone(),
        Record::from_rdata(
            www_name,
            86400,
            RData::AAAA(AAAA::new(
                0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
            )),
        )
        .set_dns_class(DNSClass::IN)
        .clone(),
        Record::from_rdata(
            origin.into(),
            3600,
            RData::SOA(SOA::new(
                Name::parse("sns.dns.icann.org.", None).unwrap(),
                Name::parse("noc.dns.icann.org.", None).unwrap(),
                2015082403,
                7200,
                3600,
                1209600,
                3600,
            )),
        )
        .set_dns_class(DNSClass::IN)
        .clone(),
    ];

    expected_set.sort();

    assert_eq!(expected_set, answers);
}

#[tokio::test]
async fn test_axfr_refused() {
    subscribe();

    let mut test = create_test();
    test.set_allow_axfr(false);

    let origin = test.origin().clone();

    let mut catalog = Catalog::new();
    catalog.upsert(origin.clone(), vec![Arc::new(test)]);

    let mut query: Query = Query::new();
    query.set_name(origin.into());
    query.set_query_type(RecordType::AXFR);

    let mut question: Message = Message::new();
    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req = MessageRequest::from_bytes(&question_bytes).unwrap();
    let question_req = Request::new(question_req, ([127, 0, 0, 1], 5553).into(), Protocol::Udp);

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(&question_req, None, response_handler.clone())
        .await;
    let result = response_handler.into_message().await;

    assert_eq!(result.response_code(), ResponseCode::Refused);
    assert!(result.answers().is_empty());
    assert!(result.name_servers().is_empty());
    assert!(result.additionals().is_empty());
}

// TODO: add this test
// #[test]
// fn test_truncated_returns_records() {

// }

// TODO: these should be moved to the battery tests
#[tokio::test]
async fn test_cname_additionals() {
    subscribe();

    let example = create_example();
    let origin = example.origin().clone();

    let mut catalog = Catalog::new();
    catalog.upsert(origin, vec![Arc::new(example)]);

    let mut question: Message = Message::new();

    let mut query: Query = Query::new();
    query.set_name(Name::from_str("alias.example.com.").unwrap());
    query.set_query_type(RecordType::A);

    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req = MessageRequest::from_bytes(&question_bytes).unwrap();
    let question_req = Request::new(question_req, ([127, 0, 0, 1], 5553).into(), Protocol::Udp);

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(&question_req, None, response_handler.clone())
        .await;
    let result = response_handler.into_message().await;

    assert_eq!(result.message_type(), MessageType::Response);
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let answers: &[Record] = result.answers();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers.first().unwrap().record_type(), RecordType::CNAME);
    assert_eq!(
        answers.first().unwrap().data(),
        &RData::CNAME(CNAME(Name::from_str("www.example.com.").unwrap()))
    );

    let additionals: &[Record] = result.additionals();
    assert!(!additionals.is_empty());
    assert_eq!(additionals.first().unwrap().record_type(), RecordType::A);
    assert_eq!(
        additionals.first().unwrap().data(),
        &RData::A(A::new(93, 184, 215, 14))
    );
}

#[tokio::test]
async fn test_multiple_cname_additionals() {
    subscribe();

    let example = create_example();
    let origin = example.origin().clone();

    let mut catalog = Catalog::new();
    catalog.upsert(origin, vec![Arc::new(example)]);

    let mut question: Message = Message::new();

    let mut query: Query = Query::new();
    query.set_name(Name::from_str("alias2.example.com.").unwrap());
    query.set_query_type(RecordType::A);

    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req = MessageRequest::from_bytes(&question_bytes).unwrap();
    let question_req = Request::new(question_req, ([127, 0, 0, 1], 5553).into(), Protocol::Udp);

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(&question_req, None, response_handler.clone())
        .await;
    let result = response_handler.into_message().await;

    assert_eq!(result.message_type(), MessageType::Response);
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let answers: &[Record] = result.answers();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers.first().unwrap().record_type(), RecordType::CNAME);
    assert_eq!(
        answers.first().unwrap().data(),
        &RData::CNAME(CNAME(Name::from_str("alias.example.com.").unwrap()))
    );

    // we should have the intermediate record
    let additionals: &[Record] = result.additionals();
    assert!(!additionals.is_empty());
    assert_eq!(
        additionals.first().unwrap().record_type(),
        RecordType::CNAME
    );
    assert_eq!(
        additionals.first().unwrap().data(),
        &RData::CNAME(CNAME(Name::from_str("www.example.com.").unwrap()))
    );

    // final record should be the actual
    let additionals: &[Record] = result.additionals();
    assert!(!additionals.is_empty());
    assert_eq!(additionals.last().unwrap().record_type(), RecordType::A);
    assert_eq!(
        additionals.last().unwrap().data(),
        &RData::A(A::new(93, 184, 215, 14))
    );
}

#[cfg(feature = "__dnssec")]
mod dnssec {
    use super::*;
    use hickory_proto::dnssec::{
        Nsec3HashAlgorithm, SigSigner, SigningKey, crypto::Ed25519SigningKey, rdata::DNSKEY,
    };

    fn make_catalog() -> Catalog {
        let origin = Name::parse("test.com.", None).unwrap();

        let mut records = InMemoryAuthority::empty(
            origin.clone(),
            ZoneType::Primary,
            false,
            Some(NxProofKind::Nsec3 {
                algorithm: Default::default(),
                salt: Default::default(),
                iterations: Default::default(),
                opt_out: false,
            }),
        );
        let key = Ed25519SigningKey::from_pkcs8(
            &Ed25519SigningKey::generate_pkcs8().expect("generate random key"),
        )
        .unwrap();

        records
            .add_zone_signing_key_mut(SigSigner::dnssec(
                DNSKEY::from_key(&key.to_public_key().expect("convert to public key")),
                Box::new(key),
                origin.clone(),
                std::time::Duration::from_secs(3600),
            ))
            .unwrap();

        create_records(&mut records);
        records.secure_zone_mut().unwrap();

        let mut catalog = Catalog::new();
        catalog.upsert(origin.into(), vec![Arc::new(records)]);
        catalog
    }

    async fn run_query(catalog: &Catalog, query: Query) -> Message {
        let mut question = Message::new();
        question.add_query(query);
        question
            .extensions_mut()
            .get_or_insert_with(Edns::new)
            .enable_dnssec();

        let question_bytes = question.to_bytes().unwrap();
        let question_req = MessageRequest::from_bytes(&question_bytes).unwrap();
        let question_req = Request::new(question_req, ([127, 0, 0, 1], 5553).into(), Protocol::Udp);

        let response_handler = TestResponseHandler::new();
        catalog
            .lookup(&question_req, None, response_handler.clone())
            .await;
        response_handler.into_message().await
    }

    #[tokio::test]
    async fn test_dnskey_and_nsec3() {
        let catalog = make_catalog();

        let mut query = Query::new();
        query.set_name(Name::from_str("test.com.").unwrap());
        query.set_query_type(RecordType::DNSKEY);

        // Check DNSKEY + RRSIG
        {
            let result = run_query(&catalog, query).await;

            let dnskey = result
                .answers()
                .iter()
                .find(|e| e.record_type() == RecordType::DNSKEY)
                .expect("result to contain one DNSKEY");
            let rrsig = result
                .answers()
                .iter()
                .find(|e| e.record_type() == RecordType::RRSIG)
                .expect("result to contain one DNSKEY");
            assert_eq!(result.answers().len(), 2, "expect only one answer");

            let dnskey = dnskey
                .data()
                .clone()
                .into_dnssec()
                .unwrap()
                .into_dnskey()
                .unwrap();
            assert!(dnskey.zone_key());

            let rrsig = rrsig
                .data()
                .clone()
                .into_dnssec()
                .unwrap()
                .into_rrsig()
                .unwrap();
            assert_eq!(rrsig.type_covered(), RecordType::DNSKEY);
        }

        // Check NSEC3
        {
            let mut query = Query::new();
            query.set_name(Name::from_str("test.com.").unwrap());
            query.set_query_type(RecordType::NSEC);

            let result = run_query(&catalog, query).await;
            assert!(result.answers().is_empty());

            result
                .name_servers()
                .iter()
                .find(|e| e.record_type() == RecordType::SOA)
                .expect("authority section to contains SOA");

            let nsec3 = result
                .name_servers()
                .iter()
                .find(|e| e.record_type() == RecordType::NSEC3)
                .expect("result to contain NSEC3");

            let nsec3 = nsec3
                .data()
                .clone()
                .into_dnssec()
                .unwrap()
                .into_nsec3()
                .unwrap();

            for denied in [RecordType::NSEC, RecordType::NSEC3] {
                assert!(
                    !nsec3.type_bit_maps().contains(&denied),
                    "{denied} MUST not be included"
                );
            }

            for required in [
                RecordType::SOA,
                RecordType::NS,
                RecordType::DNSKEY,
                RecordType::NSEC3PARAM,
                RecordType::RRSIG,
            ] {
                assert!(
                    nsec3.type_bit_maps().contains(&required),
                    "{required} MUST be included"
                );
            }
        }

        // Check NSEC3PARAM
        {
            let mut query = Query::new();
            query.set_name(Name::from_str("test.com.").unwrap());
            query.set_query_type(RecordType::NSEC3PARAM);

            let result = run_query(&catalog, query).await;

            let nsec3param = result
                .answers()
                .iter()
                .find(|e| e.record_type() == RecordType::NSEC3PARAM)
                .expect("result to contain one NSEC3PARAM");

            let nsec3param = nsec3param
                .data()
                .clone()
                .into_dnssec()
                .unwrap()
                .into_nsec3param()
                .unwrap();

            // Check default parameters
            assert_eq!(nsec3param.hash_algorithm(), Nsec3HashAlgorithm::SHA1);
            assert_eq!(nsec3param.iterations(), 0);
            assert!(nsec3param.salt().is_empty());
        }
    }
}
