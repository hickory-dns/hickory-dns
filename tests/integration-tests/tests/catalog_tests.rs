use std::{str::FromStr, sync::Arc};

use hickory_client::{
    op::*,
    rr::{rdata::*, *},
    serialize::binary::{BinDecodable, BinEncodable},
};

use hickory_server::{
    authority::{Authority, Catalog, MessageRequest, ZoneType},
    server::{Protocol, Request},
    store::in_memory::InMemoryAuthority,
};

use hickory_integration::{example_authority::create_example, *};

#[allow(clippy::unreadable_literal)]
pub fn create_test() -> InMemoryAuthority {
    let origin: Name = Name::parse("test.com.", None).unwrap();

    let mut records = InMemoryAuthority::empty(origin.clone(), ZoneType::Primary, false);

    records.upsert_mut(
        Record::new()
            .set_name(origin.clone())
            .set_ttl(3600)
            .set_rr_type(RecordType::SOA)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::SOA(SOA::new(
                Name::parse("sns.dns.icann.org.", None).unwrap(),
                Name::parse("noc.dns.icann.org.", None).unwrap(),
                2015082403,
                7200,
                3600,
                1209600,
                3600,
            ))))
            .clone(),
        0,
    );

    records.upsert_mut(
        Record::new()
            .set_name(origin.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::NS)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::NS(NS(Name::parse(
                "a.iana-servers.net.",
                None,
            )
            .unwrap()))))
            .clone(),
        0,
    );
    records.upsert_mut(
        Record::new()
            .set_name(origin.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::NS)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::NS(NS(Name::parse(
                "b.iana-servers.net.",
                None,
            )
            .unwrap()))))
            .clone(),
        0,
    );

    records.upsert_mut(
        Record::new()
            .set_name(origin.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::A(A::new(94, 184, 216, 34))))
            .clone(),
        0,
    );
    records.upsert_mut(
        Record::new()
            .set_name(origin)
            .set_ttl(86400)
            .set_rr_type(RecordType::AAAA)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::AAAA(AAAA::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            ))))
            .clone(),
        0,
    );

    let www_name: Name = Name::parse("www.test.com.", None).unwrap();
    records.upsert_mut(
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::A(A::new(94, 184, 216, 34))))
            .clone(),
        0,
    );
    records.upsert_mut(
        Record::new()
            .set_name(www_name)
            .set_ttl(86400)
            .set_rr_type(RecordType::AAAA)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::AAAA(AAAA::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            ))))
            .clone(),
        0,
    );

    records
}

#[tokio::test]
async fn test_catalog_lookup() {
    let example = create_example();
    let test = create_test();
    let origin = example.origin().clone();
    let test_origin = test.origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin.clone(), vec![Box::new(Arc::new(example))]);
    catalog.upsert(test_origin.clone(), vec![Box::new(Arc::new(test))]);

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
        answers.first().unwrap().data().unwrap(),
        &RData::A(A::new(93, 184, 216, 34))
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
        answers.first().unwrap().data().unwrap(),
        &RData::A(A::new(94, 184, 216, 34))
    );
}

#[tokio::test]
async fn test_catalog_lookup_soa() {
    let example = create_example();
    let test = create_test();
    let origin = example.origin().clone();
    let test_origin = test.origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin.clone(), vec![Box::new(Arc::new(example))]);
    catalog.upsert(test_origin, vec![Box::new(Arc::new(test))]);

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
        answers.first().unwrap().data().unwrap(),
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
        ns.first().unwrap().data().unwrap(),
        &RData::NS(NS(Name::parse("a.iana-servers.net.", None).unwrap()))
    );
    assert_eq!(ns.last().unwrap().record_type(), RecordType::NS);
    assert_eq!(
        ns.last().unwrap().data().unwrap(),
        &RData::NS(NS(Name::parse("b.iana-servers.net.", None).unwrap()))
    );
}

#[tokio::test]
#[allow(clippy::unreadable_literal)]
async fn test_catalog_nx_soa() {
    let example = create_example();
    let origin = example.origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin, vec![Box::new(Arc::new(example))]);

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
        ns.first().unwrap().data().unwrap(),
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
    let example = create_example();
    let origin = example.origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin, vec![Box::new(Arc::new(example))]);

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
    let mut test = create_test();
    test.set_allow_axfr(true);

    let origin = test.origin().clone();
    let soa = Record::new()
        .set_name(origin.clone().into())
        .set_ttl(3600)
        .set_rr_type(RecordType::SOA)
        .set_dns_class(DNSClass::IN)
        .set_data(Some(RData::SOA(SOA::new(
            Name::parse("sns.dns.icann.org.", None).unwrap(),
            Name::parse("noc.dns.icann.org.", None).unwrap(),
            2015082403,
            7200,
            3600,
            1209600,
            3600,
        ))))
        .clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin.clone(), vec![Box::new(Arc::new(test))]);

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
        Record::new()
            .set_name(origin.clone().into())
            .set_ttl(3600)
            .set_rr_type(RecordType::SOA)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::SOA(SOA::new(
                Name::parse("sns.dns.icann.org.", None).unwrap(),
                Name::parse("noc.dns.icann.org.", None).unwrap(),
                2015082403,
                7200,
                3600,
                1209600,
                3600,
            ))))
            .clone(),
        Record::new()
            .set_name(origin.clone().into())
            .set_ttl(86400)
            .set_rr_type(RecordType::NS)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::NS(NS(Name::parse(
                "a.iana-servers.net.",
                None,
            )
            .unwrap()))))
            .clone(),
        Record::new()
            .set_name(origin.clone().into())
            .set_ttl(86400)
            .set_rr_type(RecordType::NS)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::NS(NS(Name::parse(
                "b.iana-servers.net.",
                None,
            )
            .unwrap()))))
            .clone(),
        Record::new()
            .set_name(origin.clone().into())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::A(A::new(94, 184, 216, 34))))
            .clone(),
        Record::new()
            .set_name(origin.clone().into())
            .set_ttl(86400)
            .set_rr_type(RecordType::AAAA)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::AAAA(AAAA::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            ))))
            .clone(),
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::A(A::new(94, 184, 216, 34))))
            .clone(),
        Record::new()
            .set_name(www_name)
            .set_ttl(86400)
            .set_rr_type(RecordType::AAAA)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::AAAA(AAAA::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            ))))
            .clone(),
        Record::new()
            .set_name(origin.into())
            .set_ttl(3600)
            .set_rr_type(RecordType::SOA)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::SOA(SOA::new(
                Name::parse("sns.dns.icann.org.", None).unwrap(),
                Name::parse("noc.dns.icann.org.", None).unwrap(),
                2015082403,
                7200,
                3600,
                1209600,
                3600,
            ))))
            .clone(),
    ];

    expected_set.sort();

    assert_eq!(expected_set, answers);
}

#[tokio::test]
async fn test_axfr_refused() {
    let mut test = create_test();
    test.set_allow_axfr(false);

    let origin = test.origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin.clone(), vec![Box::new(Arc::new(test))]);

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
    let example = create_example();
    let origin = example.origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin, vec![Box::new(Arc::new(example))]);

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
        answers.first().unwrap().data().unwrap(),
        &RData::CNAME(CNAME(Name::from_str("www.example.com.").unwrap()))
    );

    let additionals: &[Record] = result.additionals();
    assert!(!additionals.is_empty());
    assert_eq!(additionals.first().unwrap().record_type(), RecordType::A);
    assert_eq!(
        additionals.first().unwrap().data().unwrap(),
        &RData::A(A::new(93, 184, 216, 34))
    );
}

#[tokio::test]
async fn test_multiple_cname_additionals() {
    let example = create_example();
    let origin = example.origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin, vec![Box::new(Arc::new(example))]);

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
        answers.first().unwrap().data().unwrap(),
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
        additionals.first().unwrap().data().unwrap(),
        &RData::CNAME(CNAME(Name::from_str("www.example.com.").unwrap()))
    );

    // final record should be the actual
    let additionals: &[Record] = result.additionals();
    assert!(!additionals.is_empty());
    assert_eq!(additionals.last().unwrap().record_type(), RecordType::A);
    assert_eq!(
        additionals.last().unwrap().data().unwrap(),
        &RData::A(A::new(93, 184, 216, 34))
    );
}
