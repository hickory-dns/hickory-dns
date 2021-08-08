use std::net::*;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use futures::executor::block_on;

use trust_dns_client::op::*;
use trust_dns_client::rr::rdata::*;
use trust_dns_client::rr::*;
use trust_dns_client::serialize::binary::{BinDecodable, BinEncodable};

use trust_dns_server::authority::{Authority, Catalog, MessageRequest, ZoneType};
use trust_dns_server::store::in_memory::InMemoryAuthority;

use trust_dns_integration::authority::create_example;
use trust_dns_integration::*;

#[allow(clippy::unreadable_literal)]
pub fn create_test() -> InMemoryAuthority {
    let origin: Name = Name::parse("test.com.", None).unwrap();

    let mut records = InMemoryAuthority::empty(origin.clone(), ZoneType::Primary, false);

    records.upsert(
        Record::new()
            .set_name(origin.clone())
            .set_ttl(3600)
            .set_rr_type(RecordType::SOA)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::SOA(SOA::new(
                Name::parse("sns.dns.icann.org.", None).unwrap(),
                Name::parse("noc.dns.icann.org.", None).unwrap(),
                2015082403,
                7200,
                3600,
                1209600,
                3600,
            )))
            .clone(),
        0,
    );

    records.upsert(
        Record::new()
            .set_name(origin.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::NS)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()))
            .clone(),
        0,
    );
    records.upsert(
        Record::new()
            .set_name(origin.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::NS)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()))
            .clone(),
        0,
    );

    records.upsert(
        Record::new()
            .set_name(origin.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::A(Ipv4Addr::new(94, 184, 216, 34)))
            .clone(),
        0,
    );
    records.upsert(
        Record::new()
            .set_name(origin)
            .set_ttl(86400)
            .set_rr_type(RecordType::AAAA)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::AAAA(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            )))
            .clone(),
        0,
    );

    let www_name: Name = Name::parse("www.test.com.", None).unwrap();
    records.upsert(
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::A(Ipv4Addr::new(94, 184, 216, 34)))
            .clone(),
        0,
    );
    records.upsert(
        Record::new()
            .set_name(www_name)
            .set_ttl(86400)
            .set_rr_type(RecordType::AAAA)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::AAAA(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            )))
            .clone(),
        0,
    );

    records
}

#[test]
fn test_catalog_lookup() {
    let example = create_example();
    let test = create_test();
    let origin = example.origin().clone();
    let test_origin = test.origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin.clone(), Box::new(Arc::new(RwLock::new(example))));
    catalog.upsert(test_origin.clone(), Box::new(Arc::new(RwLock::new(test))));

    let mut question: Message = Message::new();

    let mut query: Query = Query::new();
    query.set_name(origin.into());

    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req = MessageRequest::from_bytes(&question_bytes).unwrap();

    let response_handler = TestResponseHandler::new();
    block_on(catalog.lookup(question_req, None, response_handler.clone()));
    let result = block_on(response_handler.into_message());

    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.message_type(), MessageType::Response);

    let answers: &[Record] = result.answers();

    assert!(!answers.is_empty());
    assert_eq!(answers.first().unwrap().rr_type(), RecordType::A);
    assert_eq!(
        answers.first().unwrap().rdata(),
        &RData::A(Ipv4Addr::new(93, 184, 216, 34))
    );

    // let mut ns: Vec<Record> = result.name_servers().to_vec();
    // ns.sort();

    // assert_eq!(ns.len(), 2);
    // assert_eq!(ns.first().unwrap().rr_type(), RecordType::NS);
    // assert_eq!(
    //     ns.first().unwrap().rdata(),
    //     &RData::NS(Name::parse("a.iana-servers.net.", None).unwrap())
    // );
    // assert_eq!(ns.last().unwrap().rr_type(), RecordType::NS);
    // assert_eq!(
    //     ns.last().unwrap().rdata(),
    //     &RData::NS(Name::parse("b.iana-servers.net.", None).unwrap())
    // );

    // other zone
    let mut question: Message = Message::new();
    let mut query: Query = Query::new();
    query.set_name(test_origin.into());

    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req = MessageRequest::from_bytes(&question_bytes).unwrap();

    let response_handler = TestResponseHandler::new();
    block_on(catalog.lookup(question_req, None, response_handler.clone()));
    let result = block_on(response_handler.into_message());

    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.message_type(), MessageType::Response);

    let answers: &[Record] = result.answers();

    assert!(!answers.is_empty());
    assert_eq!(answers.first().unwrap().rr_type(), RecordType::A);
    assert_eq!(
        answers.first().unwrap().rdata(),
        &RData::A(Ipv4Addr::new(94, 184, 216, 34))
    );
}

#[test]
#[allow(clippy::unreadable_literal)]
fn test_catalog_nx_soa() {
    let example = create_example();
    let origin = example.origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin, Box::new(Arc::new(RwLock::new(example))));

    let mut question: Message = Message::new();

    let mut query: Query = Query::new();
    query.set_name(Name::parse("nx.example.com.", None).unwrap());

    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req = MessageRequest::from_bytes(&question_bytes).unwrap();

    let response_handler = TestResponseHandler::new();
    block_on(catalog.lookup(question_req, None, response_handler.clone()));
    let result = block_on(response_handler.into_message());

    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.message_type(), MessageType::Response);

    let ns: &[Record] = result.name_servers();

    assert_eq!(ns.len(), 1);
    assert_eq!(ns.first().unwrap().rr_type(), RecordType::SOA);
    assert_eq!(
        ns.first().unwrap().rdata(),
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

#[test]
#[allow(clippy::unreadable_literal)]
fn test_axfr() {
    let mut test = create_test();
    test.set_allow_axfr(true);

    let origin = test.origin().clone();
    let soa = Record::new()
        .set_name(origin.clone().into())
        .set_ttl(3600)
        .set_rr_type(RecordType::SOA)
        .set_dns_class(DNSClass::IN)
        .set_rdata(RData::SOA(SOA::new(
            Name::parse("sns.dns.icann.org.", None).unwrap(),
            Name::parse("noc.dns.icann.org.", None).unwrap(),
            2015082403,
            7200,
            3600,
            1209600,
            3600,
        )))
        .clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin.clone(), Box::new(Arc::new(RwLock::new(test))));

    let mut query: Query = Query::new();
    query.set_name(origin.clone().into());
    query.set_query_type(RecordType::AXFR);

    let mut question: Message = Message::new();
    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req = MessageRequest::from_bytes(&question_bytes).unwrap();

    let response_handler = TestResponseHandler::new();
    block_on(catalog.lookup(question_req, None, response_handler.clone()));
    let result = block_on(response_handler.into_message());

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
            .set_rdata(RData::SOA(SOA::new(
                Name::parse("sns.dns.icann.org.", None).unwrap(),
                Name::parse("noc.dns.icann.org.", None).unwrap(),
                2015082403,
                7200,
                3600,
                1209600,
                3600,
            )))
            .clone(),
        Record::new()
            .set_name(origin.clone().into())
            .set_ttl(86400)
            .set_rr_type(RecordType::NS)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()))
            .clone(),
        Record::new()
            .set_name(origin.clone().into())
            .set_ttl(86400)
            .set_rr_type(RecordType::NS)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()))
            .clone(),
        Record::new()
            .set_name(origin.clone().into())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::A(Ipv4Addr::new(94, 184, 216, 34)))
            .clone(),
        Record::new()
            .set_name(origin.clone().into())
            .set_ttl(86400)
            .set_rr_type(RecordType::AAAA)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::AAAA(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            )))
            .clone(),
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::A(Ipv4Addr::new(94, 184, 216, 34)))
            .clone(),
        Record::new()
            .set_name(www_name)
            .set_ttl(86400)
            .set_rr_type(RecordType::AAAA)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::AAAA(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            )))
            .clone(),
        Record::new()
            .set_name(origin.into())
            .set_ttl(3600)
            .set_rr_type(RecordType::SOA)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::SOA(SOA::new(
                Name::parse("sns.dns.icann.org.", None).unwrap(),
                Name::parse("noc.dns.icann.org.", None).unwrap(),
                2015082403,
                7200,
                3600,
                1209600,
                3600,
            )))
            .clone(),
    ];

    expected_set.sort();

    assert_eq!(expected_set, answers);
}

#[test]
fn test_axfr_refused() {
    let mut test = create_test();
    test.set_allow_axfr(false);

    let origin = test.origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin.clone(), Box::new(Arc::new(RwLock::new(test))));

    let mut query: Query = Query::new();
    query.set_name(origin.into());
    query.set_query_type(RecordType::AXFR);

    let mut question: Message = Message::new();
    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req = MessageRequest::from_bytes(&question_bytes).unwrap();

    let response_handler = TestResponseHandler::new();
    block_on(catalog.lookup(question_req, None, response_handler.clone()));
    let result = block_on(response_handler.into_message());

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
#[test]
fn test_cname_additionals() {
    let example = create_example();
    let origin = example.origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin, Box::new(Arc::new(RwLock::new(example))));

    let mut question: Message = Message::new();

    let mut query: Query = Query::new();
    query.set_name(Name::from_str("alias.example.com.").unwrap());
    query.set_query_type(RecordType::A);

    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req = MessageRequest::from_bytes(&question_bytes).unwrap();

    let response_handler = TestResponseHandler::new();
    block_on(catalog.lookup(question_req, None, response_handler.clone()));
    let result = block_on(response_handler.into_message());

    assert_eq!(result.message_type(), MessageType::Response);
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let answers: &[Record] = result.answers();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers.first().unwrap().rr_type(), RecordType::CNAME);
    assert_eq!(
        answers.first().unwrap().rdata(),
        &RData::CNAME(Name::from_str("www.example.com.").unwrap())
    );

    let additionals: &[Record] = result.additionals();
    assert!(!additionals.is_empty());
    assert_eq!(additionals.first().unwrap().rr_type(), RecordType::A);
    assert_eq!(
        additionals.first().unwrap().rdata(),
        &RData::A(Ipv4Addr::new(93, 184, 216, 34))
    );
}

#[test]
fn test_multiple_cname_additionals() {
    let example = create_example();
    let origin = example.origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin, Box::new(Arc::new(RwLock::new(example))));

    let mut question: Message = Message::new();

    let mut query: Query = Query::new();
    query.set_name(Name::from_str("alias2.example.com.").unwrap());
    query.set_query_type(RecordType::A);

    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req = MessageRequest::from_bytes(&question_bytes).unwrap();

    let response_handler = TestResponseHandler::new();
    block_on(catalog.lookup(question_req, None, response_handler.clone()));
    let result = block_on(response_handler.into_message());

    assert_eq!(result.message_type(), MessageType::Response);
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let answers: &[Record] = result.answers();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers.first().unwrap().rr_type(), RecordType::CNAME);
    assert_eq!(
        answers.first().unwrap().rdata(),
        &RData::CNAME(Name::from_str("alias.example.com.").unwrap())
    );

    // we should have the intermediate record
    let additionals: &[Record] = result.additionals();
    assert!(!additionals.is_empty());
    assert_eq!(additionals.first().unwrap().rr_type(), RecordType::CNAME);
    assert_eq!(
        additionals.first().unwrap().rdata(),
        &RData::CNAME(Name::from_str("www.example.com.").unwrap())
    );

    // final record should be the actual
    let additionals: &[Record] = result.additionals();
    assert!(!additionals.is_empty());
    assert_eq!(additionals.last().unwrap().rr_type(), RecordType::A);
    assert_eq!(
        additionals.last().unwrap().rdata(),
        &RData::A(Ipv4Addr::new(93, 184, 216, 34))
    );
}
