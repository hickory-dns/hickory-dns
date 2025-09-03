use std::{net::Ipv4Addr, str::FromStr, sync::Arc};

use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        DNSClass, LowerName, Name, RData, Record, RecordType,
        rdata::{
            A, AAAA, CNAME, NS, SOA,
            opt::{EdnsCode, EdnsOption, NSIDPayload},
        },
    },
    runtime::{Time, TokioTime},
    serialize::binary::BinEncodable,
    xfer::Protocol,
};
#[cfg(feature = "__dnssec")]
use hickory_server::dnssec::NxProofKind;
#[cfg(feature = "sqlite")]
use hickory_server::store::sqlite::SqliteZoneHandler;
use hickory_server::{
    server::{Request, RequestHandler},
    store::{
        forwarder::{ForwardConfig, ForwardZoneHandler},
        in_memory::InMemoryZoneHandler,
    },
    zone_handler::{AxfrPolicy, Catalog, ZoneHandler, ZoneType},
};

use hickory_integration::{example_zone::create_example, *};
use test_support::subscribe;

#[allow(clippy::unreadable_literal)]
pub fn create_records(records: &mut InMemoryZoneHandler) {
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

    let www_name = Name::parse("www.test.com.", None).unwrap();
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

pub fn create_test() -> InMemoryZoneHandler {
    let origin = Name::parse("test.com.", None).unwrap();

    let mut records = InMemoryZoneHandler::empty(
        origin.clone(),
        ZoneType::Primary,
        AxfrPolicy::Deny,
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

    let mut question = Message::query();

    let mut query = Query::new();
    query.set_name(origin.into());

    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req =
        Request::from_bytes(question_bytes, ([127, 0, 0, 1], 5553).into(), Protocol::Udp).unwrap();

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(
            &question_req,
            None,
            TokioTime::current_time(),
            response_handler.clone(),
        )
        .await;
    let result = response_handler.into_message().await;

    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.message_type(), MessageType::Response);
    assert!(result.header().authoritative());

    let answers = result.answers();

    assert!(!answers.is_empty());
    assert_eq!(answers.first().unwrap().record_type(), RecordType::A);
    assert_eq!(
        answers.first().unwrap().data(),
        &RData::A(A::new(93, 184, 215, 14))
    );

    let authorities = result.authorities();
    assert!(authorities.is_empty());

    // other zone
    let mut question = Message::query();
    let mut query = Query::new();
    query.set_name(test_origin.into());

    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req =
        Request::from_bytes(question_bytes, ([127, 0, 0, 1], 5553).into(), Protocol::Udp).unwrap();

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(
            &question_req,
            None,
            TokioTime::current_time(),
            response_handler.clone(),
        )
        .await;
    let result = response_handler.into_message().await;

    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.message_type(), MessageType::Response);
    assert!(result.header().authoritative());

    let answers = result.answers();

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

    let mut question = Message::query();

    let mut query = Query::new();
    query.set_name(origin.into());
    query.set_query_type(RecordType::SOA);

    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req =
        Request::from_bytes(question_bytes, ([127, 0, 0, 1], 5553).into(), Protocol::Udp).unwrap();

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(
            &question_req,
            None,
            TokioTime::current_time(),
            response_handler.clone(),
        )
        .await;
    let result = response_handler.into_message().await;

    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.message_type(), MessageType::Response);
    assert!(result.header().authoritative());

    let answers = result.answers();

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
    let mut ns = result.authorities().to_vec();
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

    let mut question = Message::query();

    let mut query = Query::new();
    query.set_name(Name::parse("nx.example.com.", None).unwrap());

    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req =
        Request::from_bytes(question_bytes, ([127, 0, 0, 1], 5553).into(), Protocol::Udp).unwrap();

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(
            &question_req,
            None,
            TokioTime::current_time(),
            response_handler.clone(),
        )
        .await;
    let result = response_handler.into_message().await;

    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.message_type(), MessageType::Response);
    assert!(result.header().authoritative());

    let authorities = result.authorities();

    assert_eq!(authorities.len(), 1);
    assert_eq!(authorities.first().unwrap().record_type(), RecordType::SOA);
    assert_eq!(
        authorities.first().unwrap().data(),
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

    let mut question = Message::query();

    let mut query = Query::new();
    query.set_name(Name::parse("com.", None).unwrap());
    query.set_query_type(RecordType::SOA);

    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req =
        Request::from_bytes(question_bytes, ([127, 0, 0, 1], 5553).into(), Protocol::Udp).unwrap();

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(
            &question_req,
            None,
            TokioTime::current_time(),
            response_handler.clone(),
        )
        .await;
    let result = response_handler.into_message().await;

    assert_eq!(result.response_code(), ResponseCode::Refused);
    assert_eq!(result.message_type(), MessageType::Response);
    assert!(!result.header().authoritative());

    assert_eq!(result.authorities().len(), 0);
    assert_eq!(result.answers().len(), 0);
    assert_eq!(result.additionals().len(), 0);
}

#[tokio::test]
#[allow(clippy::unreadable_literal)]
async fn test_axfr_allow_all() {
    subscribe();

    let mut test = create_test();
    test.set_axfr_policy(AxfrPolicy::AllowAll);

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

    let mut query = Query::new();
    query.set_name(origin.clone().into());
    query.set_query_type(RecordType::AXFR);

    let mut question = Message::query();
    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req =
        Request::from_bytes(question_bytes, ([127, 0, 0, 1], 5553).into(), Protocol::Udp).unwrap();

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(
            &question_req,
            None,
            TokioTime::current_time(),
            response_handler.clone(),
        )
        .await;
    let result = response_handler.into_message().await;

    let mut answers = result.answers().to_vec();

    assert_eq!(answers.first().expect("no records found?"), &soa);
    assert_eq!(answers.last().expect("no records found?"), &soa);

    answers.sort();

    let www_name = Name::parse("www.test.com.", None).unwrap();
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
async fn test_axfr_deny_all() {
    subscribe();

    let mut test = create_test();
    test.set_axfr_policy(AxfrPolicy::Deny);

    let origin = test.origin().clone();

    let mut catalog = Catalog::new();
    catalog.upsert(origin.clone(), vec![Arc::new(test)]);

    let mut query = Query::new();
    query.set_name(origin.into());
    query.set_query_type(RecordType::AXFR);

    let mut question = Message::query();
    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req =
        Request::from_bytes(question_bytes, ([127, 0, 0, 1], 5553).into(), Protocol::Udp).unwrap();

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(
            &question_req,
            None,
            TokioTime::current_time(),
            response_handler.clone(),
        )
        .await;
    let result = response_handler.into_message().await;

    assert_eq!(result.response_code(), ResponseCode::Refused);
    assert!(result.answers().is_empty());
    assert!(result.authorities().is_empty());
    assert!(result.additionals().is_empty());
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_axfr_deny_all_sqlite() {
    subscribe();

    let mut test = create_test();
    test.set_axfr_policy(AxfrPolicy::Deny);
    let handler = SqliteZoneHandler::new(test, AxfrPolicy::Deny, false, false);
    let origin = handler.origin().clone();

    let mut catalog = Catalog::new();
    catalog.upsert(origin.clone(), vec![Arc::new(handler)]);

    let query = Query::query(origin.into(), RecordType::AXFR);
    let mut message = Message::query();
    message.add_query(query);

    let message_bytes = message.to_bytes().unwrap();
    let request =
        Request::from_bytes(message_bytes, ([127, 0, 0, 1], 5553).into(), Protocol::Tcp).unwrap();

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(
            &request,
            None,
            TokioTime::current_time(),
            response_handler.clone(),
        )
        .await;
    let response = response_handler.into_message().await;

    assert_eq!(response.response_code(), ResponseCode::Refused);
    assert!(response.answers().is_empty());
    assert!(response.authorities().is_empty());
    assert!(response.additionals().is_empty());
}

#[tokio::test]
#[cfg(feature = "__dnssec")]
async fn test_axfr_deny_unsigned() {
    subscribe();

    let mut test = create_test();
    test.set_axfr_policy(AxfrPolicy::AllowSigned);

    let origin = test.origin().clone();

    let mut catalog = Catalog::new();
    catalog.upsert(origin.clone(), vec![Arc::new(test)]);

    let mut query = Query::new();
    query.set_name(origin.into());
    query.set_query_type(RecordType::AXFR);

    let mut question = Message::query();
    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req =
        Request::from_bytes(question_bytes, ([127, 0, 0, 1], 5553).into(), Protocol::Udp).unwrap();

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(
            &question_req,
            None,
            TokioTime::current_time(),
            response_handler.clone(),
        )
        .await;
    let result = response_handler.into_message().await;

    assert_eq!(result.response_code(), ResponseCode::Refused);
    assert!(result.answers().is_empty());
    assert!(result.authorities().is_empty());
    assert!(result.additionals().is_empty());
}

// Test that requesting NSID produces no NSID response when a payload isn't configured.
#[tokio::test]
async fn test_nsid_disabled_requested() {
    subscribe();

    let mem_handler = create_test();
    let origin = mem_handler.origin().clone();
    let mut catalog = Catalog::new(); // Default behaviour: NSID disabled.
    catalog.upsert(origin.clone(), vec![Arc::new(mem_handler)]);

    // Create a question request that asks for NSID in EDNS.
    let question_req = test_nsid_request(origin.clone(), true);

    let response_handler = TestResponseHandler::new();
    let _ = catalog
        .handle_request::<_, TokioTime>(&question_req, response_handler.clone())
        .await;
    let response = response_handler.into_message().await;
    assert_eq!(response.response_code(), ResponseCode::NoError);

    // We sent EDNS in the request, and so expect to find EDNS in the response.
    let edns = response
        .extensions()
        .as_ref()
        .expect("missing response EDNS");
    // We shouldn't find an NSID payload in the response EDNS even though we requested it
    // The catalog had no payload configured.
    assert!(
        edns.option(EdnsCode::NSID).is_none(),
        "unexpected NSID in reply EDNS"
    );
}

// Test that **not** requesting NSID produces no NSID response, even when a payload is configured.
#[tokio::test]
async fn test_nsid_enabled_not_requested() {
    subscribe();

    let mem_handler = create_test();
    let origin = mem_handler.origin().clone();
    let mut catalog = Catalog::new();
    catalog.upsert(origin.clone(), vec![Arc::new(mem_handler)]);

    // Configure the catalog with an NSID payload.
    catalog.set_nsid(Some(NSIDPayload::new(vec![0xC0, 0xFF, 0xEE]).unwrap()));

    // Create a question request that doesn't ask for NSID in EDNS.
    let question_req = test_nsid_request(origin.clone(), false);

    let response_handler = TestResponseHandler::new();
    let _ = catalog
        .handle_request::<_, TokioTime>(&question_req, response_handler.clone())
        .await;
    let response = response_handler.into_message().await;
    assert_eq!(response.response_code(), ResponseCode::NoError);

    // We sent EDNS in the request, and so expect to find EDNS in the response.
    let edns = response
        .extensions()
        .as_ref()
        .expect("missing response EDNS");
    // We shouldn't find an NSID payload in the response EDNS - we didn't request it.
    assert!(
        edns.option(EdnsCode::NSID).is_none(),
        "unexpected NSID in reply EDNS"
    );
}

// Test that requesting NSID when a payload is configured produces the expected payload
// in the response.
#[tokio::test]
async fn test_nsid_enabled_and_requested() {
    subscribe();

    let mem_handler = create_test();
    let origin = mem_handler.origin().clone();
    let mut catalog = Catalog::new();
    catalog.upsert(origin.clone(), vec![Arc::new(mem_handler)]);

    // Configure the catalog with an NSID payload.
    let nsid = NSIDPayload::new(vec![0xC0, 0xFF, 0xEE]).unwrap();
    catalog.set_nsid(Some(nsid.clone()));

    // Create a question request that asks for NSID in EDNS.
    let question_req = test_nsid_request(origin.clone(), true);

    let response_handler = TestResponseHandler::new();
    let _ = catalog
        .handle_request::<_, TokioTime>(&question_req, response_handler.clone())
        .await;
    let response = response_handler.into_message().await;
    assert_eq!(response.response_code(), ResponseCode::NoError);

    // We sent EDNS in the request, and so expect to find EDNS in the response.
    let edns = response
        .extensions()
        .as_ref()
        .expect("missing response EDNS");
    // We should find the expected EDNS NSID payload.
    assert_eq!(edns.option(EdnsCode::NSID), Some(&EdnsOption::NSID(nsid)));
}

fn test_nsid_request(origin: LowerName, request_nsid: bool) -> Request {
    let mut query = Query::new();
    query.set_name(origin.into());
    query.set_query_type(RecordType::A);

    let mut question_edns = Edns::new();
    if request_nsid {
        question_edns
            .options_mut()
            .insert(EdnsOption::NSID(NSIDPayload::new([]).unwrap()));
    }

    let mut question = Message::query();
    question.add_query(query);
    question.set_edns(question_edns);

    let question_bytes = question.to_bytes().unwrap();
    Request::from_bytes(question_bytes, ([127, 0, 0, 1], 5553).into(), Protocol::Udp).unwrap()
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

    let mut question = Message::query();

    let mut query = Query::new();
    query.set_name(Name::from_str("alias.example.com.").unwrap());
    query.set_query_type(RecordType::A);

    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req =
        Request::from_bytes(question_bytes, ([127, 0, 0, 1], 5553).into(), Protocol::Udp).unwrap();

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(
            &question_req,
            None,
            TokioTime::current_time(),
            response_handler.clone(),
        )
        .await;
    let result = response_handler.into_message().await;

    assert_eq!(result.message_type(), MessageType::Response);
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let answers = result.answers();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers.first().unwrap().record_type(), RecordType::CNAME);
    assert_eq!(
        answers.first().unwrap().data(),
        &RData::CNAME(CNAME(Name::from_str("www.example.com.").unwrap()))
    );

    let additionals = result.additionals();
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

    let mut question = Message::query();

    let mut query = Query::new();
    query.set_name(Name::from_str("alias2.example.com.").unwrap());
    query.set_query_type(RecordType::A);

    question.add_query(query);

    // temp request
    let question_bytes = question.to_bytes().unwrap();
    let question_req =
        Request::from_bytes(question_bytes, ([127, 0, 0, 1], 5553).into(), Protocol::Udp).unwrap();

    let response_handler = TestResponseHandler::new();
    catalog
        .lookup(
            &question_req,
            None,
            TokioTime::current_time(),
            response_handler.clone(),
        )
        .await;
    let result = response_handler.into_message().await;

    assert_eq!(result.message_type(), MessageType::Response);
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let answers = result.answers();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers.first().unwrap().record_type(), RecordType::CNAME);
    assert_eq!(
        answers.first().unwrap().data(),
        &RData::CNAME(CNAME(Name::from_str("alias.example.com.").unwrap()))
    );

    // we should have the intermediate record
    let additionals = result.additionals();
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
    let additionals = result.additionals();
    assert!(!additionals.is_empty());
    assert_eq!(additionals.last().unwrap().record_type(), RecordType::A);
    assert_eq!(
        additionals.last().unwrap().data(),
        &RData::A(A::new(93, 184, 215, 14))
    );
}

#[tokio::test]
async fn test_update_forwarder() {
    subscribe();

    let handler = ForwardZoneHandler::builder_tokio(ForwardConfig {
        name_servers: Vec::new(),
        options: None,
    })
    .build()
    .unwrap();

    let mut catalog = Catalog::new();
    catalog.upsert(Name::root().into(), vec![Arc::new(handler)]);

    let query = Query::query(Name::root(), RecordType::SOA);
    let mut message = Message::new(0, MessageType::Query, OpCode::Update);
    message.add_query(query);
    message.add_answer(Record::from_rdata(
        Name::root(),
        86400,
        RData::A(A(Ipv4Addr::LOCALHOST)),
    ));
    message.set_recursion_desired(true);

    let message_bytes = message.to_bytes().unwrap();
    let request =
        Request::from_bytes(message_bytes, ([127, 0, 0, 1], 5553).into(), Protocol::Tcp).unwrap();

    let response_handler = TestResponseHandler::new();
    catalog
        .handle_request::<_, TokioTime>(&request, response_handler.clone())
        .await;
    let response = response_handler.into_message().await;

    assert_eq!(response.response_code(), ResponseCode::NotAuth);
    assert!(response.answers().is_empty());
    assert!(response.authorities().is_empty());
    assert!(response.additionals().is_empty());
}

#[tokio::test]
async fn test_empty_chain_query() {
    subscribe();

    let mut catalog = Catalog::new();
    catalog.upsert(Name::root().into(), vec![]);

    let query = Query::query(Name::root(), RecordType::SOA);
    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    message.add_query(query);

    let message_bytes = message.to_bytes().unwrap();
    let request =
        Request::from_bytes(message_bytes, ([127, 0, 0, 1], 53).into(), Protocol::Tcp).unwrap();

    let response_handler = TestResponseHandler::new();
    catalog
        .handle_request::<_, TokioTime>(&request, response_handler.clone())
        .await;
    let response = response_handler.into_message().await;

    assert_eq!(response.response_code(), ResponseCode::ServFail);
    assert!(response.answers().is_empty());
    assert!(response.authorities().is_empty());
    assert!(response.additionals().is_empty());
}

#[tokio::test]
async fn test_empty_chain_update() {
    subscribe();

    let mut catalog = Catalog::new();
    catalog.upsert(Name::root().into(), vec![]);

    let query = Query::query(Name::root(), RecordType::SOA);
    let mut message = Message::new(0, MessageType::Query, OpCode::Update);
    message.add_query(query);
    message.add_answer(Record::from_rdata(
        Name::root(),
        86400,
        RData::A(A(Ipv4Addr::LOCALHOST)),
    ));

    let message_bytes = message.to_bytes().unwrap();
    let request =
        Request::from_bytes(message_bytes, ([127, 0, 0, 1], 53).into(), Protocol::Tcp).unwrap();

    let response_handler = TestResponseHandler::new();
    catalog
        .handle_request::<_, TokioTime>(&request, response_handler.clone())
        .await;
    let response = response_handler.into_message().await;

    assert_eq!(response.response_code(), ResponseCode::ServFail);
    assert!(response.answers().is_empty());
    assert!(response.authorities().is_empty());
    assert!(response.additionals().is_empty());
}

#[tokio::test]
async fn test_empty_chain_axfr() {
    subscribe();

    let mut catalog = Catalog::new();
    catalog.upsert(Name::root().into(), vec![]);

    let query = Query::query(Name::root(), RecordType::AXFR);
    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    message.add_query(query);

    let message_bytes = message.to_bytes().unwrap();
    let request =
        Request::from_bytes(message_bytes, ([127, 0, 0, 1], 53).into(), Protocol::Tcp).unwrap();

    let response_handler = TestResponseHandler::new();
    catalog
        .handle_request::<_, TokioTime>(&request, response_handler.clone())
        .await;
    let response = response_handler.into_message().await;

    assert_eq!(response.response_code(), ResponseCode::ServFail);
    assert!(response.answers().is_empty());
    assert!(response.authorities().is_empty());
    assert!(response.additionals().is_empty());
}

#[cfg(feature = "__dnssec")]
mod dnssec {
    use super::*;
    use hickory_proto::dnssec::{
        Nsec3HashAlgorithm, SigSigner, SigningKey, crypto::Ed25519SigningKey, rdata::DNSKEY,
    };

    fn make_catalog() -> Catalog {
        let origin = Name::parse("test.com.", None).unwrap();

        let mut records = InMemoryZoneHandler::empty(
            origin.clone(),
            ZoneType::Primary,
            AxfrPolicy::Deny,
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
        let mut question = Message::query();
        question.add_query(query);
        question
            .extensions_mut()
            .get_or_insert_with(Edns::new)
            .enable_dnssec();

        let question_bytes = question.to_bytes().unwrap();
        let question_req =
            Request::from_bytes(question_bytes, ([127, 0, 0, 1], 5553).into(), Protocol::Udp)
                .unwrap();

        let response_handler = TestResponseHandler::new();
        catalog
            .lookup(
                &question_req,
                None,
                TokioTime::current_time(),
                response_handler.clone(),
            )
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
            assert_eq!(rrsig.input().type_covered, RecordType::DNSKEY);
        }

        // Check NSEC3
        {
            let mut query = Query::new();
            query.set_name(Name::from_str("test.com.").unwrap());
            query.set_query_type(RecordType::NSEC);

            let result = run_query(&catalog, query).await;
            assert!(result.answers().is_empty());

            result
                .authorities()
                .iter()
                .find(|e| e.record_type() == RecordType::SOA)
                .expect("authority section to contains SOA");

            let nsec3 = result
                .authorities()
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
                    !nsec3.type_bit_maps().any(|r| r == denied),
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
                    nsec3.type_bit_maps().any(|r| r == required),
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
