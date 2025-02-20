use std::sync::Arc;

use hickory_integration::TestResponseHandler;
use hickory_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{LowerName, Name, RData, Record, RecordSet, RecordType, rdata::A},
    serialize::binary::{BinDecodable, BinEncodable},
    xfer::Protocol,
};
#[cfg(feature = "__dnssec")]
use hickory_server::{authority::Nsec3QueryInfo, dnssec::NxProofKind};
use hickory_server::{
    authority::{
        Authority, Catalog, LookupControlFlow, LookupError, LookupObject, LookupOptions,
        LookupRecords, MessageRequest, UpdateResult, ZoneType,
    },
    server::{Request, RequestInfo, ResponseInfo},
};
use test_support::subscribe;

/// Tests for the chained authority catalog.
#[tokio::test]
async fn chained_authority_test() {
    subscribe();
    let mut catalog = Catalog::new();

    let all_zeros = A::new(0, 0, 0, 0);
    let pri_lookup_ip = A::new(192, 0, 2, 1);
    let sec_lookup_ip = A::new(192, 0, 2, 2);
    let sec_consult_ip = A::new(192, 0, 2, 3);

    let pri_lookup_records = vec![
        (
            "primaryonly.example.com.",
            Some((ResponseType::ContinueOk, pri_lookup_ip)),
        ),
        (
            "primaryerr.example.com.",
            Some((ResponseType::ContinueErr, all_zeros)),
        ),
        (
            "breakerr.example.com.",
            Some((ResponseType::BreakErr, all_zeros)),
        ),
        (
            "continueboth.example.com.",
            Some((ResponseType::ContinueOk, pri_lookup_ip)),
        ),
        (
            "overwrite.example.com.",
            Some((ResponseType::ContinueOk, pri_lookup_ip)),
        ),
        (
            "breakok.example.com.",
            Some((ResponseType::BreakOk, pri_lookup_ip)),
        ),
        (
            "skipboth.example.com.",
            Some((ResponseType::Skip, all_zeros)),
        ),
        (
            "skipprimary.example.com.",
            Some((ResponseType::Skip, all_zeros)),
        ),
    ];

    let pri_consult_records = vec![
        ("breakok.example.com.", None),
        ("overwrite.example.com.", None),
    ];

    let sec_lookup_records = vec![
        (
            "continueboth.example.com.",
            Some((ResponseType::ContinueOk, sec_lookup_ip)),
        ),
        (
            "breakok.example.com.",
            Some((ResponseType::BreakOk, sec_lookup_ip)),
        ),
        (
            "skipboth.example.com.",
            Some((ResponseType::Skip, all_zeros)),
        ),
        (
            "skipprimary.example.com.",
            Some((ResponseType::ContinueOk, sec_lookup_ip)),
        ),
    ];

    let sec_consult_records = vec![
        ("breakok.example.com.", None),
        (
            "overwrite.example.com.",
            Some((ResponseType::ContinueOk, sec_consult_ip)),
        ),
        (
            "primaryerr.example.com.",
            Some((ResponseType::ContinueOk, sec_consult_ip)),
        ),
        (
            "breakerr.example.com.",
            Some((ResponseType::ContinueOk, sec_consult_ip)),
        ),
    ];

    let primary_authority = TestAuthority::new(
        Name::from_ascii("example.com.").unwrap(),
        pri_lookup_records,
        pri_consult_records,
    );

    let secondary_authority = TestAuthority::new(
        Name::from_ascii("example.com.").unwrap(),
        sec_lookup_records,
        sec_consult_records,
    );

    catalog.upsert(
        primary_authority.origin().clone(),
        vec![Arc::new(primary_authority), Arc::new(secondary_authority)],
    );

    // First test - the record only exists in the primary authority
    basic_test(&catalog, "primaryonly.example.com.", pri_lookup_ip).await;

    // Second test -- the record exists in both authorities; confirm the primary authority data
    // is returned
    basic_test(&catalog, "continueboth.example.com.", pri_lookup_ip).await;

    // Third test -- the record exists in the primary authority, but is overwritten by a record in
    // the secondary authority
    basic_test(&catalog, "overwrite.example.com.", sec_consult_ip).await;

    // Fourth test -- the record exists in the primary authority and is returned with Break -
    // verify consult methods are not consulted for any authority.
    basic_test(&catalog, "breakok.example.com.", pri_lookup_ip).await;

    // Fifth test -- primary returns skip, and the second authority has the record - verify the
    // rdata from the secondary authority is returned.
    basic_test(&catalog, "skipprimary.example.com.", sec_lookup_ip).await;

    // Sixth test - both authorities skip.  Verify the catalog returns Servfail
    error_test(&catalog, "skipboth.example.com.", ResponseCode::ServFail).await;

    // Seventh test -- Primary returns Continue(Err), secondary returns Ok with a record
    basic_test(&catalog, "primaryerr.example.com.", sec_consult_ip).await;

    // Eighth test -- Primary returns Break(Err); secondary consult WOULD result in a record
    // returned; verify no records
    error_test(&catalog, "breakerr.example.com.", ResponseCode::NXDomain).await;
}

struct TestAuthority {
    origin: LowerName,
    zone_type: ZoneType,
    lookup_records: TestRecords,
    consult_records: TestRecords,
}

impl TestAuthority {
    pub fn new(origin: Name, lookup_records: TestRecords, consult_records: TestRecords) -> Self {
        TestAuthority {
            origin: origin.into(),
            zone_type: ZoneType::External,
            lookup_records,
            consult_records,
        }
    }
}

#[async_trait::async_trait]
impl Authority for TestAuthority {
    type Lookup = LookupRecords;

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    /// What type is this zone
    fn zone_type(&self) -> ZoneType {
        self.zone_type
    }

    /// Return true if AXFR is allowed
    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        LookupControlFlow::Continue(Ok(LookupRecords::Empty))
    }

    #[cfg(feature = "__dnssec")]
    async fn get_nsec3_records(
        &self,
        _info: Nsec3QueryInfo<'_>,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        LookupControlFlow::Continue(Ok(LookupRecords::Empty))
    }

    #[cfg(feature = "__dnssec")]
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        None
    }

    async fn lookup(
        &self,
        name: &LowerName,
        _query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        let Some(res) = inner_lookup(name, &self.lookup_records, &lookup_options) else {
            panic!("reached end of records without a match");
        };
        res
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        self.lookup(
            request_info.query.name(),
            request_info.query.query_type(),
            lookup_options,
        )
        .await
    }

    async fn consult(
        &self,
        name: &LowerName,
        _rtype: RecordType,
        lookup_options: LookupOptions,
        last_result: LookupControlFlow<Box<dyn LookupObject>>,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        let Some(res) = inner_lookup(name, &self.consult_records, &lookup_options) else {
            return last_result;
        };
        res.map_dyn()
    }
}

#[derive(Debug)]
enum ResponseType {
    ContinueOk,
    BreakOk,
    ContinueErr,
    BreakErr,
    Skip,
}

/// This is a lookup table for inner_lookup, which is called by the test authority lookup and
/// consult methods.  Each entry in the Vec is a tuple, which represent a query string and action
/// pair.  The action is wrapped in an Option - for None variants, if the lookup or consult method
/// is queried for that name, the test will panic.  This covers cases where lookup and/or consult
/// should not be called, such as verifying that LookupControlFlow::Break is working properly.
/// The Some variant will include a ResponseType and a record. ResponseType is an enum that maps 1:1
/// to LookupControlFlow, and controls the control flow type returned to the catalog.  The record is
/// always an A record, and will be returned with the lookup records in Continue(Ok) and Break(Ok)
/// responses. It is used to distinguish between the primary and secondary authority having been the
/// source of the answer returned by the catalog.
type TestRecords = Vec<(&'static str, Option<(ResponseType, A)>)>;

fn inner_lookup(
    name: &LowerName,
    records: &TestRecords,
    lookup_options: &LookupOptions,
) -> Option<LookupControlFlow<LookupRecords>> {
    let ascii_name = &Name::from(name).to_ascii()[..];

    for record in records.iter() {
        let (record_name, action) = record;

        if *record_name == ascii_name {
            let Some((response_type, response_record)) = action else {
                panic!("unexpected query for {record_name} in lookup");
            };

            let mut rset = RecordSet::new(name.into(), RecordType::A, 1);
            rset.insert(
                Record::from_rdata(name.into(), 3600, RData::A(*response_record)),
                1,
            );

            let lookup = LookupRecords::new(*lookup_options, rset.into());

            use LookupControlFlow::*;
            match response_type {
                ResponseType::ContinueOk => return Some(Continue(Ok(lookup))),
                ResponseType::BreakOk => return Some(Break(Ok(lookup))),
                ResponseType::ContinueErr => {
                    return Some(Continue(Err(LookupError::ResponseCode(
                        ResponseCode::NXDomain,
                    ))));
                }
                ResponseType::BreakErr => {
                    return Some(Break(Err(LookupError::ResponseCode(
                        ResponseCode::NXDomain,
                    ))));
                }
                ResponseType::Skip => return Some(LookupControlFlow::Skip),
            }
        }
    }

    None
}

// Boilerplate to query the catalog
async fn do_query(catalog: &Catalog, query_name: &str) -> (ResponseInfo, TestResponseHandler) {
    let mut question: Message = Message::new();

    let mut query: Query = Query::new();
    query.set_name(Name::from_ascii(query_name).unwrap());
    question.add_query(query);
    question.set_recursion_desired(true);
    question.set_authentic_data(true);

    let question_bytes = question.to_bytes().unwrap();
    let question_req = MessageRequest::from_bytes(&question_bytes).unwrap();
    let question_req = Request::new(question_req, ([127, 0, 0, 1], 5553).into(), Protocol::Udp);
    let response_handler = TestResponseHandler::new();

    let res = catalog
        .lookup(&question_req, None, response_handler.clone())
        .await;
    (res, response_handler)
}

// Handle boilerplate for the most common test case pattern: a positive response with a single A
// record.
async fn basic_test(catalog: &Catalog, query_name: &'static str, answer: A) {
    let (_, response_handler) = do_query(catalog, query_name).await;
    let result = response_handler.into_message().await;

    let answers: &[Record] = result.answers();

    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.message_type(), MessageType::Response);
    assert!(!answers.is_empty());
    assert_eq!(answers.first().unwrap().record_type(), RecordType::A);
    assert_eq!(answers.first().unwrap().data(), &RData::A(answer));
}

async fn error_test(catalog: &Catalog, query_name: &str, r_code: ResponseCode) {
    let (res, _) = do_query(catalog, query_name).await;

    assert_eq!(res.response_code(), r_code);
    assert_eq!(res.answer_count(), 0);
}
