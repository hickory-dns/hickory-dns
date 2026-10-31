use async_trait::async_trait;
#[cfg(feature = "__dnssec")]
use hickory_net::client::{ClientHandle, DnssecClient};
use hickory_net::runtime::Time;
#[cfg(feature = "__dnssec")]
use hickory_proto::rr::DNSClass;
use hickory_proto::{
    op::{DnsResponse, Metadata, ResponseCode},
    rr::{LowerName, Name, RecordType},
};
use hickory_server::{
    server::{Request, RequestHandler, ResponseInfo},
    zone_handler::MessageResponseBuilder,
};
use tracing::error;

/// Replacement for `Catalog` that returns one of two canned responses.
pub struct MockHandler {
    query_name: LowerName,
    query_type: RecordType,
    response: DnsResponse,
    dnskey_name: LowerName,
    dnskey_response: DnsResponse,
}

impl MockHandler {
    pub fn new(
        query_name: LowerName,
        query_type: RecordType,
        response: DnsResponse,
        dnskey_response: DnsResponse,
    ) -> Self {
        let dnskey_name = Name::parse("example.", None).unwrap().into();
        Self {
            query_name,
            query_type,
            response,
            dnskey_name,
            dnskey_response,
        }
    }
}

#[async_trait]
impl RequestHandler for MockHandler {
    async fn handle_request<T: Time>(&self, request: &Request) -> ResponseInfo {
        let query = request.query();
        if query.name() == &self.query_name && query.query_type() == self.query_type {
            encode_response(request, &self.response)
        } else if query.name() == &self.dnskey_name && query.query_type() == RecordType::DNSKEY {
            encode_response(request, &self.dnskey_response)
        } else {
            error!(%query, "unexpected request");
            let response_builder = MessageResponseBuilder::from_message_request(request);
            let mut response_meta = Metadata::response_from_request(&request.metadata);
            response_meta.response_code = ResponseCode::ServFail;
            response_builder
                .build_no_records(response_meta)
                .encode(request.protocol())
        }
    }
}

/// Helper for implementation of `RequestHandler`.
///
/// Turns a `DnsResponse` into a `MessageResponse`, and encodes it into a `ResponseInfo`.
fn encode_response(request: &Request, response: &DnsResponse) -> ResponseInfo {
    let mut response_meta = response.metadata;
    response_meta.id = request.metadata.id;

    let mut message_response_builder = MessageResponseBuilder::from_message_request(request);
    if let Some(edns) = &response.edns {
        message_response_builder.edns(edns);
    }
    let message_response = message_response_builder.build(
        response_meta,
        &response.answers,
        &response.authorities,
        [],
        &response.additionals,
    );

    message_response.encode(request.protocol())
}

/// Helper to query `example. IN DNSKEY` and return the response.
///
/// This response is needed by [`MockHandler::new`].
#[cfg(feature = "__dnssec")]
pub async fn fetch_dnskey(client: &mut DnssecClient) -> DnsResponse {
    let dnskey_response = client
        .query(
            Name::parse("example.", None).unwrap(),
            DNSClass::IN,
            RecordType::DNSKEY,
        )
        .await
        .unwrap();
    assert_eq!(dnskey_response.response_code, ResponseCode::NoError);
    dnskey_response
}
