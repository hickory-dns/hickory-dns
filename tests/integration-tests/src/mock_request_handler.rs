use async_trait::async_trait;
#[cfg(feature = "__dnssec")]
use hickory_client::client::{ClientHandle, DnssecClient};
#[cfg(feature = "__dnssec")]
use hickory_proto::rr::DNSClass;
use hickory_proto::{
    op::{DnsResponse, Header, MessageType, ResponseCode},
    rr::{LowerName, RecordType},
    runtime::Time,
};
use hickory_resolver::Name;
use hickory_server::{
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
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
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let request_info = request.request_info().unwrap();
        if request_info.query.name() == &self.query_name
            && request_info.query.query_type() == self.query_type
        {
            send_response(response_handle, request, &self.response).await
        } else if request_info.query.name() == &self.dnskey_name
            && request_info.query.query_type() == RecordType::DNSKEY
        {
            send_response(response_handle, request, &self.dnskey_response).await
        } else {
            error!(query = ?request_info.query, "unexpected request");
            let response_builder = MessageResponseBuilder::from_message_request(request);
            let mut response_header = Header::response_from_request(request.header());
            response_header.set_response_code(ResponseCode::ServFail);
            let result = response_handle
                .send_response(response_builder.build_no_records(response_header))
                .await;
            if let Err(e) = result {
                error!(error = %e, "error responding to request");
            }
            response_header.into()
        }
    }
}

/// Helper for implementation of `RequestHandler`.
///
/// Turns a `DnsResponse` into a `MessageResponse`, performs error handling, and produces a
/// `ResponseInfo`.
async fn send_response(
    mut response_handle: impl ResponseHandler,
    request: &Request,
    response: &DnsResponse,
) -> ResponseInfo {
    let mut response_header = *response.header();
    response_header.set_id(request.id());

    let mut message_response_builder = MessageResponseBuilder::from_message_request(request);
    if let Some(edns) = response.extensions() {
        message_response_builder.edns(edns);
    }
    let message_response = message_response_builder.build(
        response_header,
        response.answers(),
        response.authorities(),
        [],
        response.additionals(),
    );

    let result = response_handle.send_response(message_response).await;
    match result {
        Ok(info) => info,
        Err(e) => {
            error!(error = %e, "error responding to request");
            let mut header = Header::new(
                request.id(),
                MessageType::Response,
                request.header().op_code(),
            );
            header.set_response_code(ResponseCode::ServFail);
            ResponseInfo::from(header)
        }
    }
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
    assert_eq!(dnskey_response.response_code(), ResponseCode::NoError);
    dnskey_response
}
