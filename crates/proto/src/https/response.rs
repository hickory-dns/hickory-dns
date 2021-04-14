// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! HTTP request creation and validation

use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{Response, StatusCode, Version};

use crate::error::ProtoError;
use crate::https::HttpsResult;

/// Create a new Response for an http/2 dns-message request
///
/// ```text
///  4.2.1.  Handling DNS and HTTP Errors
///
/// DNS response codes indicate either success or failure for the DNS
/// query.  A successful HTTP response with a 2xx status code ([RFC7231]
/// Section 6.3) is used for any valid DNS response, regardless of the
/// DNS response code.  For example, a successful 2xx HTTP status code is
/// used even with a DNS message whose DNS response code indicates
/// failure, such as SERVFAIL or NXDOMAIN.
///
/// HTTP responses with non-successful HTTP status codes do not contain
/// replies to the original DNS question in the HTTP request.  DoH
///
/// clients need to use the same semantic processing of non-successful
/// HTTP status codes as other HTTP clients.  This might mean that the
/// DoH client retries the query with the same DoH server, such as if
/// there are authorization failures (HTTP status code 401 [RFC7235]
/// Section 3.1).  It could also mean that the DoH client retries with a
/// different DoH server, such as for unsupported media types (HTTP
/// status code 415, [RFC7231] Section 6.5.13), or where the server
/// cannot generate a representation suitable for the client (HTTP status
/// code 406, [RFC7231] Section 6.5.6), and so on.
/// ```
pub fn new(message_len: usize) -> HttpsResult<Response<()>> {
    Response::builder()
        .status(StatusCode::OK)
        .version(Version::HTTP_2)
        .header(CONTENT_TYPE, crate::https::MIME_APPLICATION_DNS)
        .header(CONTENT_LENGTH, message_len)
        .body(())
        .map_err(|e| ProtoError::from(format!("invalid response: {}", e)).into())
}
