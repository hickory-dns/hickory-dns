// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! HTTP request creation and validation

use std::str::FromStr;

use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use http::{header, uri, Request, Uri, Version};
use tracing::debug;

use crate::error::ProtoError;
use crate::https::HttpsResult;

/// Create a new Request for an http/2 dns-message request
///
/// ```text
/// https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-10#section-5.1
/// The URI Template defined in this document is processed without any
/// variables when the HTTP method is POST.  When the HTTP method is GET
/// the single variable "dns" is defined as the content of the DNS
/// request (as described in Section 7), encoded with base64url
/// [RFC4648].
/// ```
#[allow(clippy::field_reassign_with_default)] // https://github.com/rust-lang/rust-clippy/issues/6527
pub fn new(name_server_name: &str, message_len: usize) -> HttpsResult<Request<()>> {
    // TODO: this is basically the GET version, but it is more expensive than POST
    //   perhaps add an option if people want better HTTP caching options.

    // let query = BASE64URL_NOPAD.encode(&message);
    // let url = format!("/dns-query?dns={}", query);
    // let request = Request::get(&url)
    //     .header(header::CONTENT_TYPE, ::MIME_DNS_BINARY)
    //     .header(header::HOST, &self.name_server_name as &str)
    //     .header("authority", &self.name_server_name as &str)
    //     .header(header::USER_AGENT, USER_AGENT)
    //     .body(());

    let mut parts = uri::Parts::default();
    parts.path_and_query = Some(uri::PathAndQuery::from_static(crate::https::DNS_QUERY_PATH));
    parts.scheme = Some(uri::Scheme::HTTPS);
    parts.authority = Some(
        uri::Authority::from_str(name_server_name)
            .map_err(|e| ProtoError::from(format!("invalid authority: {}", e)))?,
    );

    let url =
        Uri::from_parts(parts).map_err(|e| ProtoError::from(format!("uri parse error: {}", e)))?;

    // TODO: add user agent to TypedHeaders
    let request = Request::builder()
        .method("POST")
        .uri(url)
        .version(Version::HTTP_2)
        .header(CONTENT_TYPE, crate::https::MIME_APPLICATION_DNS)
        .header(ACCEPT, crate::https::MIME_APPLICATION_DNS)
        .header(CONTENT_LENGTH, message_len)
        .body(())
        .map_err(|e| ProtoError::from(format!("h2 stream errored: {}", e)))?;

    Ok(request)
}

/// Verifies the request is something we know what to deal with
pub fn verify<T>(name_server: &str, request: &Request<T>) -> HttpsResult<()> {
    // Verify all HTTP parameters
    let uri = request.uri();

    // validate path
    if uri.path() != crate::https::DNS_QUERY_PATH {
        return Err(format!(
            "bad path: {}, expected: {}",
            uri.path(),
            crate::https::DNS_QUERY_PATH
        )
        .into());
    }

    // we only accept HTTPS
    if Some(&uri::Scheme::HTTPS) != uri.scheme() {
        return Err("must be HTTPS scheme".into());
    }

    // the authority must match our nameserver name
    if let Some(authority) = uri.authority() {
        if authority.host() != name_server {
            return Err("incorrect authority".into());
        }
    } else {
        return Err("no authority in HTTPS request".into());
    }

    // TODO: switch to mime::APPLICATION_DNS when that stabilizes
    match request.headers().get(CONTENT_TYPE).map(|v| v.to_str()) {
        Some(Ok(ctype)) if ctype == crate::https::MIME_APPLICATION_DNS => {}
        _ => return Err("unsupported content type".into()),
    };

    // TODO: switch to mime::APPLICATION_DNS when that stabilizes
    match request.headers().get(ACCEPT).map(|v| v.to_str()) {
        Some(Ok(ctype)) => {
            let mut found = false;
            for mime_and_quality in ctype.split(',') {
                let mut parts = mime_and_quality.splitn(2, ';');
                match parts.next() {
                    Some(mime) if mime.trim() == crate::https::MIME_APPLICATION_DNS => {
                        found = true;
                        break;
                    }
                    Some(mime) if mime.trim() == "application/*" => {
                        found = true;
                        break;
                    }
                    _ => continue,
                }
            }

            if !found {
                return Err("does not accept content type".into());
            }
        }
        Some(Err(e)) => return Err(e.into()),
        None => return Err("Accept is unspecified".into()),
    };

    if request.version() != Version::HTTP_2 {
        return Err("only HTTP/2 supported".into());
    }

    debug!(
        "verified request from: {}",
        request
            .headers()
            .get(header::USER_AGENT)
            .map(|h| h.to_str().unwrap_or("bad user agent"))
            .unwrap_or("unknown user agent")
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_verify() {
        let request = new("ns.example.com", 512).expect("error converting to http");
        assert!(verify("ns.example.com", &request).is_ok());
    }
}
