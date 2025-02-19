// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! HTTP request creation and validation

use core::str::FromStr;

use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use http::{Request, Uri, header, uri};
use tracing::debug;

use crate::error::ProtoError;
use crate::http::Version;
use crate::http::error::Result;

/// Create a new Request for an http dns-message request
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
pub fn new(
    version: Version,
    name_server_name: &str,
    query_path: &str,
    message_len: usize,
) -> Result<Request<()>> {
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
    parts.path_and_query = Some(
        uri::PathAndQuery::try_from(query_path)
            .map_err(|e| ProtoError::from(format!("invalid DoH path: {e}")))?,
    );
    parts.scheme = Some(uri::Scheme::HTTPS);
    parts.authority = Some(
        uri::Authority::from_str(name_server_name)
            .map_err(|e| ProtoError::from(format!("invalid authority: {e}")))?,
    );

    let url =
        Uri::from_parts(parts).map_err(|e| ProtoError::from(format!("uri parse error: {e}")))?;

    // TODO: add user agent to TypedHeaders
    let request = Request::builder()
        .method("POST")
        .uri(url)
        .version(version.to_http())
        .header(CONTENT_TYPE, crate::http::MIME_APPLICATION_DNS)
        .header(ACCEPT, crate::http::MIME_APPLICATION_DNS)
        .header(CONTENT_LENGTH, message_len)
        .body(())
        .map_err(|e| ProtoError::from(format!("http stream errored: {e}")))?;

    Ok(request)
}

/// Verifies the request is something we know what to deal with
pub fn verify<T>(
    version: Version,
    name_server: Option<&str>,
    query_path: &str,
    request: &Request<T>,
) -> Result<()> {
    // Verify all HTTP parameters
    let uri = request.uri();

    // validate path
    if uri.path() != query_path {
        return Err(format!("bad path: {}, expected: {}", uri.path(), query_path,).into());
    }

    // we only accept HTTPS
    if Some(&uri::Scheme::HTTPS) != uri.scheme() {
        return Err("must be HTTPS scheme".into());
    }

    // the authority must match our nameserver name
    if let Some(name_server) = name_server {
        if let Some(authority) = uri.authority() {
            if authority.host() != name_server {
                return Err("incorrect authority".into());
            }
        } else {
            return Err("no authority in HTTPS request".into());
        }
    }

    // TODO: switch to mime::APPLICATION_DNS when that stabilizes
    match request.headers().get(CONTENT_TYPE).map(|v| v.to_str()) {
        Some(Ok(ctype)) if ctype == crate::http::MIME_APPLICATION_DNS => {}
        _ => return Err("unsupported content type".into()),
    };

    // TODO: switch to mime::APPLICATION_DNS when that stabilizes
    match request.headers().get(ACCEPT).map(|v| v.to_str()) {
        Some(Ok(ctype)) => {
            let mut found = false;
            for mime_and_quality in ctype.split(',') {
                let mut parts = mime_and_quality.splitn(2, ';');
                match parts.next() {
                    Some(mime) if mime.trim() == crate::http::MIME_APPLICATION_DNS => {
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

    if request.version() != version.to_http() {
        let message = match version {
            #[cfg(feature = "__https")]
            Version::Http2 => "only HTTP/2 supported",
            #[cfg(feature = "__h3")]
            Version::Http3 => "only HTTP/3 supported",
        };
        return Err(message.into());
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
    #[cfg(feature = "__https")]
    fn test_new_verify_h2() {
        let request = new(Version::Http2, "ns.example.com", "/dns-query", 512)
            .expect("error converting to http");
        assert!(
            verify(
                Version::Http2,
                Some("ns.example.com"),
                "/dns-query",
                &request
            )
            .is_ok()
        );
    }

    #[test]
    #[cfg(feature = "__h3")]
    fn test_new_verify_h3() {
        let request = new(Version::Http3, "ns.example.com", "/dns-query", 512)
            .expect("error converting to http");
        assert!(
            verify(
                Version::Http3,
                Some("ns.example.com"),
                "/dns-query",
                &request
            )
            .is_ok()
        );
    }
}
