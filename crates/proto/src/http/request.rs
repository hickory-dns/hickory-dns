// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! HTTP request creation and validation

use alloc::sync::Arc;
use core::str::FromStr;

use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use http::{Request, Uri, header, uri};
use tracing::debug;

use super::error::Result;
use super::{SetHeaders, Version};
use crate::error::ProtoError;

pub(crate) struct RequestContext {
    pub(crate) version: Version,
    pub(crate) server_name: Arc<str>,
    pub(crate) query_path: Arc<str>,
    pub(crate) set_headers: Option<Arc<dyn SetHeaders>>,
}

impl RequestContext {
    /// Create a new Request for an http dns-message request
    ///
    /// ```text
    /// RFC 8484              DNS Queries over HTTPS (DoH)          October 2018
    ///
    /// The URI Template defined in this document is processed without any
    /// variables when the HTTP method is POST.  When the HTTP method is GET,
    /// the single variable "dns" is defined as the content of the DNS
    /// request (as described in Section 6), encoded with base64url
    /// [RFC4648].
    /// ```
    pub(crate) fn build(&self, message_len: usize) -> Result<Request<()>> {
        let mut parts = uri::Parts::default();
        parts.path_and_query = Some(
            uri::PathAndQuery::try_from(&*self.query_path)
                .map_err(|e| ProtoError::from(format!("invalid DoH path: {e}")))?,
        );
        parts.scheme = Some(uri::Scheme::HTTPS);
        parts.authority = Some(
            uri::Authority::from_str(&self.server_name)
                .map_err(|e| ProtoError::from(format!("invalid authority: {e}")))?,
        );

        let url = Uri::from_parts(parts)
            .map_err(|e| ProtoError::from(format!("uri parse error: {e}")))?;

        // TODO: add user agent to TypedHeaders
        let mut request = Request::builder()
            .method("POST")
            .uri(url)
            .version(self.version.to_http())
            .header(CONTENT_TYPE, crate::http::MIME_APPLICATION_DNS)
            .header(ACCEPT, crate::http::MIME_APPLICATION_DNS)
            .header(CONTENT_LENGTH, message_len);

        if let Some(headers) = &self.set_headers {
            if let Some(map) = request.headers_mut() {
                headers.set_headers(map)?;
            }
        }

        Ok(request
            .body(())
            .map_err(|e| ProtoError::from(format!("http stream errored: {e}")))?)
    }
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
    use alloc::vec::Vec;
    use http::{
        HeaderMap,
        header::{HeaderName, HeaderValue},
    };

    use super::*;

    #[test]
    #[cfg(feature = "__https")]
    fn test_new_verify_h2() {
        let cx = RequestContext {
            version: Version::Http2,
            server_name: Arc::from("ns.example.com"),
            query_path: Arc::from("/dns-query"),
            set_headers: None,
        };

        let request = cx.build(512).expect("error converting to http");
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
    #[cfg(feature = "__https")]
    fn test_additional_headers() {
        let cx = RequestContext {
            version: Version::Http2,
            server_name: Arc::from("ns.example.com"),
            query_path: Arc::from("/dns-query"),
            set_headers: Some(Arc::new(vec![(
                HeaderName::from_static("test-header"),
                HeaderValue::from_static("test-header-value"),
            )]) as Arc<dyn SetHeaders>),
        };

        let request = cx.build(512).expect("error converting to http");
        assert!(
            verify(
                Version::Http2,
                Some("ns.example.com"),
                "/dns-query",
                &request
            )
            .is_ok()
        );

        assert_eq!(
            request
                .headers()
                .get(HeaderName::from_static("test-header"))
                .expect("header to be set"),
            HeaderValue::from_static("test-header-value")
        )
    }

    #[test]
    #[cfg(feature = "__h3")]
    fn test_new_verify_h3() {
        let cx = RequestContext {
            version: Version::Http3,
            server_name: Arc::from("ns.example.com"),
            query_path: Arc::from("/dns-query"),
            set_headers: None,
        };

        let request = cx.build(512).expect("error converting to http");
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

    impl SetHeaders for Vec<(HeaderName, HeaderValue)> {
        fn set_headers(&self, map: &mut HeaderMap<HeaderValue>) -> Result<()> {
            for (name, value) in self.iter() {
                map.insert(name.clone(), value.clone());
            }
            Ok(())
        }
    }
}
