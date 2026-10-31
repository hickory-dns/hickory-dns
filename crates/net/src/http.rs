// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! HTTP protocol related components for DNS over HTTP/2 (DoH) and HTTP/3 (DoH3)

use core::future::Future;
use core::net::Ipv6Addr;
use core::str::FromStr;
use std::sync::Arc;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::{Stream, StreamExt};
use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use http::{
    HeaderMap, HeaderValue, Request, Response, StatusCode, Uri, header, response::Parts, uri,
};
use tracing::debug;

use crate::error::NetError;
use crate::proto::op::{DnsRequest, DnsResponse};
use crate::xfer::DnsResponseStream;

pub(crate) struct RequestContext {
    pub(crate) version: Version,
    pub(crate) server_name: Arc<str>,
    /// The port the server listens on: part of the request's authority unless it is 443, the
    /// default port of `https`.
    pub(crate) port: u16,
    pub(crate) query_path: Arc<str>,
    pub(crate) set_headers: Option<Arc<dyn SetHeaders>>,
}

impl RequestContext {
    /// The authority of the target URI: `server_name`, with the port unless it is 443, and in
    /// brackets if it is an IPv6 address.
    ///
    /// The `:authority` pseudo-header carries the authority of the target URI (RFC 9113 section
    /// 8.3.1, RFC 9114 section 4.3.1), and that includes the port unless it is the scheme's
    /// default (RFC 9110 sections 4.2.2 and 7.2). Without it, a request to a server on another
    /// port names the origin on port 443, which a server or proxy that routes by authority would
    /// send elsewhere or refuse.
    ///
    /// An IPv6 address is written in brackets in a URI's authority (RFC 3986 section 3.2.2), so
    /// that its colons are not taken for the port's; `server_name` holds it bare, as the TLS
    /// server name (RFC 6066 section 3 does not allow a literal there, but rustls matches it
    /// against the certificate's IP address entries).
    fn authority(&self) -> Result<uri::Authority, NetError> {
        let host = match self.server_name.parse::<Ipv6Addr>() {
            Ok(_) => format!("[{}]", self.server_name),
            Err(_) => self.server_name.to_string(),
        };
        let authority = match self.port {
            HTTPS_DEFAULT_PORT => uri::Authority::from_str(&host),
            port => uri::Authority::from_str(&format!("{host}:{port}")),
        };
        authority.map_err(|e| NetError::from(format!("invalid authority: {e}")))
    }

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
    pub(crate) fn build(&self, message_len: usize) -> Result<Request<()>, NetError> {
        let mut parts = uri::Parts::default();
        parts.path_and_query = Some(
            uri::PathAndQuery::try_from(&*self.query_path)
                .map_err(|e| NetError::from(format!("invalid DoH path: {e}")))?,
        );
        parts.scheme = Some(uri::Scheme::HTTPS);
        parts.authority = Some(self.authority()?);

        let url =
            Uri::from_parts(parts).map_err(|e| NetError::from(format!("uri parse error: {e}")))?;

        // TODO: add user agent to TypedHeaders
        let mut request = Request::builder()
            .method("POST")
            .uri(url)
            .version(self.version.to_http())
            .header(CONTENT_TYPE, MIME_APPLICATION_DNS)
            .header(ACCEPT, MIME_APPLICATION_DNS)
            .header(CONTENT_LENGTH, message_len);

        if let Some(headers) = &self.set_headers {
            if let Some(map) = request.headers_mut() {
                headers.set_headers(map)?;
            }
        }

        request
            .body(())
            .map_err(|e| NetError::from(format!("http stream errored: {e}")))
    }
}

/// The HTTP half of a DNS-over-HTTP client
///
/// A type implementing this trait owns the HTTP version-specific connection to a
/// DoH server and knows how to send a request and receive a response over it. Everything
/// above that, such as building the request from the `RequestContext`, and validating
/// and parsing the response will be implemented in the `http` module.
pub(crate) trait HttpSender: Clone + Send + 'static {
    /// Send `message`, and return the response head in `Parts` along with the complete response body
    ///
    /// Collects the body Bytes rather than handing back a stream. An HTTP/3 connection
    /// shares the same stream for send and recv, so this avoids having to split it there
    /// and simplifies the type signature of this method.
    fn send_http_request(
        &mut self,
        request: Request<()>,
        message: Bytes,
    ) -> impl Future<Output = Result<(Parts, BytesMut), NetError>> + Send;

    /// Serialize `request` and send it to the DoH server `sender` is connected to
    ///
    /// This is the shared implementation of [`crate::xfer::DnsRequestSender::send_message`] for every
    /// HTTP client; `is_shutdown` is the caller's own shutdown flag.
    fn send_request(&self, mut request: DnsRequest) -> DnsResponseStream {
        // per the RFC, a zero id allows for the HTTP packet to be cached better
        request.metadata.id = 0;

        let bytes = match request.to_vec() {
            Ok(bytes) => Bytes::from(bytes),
            Err(err) => return NetError::from(err).into(),
        };

        let request = match self.context().build(bytes.remaining()) {
            Ok(request) => request,
            Err(err) => return DnsResponseStream::from(err),
        };

        debug!(
            method = %request.method(),
            uri = %request.uri(),
            headers = ?request.headers(),
            "sending request"
        );

        let mut sender = self.clone();
        Box::pin(async move {
            let (parts, response_bytes) = sender.send_http_request(request, bytes).await?;

            debug!(status = %parts.status, headers = ?parts.headers, "got response");

            // Was it a successful request?
            if !parts.status.is_success() {
                let error_string = String::from_utf8_lossy(response_bytes.as_ref());

                // TODO: make explicit error type
                return Err(NetError::from(format!(
                    "http unsuccessful code: {}, message: {}",
                    parts.status, error_string
                )));
            }

            // in the case that the ContentType is not specified, we assume it's the standard DNS format
            let content_type = parts
                .headers
                .get(CONTENT_TYPE)
                .map(|h| {
                    h.to_str().map_err(|err| {
                        // TODO: make explicit error type
                        NetError::from(format!("ContentType header not a string: {err}"))
                    })
                })
                .unwrap_or(Ok(MIME_APPLICATION_DNS))?;

            if !is_dns_message(content_type) {
                return Err(NetError::from(format!(
                    "ContentType unsupported (must be '{}'): '{}'",
                    MIME_APPLICATION_DNS, content_type
                )));
            }

            // and finally convert the bytes into a DNS message
            DnsResponse::from_buffer(response_bytes.to_vec()).map_err(NetError::from)
        })
        .into()
    }

    /// The context describing the DoH server this client is connected to
    fn context(&self) -> &RequestContext;
}

/// Verifies the request is well-formed for the name-server and supported protocols
pub fn verify<T>(
    version: Version,
    name_server: Option<&str>,
    query_path: &str,
    request: &Request<T>,
) -> Result<(), NetError> {
    // Verify all HTTP parameters
    let uri = request.uri();

    // validate path
    if uri.path() != query_path {
        return Err(format!("bad path: {}, expected: {}", uri.path(), query_path).into());
    }

    // we only accept HTTPS
    if Some(&uri::Scheme::HTTPS) != uri.scheme() {
        return Err("must be HTTPS scheme".into());
    }

    // the authority must match our nameserver name
    if let Some(name_server) = name_server {
        if let Some(authority) = uri.authority() {
            if unbracketed(authority.host()) != name_server {
                return Err("incorrect authority".into());
            }
        } else {
            return Err("no authority in HTTPS request".into());
        }
    }

    // TODO: switch to mime::APPLICATION_DNS when that stabilizes
    match request.headers().get(CONTENT_TYPE).map(|v| v.to_str()) {
        Some(Ok(ctype)) if is_dns_message(ctype) => {}
        _ => return Err("unsupported content type".into()),
    };

    // TODO: switch to mime::APPLICATION_DNS when that stabilizes
    match request.headers().get(ACCEPT).map(|v| v.to_str()) {
        Some(Ok(ctype)) => {
            let mut found = false;
            for mime_and_quality in ctype.split(',') {
                let mut parts = mime_and_quality.splitn(2, ';');
                match parts.next() {
                    Some(mime) if mime.trim().eq_ignore_ascii_case(MIME_APPLICATION_DNS) => {
                        found = true;
                        break;
                    }
                    Some(mime) if mime.trim().eq_ignore_ascii_case("application/*") => {
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

/// Fetch the body of the request from the stream
pub async fn fetch_body<E: Into<NetError>>(
    mut stream: impl Stream<Item = Result<impl Buf, E>> + Unpin,
    length: Option<usize>,
) -> Result<BytesMut, NetError> {
    let mut bytes = BytesMut::with_capacity(512);
    loop {
        match stream.next().await {
            Some(Ok(frame)) => match bytes.len() + frame.remaining() > MAX_REQUEST_SIZE {
                true => return Err(NetError::RequestTooLarge),
                false => bytes.put(frame),
            },
            Some(Err(err)) => return Err(err.into()),
            None => match length {
                Some(length) if bytes.len() == length => return Ok(bytes),
                Some(_) => return Err("body size does not match expected content-length".into()),
                None => return Ok(bytes),
            },
        };
    }
}

const MAX_REQUEST_SIZE: usize = u16::MAX as usize;

/// Get the length of the body announced by the `content-length` header, if any
pub(crate) fn content_length(headers: &HeaderMap) -> Result<Option<usize>, NetError> {
    headers
        .get(CONTENT_LENGTH)
        .map(|v| v.to_str())
        .transpose()
        .map_err(|e| NetError::from(format!("bad headers received: {e}")))?
        .map(usize::from_str)
        .transpose()
        .map_err(|e| NetError::from(format!("bad headers received: {e}")))
}

/// Create a new Response for an http dns-message request
///
/// ```text
/// RFC 8484              DNS Queries over HTTPS (DoH)          October 2018
///
///  4.2.1.  Handling DNS and HTTP Errors
///
/// DNS response codes indicate either success or failure for the DNS
/// query.  A successful HTTP response with a 2xx status code (see
/// Section 6.3 of [RFC7231]) is used for any valid DNS response,
/// regardless of the DNS response code.  For example, a successful 2xx
/// HTTP status code is used even with a DNS message whose DNS response
/// code indicates failure, such as SERVFAIL or NXDOMAIN.
///
/// HTTP responses with non-successful HTTP status codes do not contain
/// replies to the original DNS question in the HTTP request.  DoH
/// clients need to use the same semantic processing of non-successful
/// HTTP status codes as other HTTP clients.  This might mean that the
/// DoH client retries the query with the same DoH server, such as if
/// there are authorization failures (HTTP status code 401; see
/// Section 3.1 of [RFC7235]).  It could also mean that the DoH client
/// retries with a different DoH server, such as for unsupported media
/// types (HTTP status code 415; see Section 6.5.13 of [RFC7231]), or
/// where the server cannot generate a representation suitable for the
/// client (HTTP status code 406; see Section 6.5.6 of [RFC7231]), and so
/// on.
/// ```
pub fn response(version: Version, message_len: usize) -> Result<Response<()>, NetError> {
    Response::builder()
        .status(StatusCode::OK)
        .version(version.to_http())
        .header(CONTENT_TYPE, MIME_APPLICATION_DNS)
        .header(CONTENT_LENGTH, message_len)
        .body(())
        .map_err(|e| NetError::from(format!("invalid response: {e}")))
}

/// Represents a version of the HTTP spec.
#[derive(Clone, Copy, Debug)]
pub enum Version {
    /// HTTP/2 for DoH.
    #[cfg(feature = "__https")]
    Http2,
    /// HTTP/3 for DoH3.
    #[cfg(feature = "__h3")]
    Http3,
}

impl Version {
    fn to_http(self) -> http::Version {
        match self {
            #[cfg(feature = "__https")]
            Self::Http2 => http::Version::HTTP_2,
            #[cfg(feature = "__h3")]
            Self::Http3 => http::Version::HTTP_3,
        }
    }
}

/// Helper trait to update HTTP headers on requests
///
/// For instance a DoH server may require authentication based
/// on per-request HTTP headers and this trait allows their addition.
pub trait SetHeaders: Send + Sync + 'static {
    /// Get a set of headers to add to the query
    fn set_headers(&self, headers: &mut HeaderMap<HeaderValue>) -> Result<(), NetError>;
}

pub(crate) const MIME_APPLICATION_DNS: &str = "application/dns-message";

/// The default port of the `https` scheme (RFC 9110 section 4.2.2).
const HTTPS_DEFAULT_PORT: u16 = 443;

/// A URI's host without the brackets around an IPv6 address (RFC 3986 section 3.2.2), as a
/// server name holds it.
fn unbracketed(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
}

/// Whether a `Content-Type` value names [`MIME_APPLICATION_DNS`].
///
/// The type and subtype are case-insensitive, and may be followed by semicolon-delimited
/// parameters (RFC 9110 section 8.3.1). RFC 8484 section 7.1 registers no parameters for
/// `application/dns-message`, so a parameter a peer adds carries no meaning and is ignored, as
/// MIME implementations ignore parameters they do not recognise (RFC 2045 section 5.1), instead
/// of making the message unreadable.
pub(crate) fn is_dns_message(content_type: &str) -> bool {
    let media_type = content_type.split(';').next().unwrap_or_default();
    media_type.trim().eq_ignore_ascii_case(MIME_APPLICATION_DNS)
}

/// The default query path for DNS-over-HTTPS if none was given.
pub const DEFAULT_DNS_QUERY_PATH: &str = "/dns-query";

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures_util::stream;
    use http::{
        HeaderMap,
        header::{HeaderName, HeaderValue},
    };

    use super::*;

    #[test]
    fn dns_message_media_type_matches_case_insensitively_without_parameters() {
        for accepted in [
            "application/dns-message",
            "Application/DNS-Message",
            "APPLICATION/DNS-MESSAGE",
            "application/dns-message;charset=utf-8",
            "application/dns-message ; charset=utf-8",
            "application/dns-message;",
        ] {
            assert!(is_dns_message(accepted), "{accepted:?}");
        }
        for refused in [
            "",
            "application/json",
            "application/dns-json",
            "application/dns-messages",
            "application/dns",
            "text/dns-message",
            "application/octet-stream; type=application/dns-message",
        ] {
            assert!(!is_dns_message(refused), "{refused:?}");
        }
    }

    #[test]
    #[cfg(feature = "__https")]
    fn test_verify_accepts_parameters_and_case() {
        let mut request = RequestContext {
            version: Version::Http2,
            server_name: Arc::from("ns.example.com"),
            port: 443,
            query_path: Arc::from("/dns-query"),
            set_headers: None,
        }
        .build(512)
        .expect("error converting to http");
        request.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("Application/DNS-Message; charset=utf-8"),
        );
        request
            .headers_mut()
            .insert(ACCEPT, HeaderValue::from_static("Application/DNS-Message"));
        verify(
            Version::Http2,
            Some("ns.example.com"),
            "/dns-query",
            &request,
        )
        .expect("failed to verify");

        request
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        assert!(
            verify(
                Version::Http2,
                Some("ns.example.com"),
                "/dns-query",
                &request
            )
            .is_err()
        );
    }

    #[test]
    #[cfg(feature = "__https")]
    fn test_authority_carries_a_port_other_than_443() {
        for (port, authority) in [(443, "ns.example.com"), (8443, "ns.example.com:8443")] {
            let request = RequestContext {
                version: Version::Http2,
                server_name: Arc::from("ns.example.com"),
                port,
                query_path: Arc::from("/dns-query"),
                set_headers: None,
            }
            .build(512)
            .expect("error converting to http");
            assert_eq!(
                request.uri().authority().map(|a| a.as_str()),
                Some(authority)
            );
            verify(
                Version::Http2,
                Some("ns.example.com"),
                "/dns-query",
                &request,
            )
            .expect("failed to verify");
        }
    }

    #[test]
    #[cfg(feature = "__https")]
    fn test_authority_brackets_an_ipv6_address() {
        for (server_name, port, authority) in [
            ("2001:db8::53", 443, "[2001:db8::53]"),
            ("2001:db8::53", 8443, "[2001:db8::53]:8443"),
            ("::1", 8443, "[::1]:8443"),
            ("192.0.2.53", 8443, "192.0.2.53:8443"),
        ] {
            let request = RequestContext {
                version: Version::Http2,
                server_name: Arc::from(server_name),
                port,
                query_path: Arc::from("/dns-query"),
                set_headers: None,
            }
            .build(512)
            .expect("error converting to http");
            assert_eq!(
                request.uri().authority().map(|a| a.as_str()),
                Some(authority)
            );
            verify(Version::Http2, Some(server_name), "/dns-query", &request)
                .expect("failed to verify");
        }
    }

    #[test]
    #[cfg(feature = "__https")]
    fn test_new_verify_h2() {
        let cx = RequestContext {
            version: Version::Http2,
            server_name: Arc::from("ns.example.com"),
            port: 443,
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
            port: 443,
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
            port: 443,
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
        fn set_headers(&self, map: &mut HeaderMap<HeaderValue>) -> Result<(), NetError> {
            for (name, value) in self.iter() {
                map.insert(name.clone(), value.clone());
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn fetch_body_accumulates_chunks() {
        let mut body = chunks(&[512, 512, 200]);
        let bytes = fetch_body(&mut body, None).await.unwrap();
        assert_eq!(bytes.len(), 1224);
    }

    #[tokio::test]
    async fn fetch_body_stops_at_content_length() {
        let mut body = chunks(&[512, 512]);
        assert!(fetch_body(&mut body, Some(512)).await.is_err());
    }

    #[tokio::test]
    async fn fetch_body_short_body_errors() {
        let mut body = chunks(&[512]);
        assert!(fetch_body(&mut body, Some(1024)).await.is_err());
    }

    #[tokio::test]
    async fn fetch_body_single_oversized_chunk() {
        // a single chunk exceeding the limit is rejected without being buffered
        let mut body = chunks(&[MAX_REQUEST_SIZE + 1]);
        assert!(matches!(
            fetch_body(&mut body, None).await,
            Err(NetError::RequestTooLarge)
        ));
    }

    #[tokio::test]
    async fn fetch_body_accumulated_oversize_rejected() {
        // no single chunk is too large, but together they exceed the limit
        let half = MAX_REQUEST_SIZE / 2 + 1;
        let mut body = chunks(&[half, half]);
        assert!(matches!(
            fetch_body(&mut body, None).await,
            Err(NetError::RequestTooLarge)
        ));
    }

    #[tokio::test]
    async fn fetch_body_at_limit_ok() {
        // a body exactly at the limit is still accepted
        let mut body = chunks(&[MAX_REQUEST_SIZE]);
        let bytes = fetch_body(&mut body, None).await.unwrap();
        assert_eq!(bytes.len(), MAX_REQUEST_SIZE);
    }

    fn chunks(lengths: &[usize]) -> impl Stream<Item = Result<Bytes, NetError>> + Unpin {
        stream::iter(
            lengths
                .iter()
                .map(|&len| Ok(Bytes::from(vec![0u8; len])))
                .collect::<Vec<_>>(),
        )
    }
}
