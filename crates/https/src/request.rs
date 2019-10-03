// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! HTTP request creation and validation

use std::str::FromStr;

use http::{header, uri, Method, Request, Uri, Version};
use typed_headers::{
    mime::Mime, Accept, ContentLength, ContentType, HeaderMapExt, Quality, QualityItem,
};

use trust_dns_proto::error::ProtoError;

use crate::HttpsResult;

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
    parts.path_and_query = Some(uri::PathAndQuery::from_static(crate::DNS_QUERY_PATH));
    parts.scheme = Some(uri::Scheme::HTTPS);
    parts.authority = Some(
        uri::Authority::from_str(&name_server_name)
            .map_err(|e| ProtoError::from(format!("invalid authority: {}", e)))?,
    );

    let url =
        Uri::from_parts(parts).map_err(|e| ProtoError::from(format!("uri parse error: {}", e)))?;

    let accepts_dns = Mime::from_str(crate::MIME_APPLICATION_DNS).unwrap();
    let content_type = ContentType(accepts_dns.clone());
    let accept = Accept(vec![QualityItem::new(accepts_dns, Quality::from_u16(1000))]);

    // TODO: add user agent to TypedHeaders
    let mut request = Request::post(url)
        .header(header::USER_AGENT, crate::USER_AGENT)
        .version(Version::HTTP_2)
        .body(())
        .map_err(|e| ProtoError::from(format!("h2 stream errored: {}", e)))?;

    request.headers_mut().typed_insert(&content_type);
    request.headers_mut().typed_insert(&accept);

    // future proof for when GET is supported
    if Method::POST == request.method() {
        request
            .headers_mut()
            .typed_insert(&ContentLength(message_len as u64));
    }

    Ok(request)
}

/// Verifies the request is something we know what to deal with
pub fn verify<T>(name_server: &str, request: &Request<T>) -> HttpsResult<()> {
    // Verify all HTTP parameters
    let uri = request.uri();

    // validate path
    if uri.path() != crate::DNS_QUERY_PATH {
        return Err(format!("bad path: {}, expected: {}", uri.path(), crate::DNS_QUERY_PATH).into());
    }

    // we only accept HTTPS
    if Some(&uri::Scheme::HTTPS) != uri.scheme_part() {
        return Err("must be HTTPS scheme".into());
    }

    // the authority must match our nameserver name
    if let Some(authority) = uri.authority_part() {
        if authority.host() != name_server {
            return Err("incorrect authority".into());
        }
    } else {
        return Err("no authority in HTTPS request".into());
    }

    let content_type: Option<ContentType> = request.headers().typed_get()?;
    let accept: Option<Accept> = request.headers().typed_get()?;

    // TODO: switch to mime::APPLICATION_DNS when that stabilizes
    if !content_type
        .map(|c| (c.type_() == crate::MIME_APPLICATION && c.subtype() == crate::MIME_DNS_BINARY))
        .unwrap_or(true)
    {
        return Err("unsupported content type".into());
    }

    let accept = accept.ok_or_else(|| "Accept is unspecified")?;

    // TODO: switch to mime::APPLICATION_DNS when that stabilizes
    if !accept
        .iter()
        .any(|q| (q.item.type_() == crate::MIME_APPLICATION && q.item.subtype() == crate::MIME_DNS_BINARY))
    {
        return Err("does not accept content type".into());
    }

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
