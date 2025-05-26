// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Request Handler for incoming requests

use std::net::SocketAddr;

use bytes::Bytes;

use crate::{
    authority::MessageRequest,
    proto::{
        ProtoError,
        op::{Header, LowerQuery, MessageType, ResponseCode},
        xfer::Protocol,
    },
    server::ResponseHandler,
};

/// An incoming request to the DNS catalog
#[derive(Debug)]
pub struct Request {
    /// Message with the associated query or update data
    pub(crate) message: MessageRequest,
    pub(crate) raw: Bytes,
    /// Source address of the Client
    src: SocketAddr,
    /// Protocol of the request
    protocol: Protocol,
}

impl Request {
    /// Build a new requests with the inbound message, source address, and protocol.
    ///
    /// This will return an error on bad verification.
    pub fn new(message: MessageRequest, raw: Bytes, src: SocketAddr, protocol: Protocol) -> Self {
        Self {
            message,
            raw,
            src,
            protocol,
        }
    }

    /// Return just the header and request information from the Request Message
    ///
    /// Returns an error if there is not exactly one query
    pub fn request_info(&self) -> Result<RequestInfo<'_>, ProtoError> {
        Ok(RequestInfo {
            src: self.src,
            protocol: self.protocol,
            header: self.message.header(),
            query: self.message.raw_queries().try_as_query()?,
        })
    }

    /// The IP address from which the request originated.
    pub fn src(&self) -> SocketAddr {
        self.src
    }

    /// The protocol that was used for the request
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// The raw bytes of the request
    pub fn as_slice(&self) -> &[u8] {
        &self.raw
    }
}

impl std::ops::Deref for Request {
    type Target = MessageRequest;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

// TODO: add ProtocolInfo that would have TLS details or other additional things...
/// A narrow view of the Request, specifically a verified single query for the request
#[non_exhaustive]
#[derive(Clone)]
pub struct RequestInfo<'a> {
    /// The source address from which the request came
    pub src: SocketAddr,
    /// The protocol used for the request
    pub protocol: Protocol,
    /// The header from the original request
    pub header: &'a Header,
    /// The query from the request
    pub query: &'a LowerQuery,
}

impl<'a> RequestInfo<'a> {
    /// Construct a new RequestInfo
    ///
    /// # Arguments
    ///
    /// * `src` - The source address from which the request came
    /// * `protocol` - The protocol used for the request
    /// * `header` - The header from the original request
    /// * `query` - The query from the request, LowerQuery is intended to reduce complexity for lookups in authorities
    pub fn new(
        src: SocketAddr,
        protocol: Protocol,
        header: &'a Header,
        query: &'a LowerQuery,
    ) -> Self {
        Self {
            src,
            protocol,
            header,
            query,
        }
    }
}

/// Information about the response sent for a request
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct ResponseInfo(Header);

impl ResponseInfo {
    pub(crate) fn serve_failed(request: &Request) -> Self {
        let mut header = Header::new(request.id(), MessageType::Response, request.op_code());
        header.set_response_code(ResponseCode::ServFail);
        header.into()
    }
}

impl From<Header> for ResponseInfo {
    fn from(header: Header) -> Self {
        Self(header)
    }
}

impl std::ops::Deref for ResponseInfo {
    type Target = Header;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Trait for handling incoming requests, and providing a message response.
#[async_trait::async_trait]
pub trait RequestHandler: Send + Sync + Unpin + 'static {
    /// Determines what needs to happen given the type of request, i.e. Query or Update.
    ///
    /// # Arguments
    ///
    /// * `request` - the requested action to perform.
    /// * `response_handle` - handle to which a return message should be sent
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::op::{Header, OpCode, Query};

    #[test]
    fn request_info_clone() {
        let query = Query::new();
        let header = Header::new(10, MessageType::Query, OpCode::Query);
        let lower_query = query.into();
        let origin = RequestInfo::new(
            "127.0.0.1:3000".parse().unwrap(),
            Protocol::Udp,
            &header,
            &lower_query,
        );
        let cloned = origin.clone();
        assert_eq!(origin.header, cloned.header);
    }
}
