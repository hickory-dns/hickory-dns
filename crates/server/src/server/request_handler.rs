// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Request Handler for incoming requests

use std::net::SocketAddr;

use crate::{
    authority::MessageRequest,
    client::op::LowerQuery,
    proto::op::{Header, ResponseCode},
    server::{Protocol, ResponseHandler},
};

/// An incoming request to the DNS catalog
#[derive(Debug)]
pub struct Request {
    /// Message with the associated query or update data
    message: MessageRequest,
    /// Source address of the Client
    src: SocketAddr,
    /// Protocol of the request
    protocol: Protocol,
}

impl Request {
    /// Build a new requests with the inbound message, source address, and protocol.
    ///
    /// This will return an error on bad verification.
    pub fn new(message: MessageRequest, src: SocketAddr, protocol: Protocol) -> Self {
        Self {
            message,
            src,
            protocol,
        }
    }

    /// Return just the header and request information from the Request Message
    pub fn request_info(&self) -> RequestInfo<'_> {
        RequestInfo {
            src: self.src,
            protocol: self.protocol,
            header: self.message.header(),
            query: self.message.query(),
        }
    }

    /// The IP address from which the request originated.
    pub fn src(&self) -> SocketAddr {
        self.src
    }

    /// The protocol that was used for the request
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
}

impl std::ops::Deref for Request {
    type Target = MessageRequest;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

/// A narrow view of the Request, specifically a verified single query for the request
#[non_exhaustive]
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

/// Information about the response sent for a request
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct ResponseInfo(Header);

impl ResponseInfo {
    pub(crate) fn serve_failed() -> ResponseInfo {
        let mut header = Header::new();
        header.set_response_code(ResponseCode::ServFail);
        header.into()
    }
}

impl From<Header> for ResponseInfo {
    fn from(header: Header) -> Self {
        ResponseInfo(header)
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
