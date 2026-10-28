// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Request Handler for incoming requests

use std::net::SocketAddr;

use bytes::Bytes;
use hickory_proto::op::LowerQuery;

#[cfg(feature = "testing")]
use crate::proto::serialize::binary::{BinEncodable, BinEncoder};
use crate::{
    net::{runtime::Time, xfer::Protocol},
    proto::{
        ProtoError,
        op::{Header, HeaderCounts, MessageRequest, MessageType, Metadata, ResponseCode},
        serialize::binary::{BinDecodable, BinDecoder},
    },
    server::ResponseHandler,
};

/// An incoming request to the DNS catalog
#[derive(Debug)]
pub struct Request {
    /// Message with the associated query or update data
    pub(crate) message: MessageRequest,
    pub(super) raw: Bytes,
    /// Source address of the Client
    pub(super) src: SocketAddr,
    /// Protocol of the request
    pub(super) protocol: Protocol,
}

impl Request {
    /// Construct a new Request from the raw bytes, source address, and protocol
    pub fn from_bytes(
        raw: Vec<u8>,
        src: SocketAddr,
        protocol: Protocol,
    ) -> Result<Self, ProtoError> {
        let mut decoder = BinDecoder::new(&raw);
        let header = Header::read(&mut decoder)?;
        Ok(Self {
            message: MessageRequest::read(&mut decoder, header)?,
            raw: Bytes::from(raw),
            src,
            protocol,
        })
    }

    /// Construct a new Request from the encoding of a MessageRequest, source address, and protocol
    #[cfg(feature = "testing")]
    pub fn from_message(
        message: MessageRequest,
        src: SocketAddr,
        protocol: Protocol,
    ) -> Result<Self, ProtoError> {
        let mut encoded = Vec::new();
        let mut encoder = BinEncoder::new(&mut encoded);
        message.emit(&mut encoder)?;

        Ok(Self {
            message,
            raw: Bytes::from(encoded),
            src,
            protocol,
        })
    }

    pub(crate) fn max_payload_size(&self) -> Option<u16> {
        self.message.edns.as_ref().map(|edns| edns.max_payload())
    }

    /// The query contained in the request
    pub fn query(&self) -> &LowerQuery {
        &self.message.queries
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

/// Information about the response sent for a request
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct ResponseInfo(Header);

impl ResponseInfo {
    pub(crate) fn serve_failed(request: &Request) -> Self {
        let mut metadata = Metadata::new(
            request.metadata.id,
            MessageType::Response,
            request.metadata.op_code,
        );
        metadata.response_code = ResponseCode::ServFail;
        Self(Header {
            metadata,
            counts: HeaderCounts::default(),
        })
    }

    /// Header counts for the response
    pub fn counts(&self) -> HeaderCounts {
        self.0.counts
    }
}

impl From<Header> for ResponseInfo {
    fn from(value: Header) -> Self {
        Self(value)
    }
}

impl std::ops::Deref for ResponseInfo {
    type Target = Metadata;

    fn deref(&self) -> &Self::Target {
        &self.0.metadata
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
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
    );
}
