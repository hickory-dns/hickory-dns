// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Request Handler for incoming requests

use std::net::SocketAddr;

use bytes::Bytes;
use hickory_proto::op::{DEFAULT_MAX_PAYLOAD_LEN, Edns, LowerQuery};

#[cfg(any(test, feature = "testing"))]
use crate::proto::serialize::binary::{BinEncodable, BinEncoder};
use crate::{
    net::{runtime::Time, xfer::Protocol},
    proto::{
        ProtoError,
        op::{Header, MessageRequest, Metadata},
        serialize::binary::{BinDecodable, BinDecoder},
    },
};

/// An incoming request to the DNS catalog
#[derive(Debug)]
pub struct Request {
    /// Message with the associated query or update data
    pub(crate) message: MessageRequest,
    pub(crate) response_edns: Option<Edns>,
    pub(super) raw: Bytes,
    /// Source address of the Client
    pub(super) src: SocketAddr,
    /// Protocol of the request
    pub(super) protocol: Protocol,
}

impl Request {
    /// Construct a new Request from the raw bytes, source address, and protocol
    ///
    /// This is only used in tests.
    #[doc(hidden)]
    pub fn from_bytes(
        raw: Vec<u8>,
        src: SocketAddr,
        protocol: Protocol,
    ) -> Result<Self, ProtoError> {
        let mut decoder = BinDecoder::new(&raw);
        let header = Header::read(&mut decoder)?;
        let message = MessageRequest::read(&mut decoder, header)?;

        let response_edns = message
            .edns
            .as_ref()
            // Ignore bad EDNS version errors here -- only used for testing
            .map(|edns| Edns::for_response(edns, DEFAULT_MAX_PAYLOAD_LEN, None).0);

        Ok(Self {
            message,
            response_edns,
            raw: Bytes::from(raw),
            src,
            protocol,
        })
    }

    /// Construct a new Request from the encoding of a MessageRequest, source address, and protocol
    #[cfg(any(test, feature = "testing"))]
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
            response_edns: None,
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
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct ResponseInfo {
    /// Header for this response
    pub header: Header,
    /// The TTL this response may be cached for, if it is cacheable.
    ///
    /// `None` means the response is not cacheable. The TTL is derived while the response is
    /// encoded, so a `ResponseInfo` from any other source reports `None`.
    pub cache_ttl: Option<u32>,
    /// The encoded response message
    pub bytes: Vec<u8>,
}

impl std::ops::Deref for ResponseInfo {
    type Target = Metadata;

    fn deref(&self) -> &Self::Target {
        &self.header.metadata
    }
}

/// Trait for handling incoming requests, and providing a message response.
#[async_trait::async_trait]
pub trait RequestHandler: Send + Sync + Unpin + 'static {
    /// Determines what needs to happen given the type of request, i.e. Query or Update.
    ///
    /// Returns the encoded response message to send back to the client.
    ///
    /// # Arguments
    ///
    /// * `request` - the requested action to perform.
    async fn handle_request<T: Time>(&self, request: &Request) -> ResponseInfo;
}
