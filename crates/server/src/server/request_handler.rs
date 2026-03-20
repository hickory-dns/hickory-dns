// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Request Handler for incoming requests

use std::net::SocketAddr;

use bytes::Bytes;

#[cfg(feature = "testing")]
use crate::proto::serialize::binary::{BinEncodable, BinEncoder};
use crate::{
    net::{runtime::Time, xfer::Protocol},
    proto::{
        ProtoError,
        op::{Header, HeaderCounts, LowerQuery, Message, MessageType, Metadata, ResponseCode},
        rr::{Record, rdata::TSIG},
        serialize::binary::{BinDecodable, BinDecoder},
    },
    server::ResponseHandler,
    zone_handler::{LookupError, Queries, UpdateRequest},
};

/// An incoming request to the DNS catalog
#[derive(Debug)]
pub struct Request {
    /// Message with the associated query or update data
    pub(crate) message: Message,
    /// Server-side query data with cached wire bytes and lowercased names
    pub(crate) server_queries: Queries,
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
        let raw = Bytes::from(raw);
        let mut decoder = BinDecoder::new(&raw);
        let header = Header::read(&mut decoder)?;
        Ok(Self::read(&mut decoder, header, raw.clone(), src, protocol)?)
    }

    /// Construct a new Request from the encoding of a Message, source address, and protocol
    #[cfg(feature = "testing")]
    pub fn from_message(
        message: Message,
        src: SocketAddr,
        protocol: Protocol,
    ) -> Result<Self, ProtoError> {
        let mut encoded = Vec::new();
        let mut encoder = BinEncoder::new(&mut encoded);
        message.emit(&mut encoder)?;

        let server_queries = Queries::from_queries(&message.queries);

        Ok(Self {
            message,
            server_queries,
            raw: Bytes::from(encoded),
            src,
            protocol,
        })
    }

    /// Construct a mock Request for testing purposes
    ///
    /// The unspecified fields are left empty.
    #[cfg(any(test, feature = "testing"))]
    pub fn mock(metadata: Metadata, query: impl Into<LowerQuery>) -> Self {
        let lower_query: LowerQuery = query.into();
        let query_clone = lower_query.original().clone();
        let server_queries = Queries::new(vec![lower_query]);
        let mut message = Message::new(metadata.id, metadata.message_type, metadata.op_code);
        message.metadata = metadata;
        message.queries = vec![query_clone];
        Self {
            message,
            server_queries,
            raw: Bytes::new(),
            src: SocketAddr::from(([127, 0, 0, 1], 53)),
            protocol: Protocol::Udp,
        }
    }

    /// Return just the header and request information from the Request Message
    ///
    /// Returns an error if there is not exactly one query
    pub fn request_info(&self) -> Result<RequestInfo<'_>, LookupError> {
        Ok(RequestInfo {
            src: self.src,
            protocol: self.protocol,
            metadata: &self.message.metadata,
            query: self.server_queries.try_as_query()?,
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

    /// Construct a Request from a pre-parsed header and decoder
    pub(super) fn read(
        decoder: &mut BinDecoder<'_>,
        header: Header,
        raw: Bytes,
        src: SocketAddr,
        protocol: Protocol,
    ) -> Result<Self, crate::proto::serialize::binary::DecodeError> {
        let Header {
            mut metadata,
            counts,
        } = header;

        let server_queries = Queries::read(decoder, counts.query_count as usize)?;
        let queries = server_queries
            .queries()
            .iter()
            .map(|lq| lq.original().clone())
            .collect();
        let (answers, _, _) =
            Message::read_records(decoder, counts.answer_count as usize, false)?;
        let (authorities, _, _) =
            Message::read_records(decoder, counts.authority_count as usize, false)?;
        let (additionals, edns, signature) =
            Message::read_records(decoder, counts.additional_count as usize, true)?;

        if let Some(edns) = &edns {
            metadata.merge_response_code(edns.rcode_high());
        }

        let mut message = Message::new(metadata.id, metadata.message_type, metadata.op_code);
        message.metadata = metadata;
        message.queries = queries;
        message.answers = answers;
        message.authorities = authorities;
        message.additionals = additionals;
        message.signature = signature;
        message.edns = edns;

        Ok(Self {
            message,
            server_queries,
            raw,
            src,
            protocol,
        })
    }
}

impl std::ops::Deref for Request {
    type Target = Message;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl UpdateRequest for Request {
    fn id(&self) -> u16 {
        self.message.metadata.id
    }

    fn zone(&self) -> Result<&LowerQuery, LookupError> {
        self.server_queries.try_as_query()
    }

    fn prerequisites(&self) -> &[Record] {
        &self.message.answers
    }

    fn updates(&self) -> &[Record] {
        &self.message.authorities
    }

    fn additionals(&self) -> &[Record] {
        &self.message.additionals
    }

    fn signature(&self) -> Option<&Record<TSIG>> {
        self.message.signature.as_deref()
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
    pub metadata: &'a Metadata,
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
    /// * `query` - The query from the request, LowerQuery is intended to reduce complexity for lookups in zone handlers
    pub fn new(
        src: SocketAddr,
        protocol: Protocol,
        metadata: &'a Metadata,
        query: &'a LowerQuery,
    ) -> Self {
        Self {
            src,
            protocol,
            metadata,
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
    ) -> ResponseInfo;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::op::{Metadata, OpCode, Query};

    #[test]
    fn request_info_clone() {
        let query = Query::new();
        let header = Metadata::new(10, MessageType::Query, OpCode::Query);
        let lower_query = query.into();
        let origin = RequestInfo::new(
            "127.0.0.1:3000".parse().unwrap(),
            Protocol::Udp,
            &header,
            &lower_query,
        );
        let cloned = origin.clone();
        assert_eq!(origin.metadata, cloned.metadata);
    }
}
