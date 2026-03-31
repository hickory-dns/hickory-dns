// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::SocketAddr;

use crate::{
    net::{BufDnsStreamHandle, DnsStreamHandle, NetError, xfer::Protocol},
    proto::{
        ProtoError,
        op::{Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode, SerialMessage},
        rr::Record,
        serialize::binary::BinEncodable,
        serialize::binary::BinEncoder,
    },
    server::ResponseInfo,
    zone_handler::MessageResponse,
};

/// A handler for send a response to a client
#[async_trait::async_trait]
pub trait ResponseHandler: Clone + Send + Sync + Unpin + 'static {
    // TODO: add associated error type
    //type Error;

    /// Serializes and sends a message to the wrapped handle
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError>;
}

/// A handler for wrapping a [`BufDnsStreamHandle`], which will properly serialize the message and add the
///  associated destination.
#[derive(Clone)]
pub struct ResponseHandle {
    dst: SocketAddr,
    stream_handle: BufDnsStreamHandle,
    protocol: Protocol,
}

impl ResponseHandle {
    /// Returns a new `ResponseHandle` for sending a response message
    pub fn new(dst: SocketAddr, stream_handle: BufDnsStreamHandle, protocol: Protocol) -> Self {
        Self {
            dst,
            stream_handle,
            protocol,
        }
    }
}

#[async_trait::async_trait]
impl ResponseHandler for ResponseHandle {
    /// Serializes and sends a message to the wrapped handle
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        let (info, buffer) = response.encode(self.protocol)?;
        self.stream_handle
            .send(SerialMessage::new(buffer, self.dst))?;

        Ok(info)
    }
}

/// Clears the buffer, encodes a SERVFAIL response in it, and returns a matching
/// ResponseInfo.
pub(crate) fn encode_fallback_servfail_response(
    id: u16,
    buffer: &mut Vec<u8>,
) -> Result<ResponseInfo, ProtoError> {
    buffer.clear();
    let mut encoder = BinEncoder::new(buffer);
    encoder.set_max_size(512);

    let mut metadata = Metadata::new(id, MessageType::Response, OpCode::Query);
    metadata.response_code = ResponseCode::ServFail;
    let header = Header {
        metadata,
        counts: HeaderCounts::default(),
    };

    header.emit(&mut encoder)?;
    Ok(ResponseInfo::from(header))
}
