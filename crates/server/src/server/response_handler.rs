// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{io, net::SocketAddr};

use hickory_proto::{
    ProtoError,
    op::{Header, ResponseCode},
    rr::Record,
    serialize::binary::BinEncodable,
};
use tracing::{debug, error, trace};

use crate::{
    authority::MessageResponse,
    proto::{
        BufDnsStreamHandle, DnsStreamHandle,
        serialize::binary::BinEncoder,
        xfer::{Protocol, SerialMessage},
    },
    server::ResponseInfo,
};

/// A handler for send a response to a client
#[async_trait::async_trait]
pub trait ResponseHandler: Clone + Send + Sync + Unpin + 'static {
    // TODO: add associated error type
    //type Error;

    /// Serializes and sends a message to the wrapped handle
    ///
    /// self is consumed as only one message should ever be sent in response to a Request
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
    ) -> io::Result<ResponseInfo>;
}

/// A handler for wrapping a BufStreamHandle, which will properly serialize the message and add the
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

    /// Selects an appropriate maximum serialized size for the given response.
    fn max_size_for_response<'a>(
        &self,
        response: &MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> u16 {
        match self.protocol {
            Protocol::Udp => {
                // Use EDNS, if available.
                if let Some(edns) = response.get_edns() {
                    edns.max_payload()
                } else {
                    // No EDNS, use the recommended max from RFC6891.
                    hickory_proto::udp::MAX_RECEIVE_BUFFER_SIZE as u16
                }
            }
            _ => u16::MAX,
        }
    }
}

#[async_trait::async_trait]
impl ResponseHandler for ResponseHandle {
    /// Serializes and sends a message to to the wrapped handle
    ///
    /// self is consumed as only one message should ever be sent in response to a Request
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
    ) -> io::Result<ResponseInfo> {
        let id = response.header().id();
        debug!(
            id,
            response_code = %response.header().response_code(),
            "sending response",
        );
        let mut buffer = Vec::with_capacity(512);
        let encode_result = {
            let mut encoder = BinEncoder::new(&mut buffer);

            // Set an appropriate maximum on the encoder.
            let max_size = self.max_size_for_response(&response);
            trace!(
                "setting response max size: {max_size} for protocol: {:?}",
                self.protocol
            );
            encoder.set_max_size(max_size);

            response.destructive_emit(&mut encoder)
        };

        let info = encode_result.or_else(|error| {
            error!(%error, "error encoding message");
            encode_fallback_servfail_response(id, &mut buffer)
        })?;

        self.stream_handle
            .send(SerialMessage::new(buffer, self.dst))
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "unknown"))?;

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
    let mut header = Header::new();
    header.set_id(id);
    header.set_response_code(ResponseCode::ServFail);
    header.emit(&mut encoder)?;

    Ok(ResponseInfo::from(header))
}
