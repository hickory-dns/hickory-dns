// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tracing::{debug, error, trace};

use crate::{
    net::{
        BufDnsStreamHandle, DnsStreamHandle, NetError, udp::MAX_RECEIVE_BUFFER_SIZE, xfer::Protocol,
    },
    proto::{
        ProtoError,
        op::{Header, MessageType, OpCode, ResponseCode, SerialMessage},
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

    /// Set a shared buffer to capture wire-format response bytes after serialization.
    ///
    /// Used by DNSTAP logging to capture the response message. The default
    /// implementation is a no-op for handlers that don't support capture.
    fn set_response_bytes_capture(&mut self, _capture: Arc<Mutex<Option<Vec<u8>>>>) {}

    /// Take the captured wire-format response bytes, if any.
    ///
    /// Returns `None` if no capture buffer was set or if no response has been
    /// sent yet. After calling this, the capture buffer is cleared.
    fn take_response_bytes(&mut self) -> Option<Vec<u8>> {
        None
    }
}

/// A handler for wrapping a [`BufDnsStreamHandle`], which will properly serialize the message and add the
///  associated destination.
#[derive(Clone)]
pub struct ResponseHandle {
    dst: SocketAddr,
    stream_handle: BufDnsStreamHandle,
    protocol: Protocol,
    /// Optional shared buffer for capturing the serialized response bytes (used by DNSTAP).
    response_bytes_capture: Option<Arc<Mutex<Option<Vec<u8>>>>>,
}

impl ResponseHandle {
    /// Returns a new `ResponseHandle` for sending a response message
    pub fn new(dst: SocketAddr, stream_handle: BufDnsStreamHandle, protocol: Protocol) -> Self {
        Self {
            dst,
            stream_handle,
            protocol,
            response_bytes_capture: None,
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
                if let Some(edns) = response.edns() {
                    edns.max_payload()
                } else {
                    // No EDNS, use the recommended max from RFC6891.
                    MAX_RECEIVE_BUFFER_SIZE as u16
                }
            }
            _ => u16::MAX,
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

        // Capture the serialized response bytes for DNSTAP logging if requested.
        if let Some(ref capture) = self.response_bytes_capture {
            if let Ok(mut guard) = capture.lock() {
                *guard = Some(buffer.clone());
            }
        }

        self.stream_handle
            .send(SerialMessage::new(buffer, self.dst))?;

        Ok(info)
    }

    fn set_response_bytes_capture(&mut self, capture: Arc<Mutex<Option<Vec<u8>>>>) {
        self.response_bytes_capture = Some(capture);
    }

    fn take_response_bytes(&mut self) -> Option<Vec<u8>> {
        self.response_bytes_capture
            .as_ref()
            .and_then(|c| c.lock().ok())
            .and_then(|mut guard| guard.take())
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
    let mut header = Header::new(id, MessageType::Response, OpCode::Query);
    header.set_response_code(ResponseCode::ServFail);
    header.emit(&mut encoder)?;

    Ok(ResponseInfo::from(header))
}
