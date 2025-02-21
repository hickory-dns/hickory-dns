// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{io, net::SocketAddr};

use hickory_proto::rr::Record;
use tracing::{debug, trace};

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
        debug!(
            "response: {} response_code: {}",
            response.header().id(),
            response.header().response_code(),
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

        let info = encode_result.map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("error encoding message: {e}"))
        })?;

        self.stream_handle
            .send(SerialMessage::new(buffer, self.dst))
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "unknown"))?;

        Ok(info)
    }
}
