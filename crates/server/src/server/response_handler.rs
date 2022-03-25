// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{io, net::SocketAddr};

use tracing::debug;
use trust_dns_proto::rr::Record;

use crate::{
    authority::MessageResponse,
    client::serialize::binary::BinEncoder,
    proto::{xfer::SerialMessage, BufDnsStreamHandle, DnsStreamHandle},
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
}

impl ResponseHandle {
    /// Returns a new `ResponseHandle` for sending a response message
    pub fn new(dst: SocketAddr, stream_handle: BufDnsStreamHandle) -> Self {
        Self { dst, stream_handle }
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
            response.destructive_emit(&mut encoder)
        };

        let info = encode_result.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("error encoding message: {}", e),
            )
        })?;

        self.stream_handle
            .send(SerialMessage::new(buffer, self.dst))
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "unknown"))?;

        Ok(info)
    }
}
