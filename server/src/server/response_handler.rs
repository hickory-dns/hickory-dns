// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io;
use std::net::SocketAddr;

use trust_dns::error::ClientError;
use trust_dns::serialize::binary::BinEncoder;
use trust_dns::BufStreamHandle;
use trust_dns_proto::xfer::SerialMessage;

use authority::MessageResponse;

/// A handler for send a response to a client
pub trait ResponseHandler {
    /// Serializes and sends a message to to the wrapped handle
    ///
    /// self is consumed as only one message should ever be sent in response to a Request
    fn send(self, response: MessageResponse) -> io::Result<()>;
}

/// A handler for wraping a BufStreamHandle, which will properly serialize the message and add the
///  associated destination.
pub struct ResponseHandle {
    dst: SocketAddr,
    stream_handle: BufStreamHandle<ClientError>,
}

impl ResponseHandle {
    /// Returns a new `ResponseHandle` for sending a response message
    pub fn new(dst: SocketAddr, stream_handle: BufStreamHandle<ClientError>) -> Self {
        ResponseHandle { dst, stream_handle }
    }
}

impl ResponseHandler for ResponseHandle {
    /// Serializes and sends a message to to the wrapped handle
    ///
    /// self is consumed as only one message should ever be sent in response to a Request
    fn send(self, response: MessageResponse) -> io::Result<()> {
        info!(
            "response: {} response_code: {}",
            response.header().id(),
            response.header().response_code(),
        );
        let mut buffer = Vec::with_capacity(512);
        let encode_result = {
            let mut encoder: BinEncoder = BinEncoder::new(&mut buffer);
            response.destructive_emit(&mut encoder)
        };

        encode_result.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("error encoding message: {}", e),
            )
        })?;

        self.stream_handle
            .unbounded_send(SerialMessage::new(buffer, self.dst))
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "unknown"))
    }
}
