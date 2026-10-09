// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::future::Future;
use std::net::SocketAddr;

use crate::{
    net::{BufDnsStreamHandle, DnsStreamHandle, NetError, xfer::Protocol},
    proto::{op::SerialMessage, rr::Record},
    server::ResponseInfo,
    zone_handler::MessageResponse,
};

/// A handler for send a response to a client
pub trait ResponseHandler: Send + Sync + Unpin + 'static {
    // TODO: add associated error type
    //type Error;

    /// The protocol responses are serialized for.
    fn protocol(&self) -> Protocol;

    /// Sends an already-serialized message to the wrapped handle.
    fn send_encoded(
        &mut self,
        info: ResponseInfo,
        bytes: Vec<u8>,
    ) -> impl Future<Output = Result<ResponseInfo, NetError>> + Send;

    /// Serializes and sends a message to the wrapped handle
    #[cfg_attr(not(feature = "__quic"), allow(unused_mut))]
    fn send_response<'a>(
        &mut self,
        mut response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> impl Future<Output = Result<ResponseInfo, NetError>> + Send {
        let protocol = self.protocol();

        // The id should always be 0 in DoQ
        #[cfg(feature = "__quic")]
        if protocol == Protocol::Quic {
            response.metadata_mut().id = 0;
        }

        let encoded = response.encode(protocol);
        async move {
            let (info, bytes) = encoded?;
            self.send_encoded(info, bytes).await
        }
    }
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

impl ResponseHandler for ResponseHandle {
    fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Serializes and sends a message to the wrapped handle
    async fn send_encoded(
        &mut self,
        info: ResponseInfo,
        bytes: Vec<u8>,
    ) -> Result<ResponseInfo, NetError> {
        self.stream_handle
            .send(SerialMessage::new(bytes, self.dst))?;

        Ok(info)
    }
}
