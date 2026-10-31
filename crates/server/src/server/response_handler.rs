// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::SocketAddr;

use super::ResponseInfo;
use crate::{
    net::{BufDnsStreamHandle, DnsStreamHandle, NetError},
    proto::op::SerialMessage,
};

/// A handler for send a response to a client
#[async_trait::async_trait]
pub trait ResponseHandler: Send + Sync + Unpin + 'static {
    // TODO: add associated error type
    //type Error;

    /// Sends an encoded response message to the wrapped handle
    async fn send_response(&mut self, info: ResponseInfo) -> Result<(), NetError>;
}

/// A handler for wrapping a [`BufDnsStreamHandle`]
///
/// Adds the associated destination to the message.
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
    /// Sends an encoded response message to the wrapped handle
    async fn send_response(&mut self, info: ResponseInfo) -> Result<(), NetError> {
        self.stream_handle
            .send(SerialMessage::new(info.bytes, self.dst))
    }
}
