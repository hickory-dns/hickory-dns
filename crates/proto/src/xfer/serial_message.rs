// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::SocketAddr;

use crate::error::ProtoResult;
use crate::op::Message;
use std::convert::TryInto;

/// A DNS message in serialized form, with either the target address or source address
#[derive(Clone)]
pub struct SerialMessage {
    // TODO: change to Bytes? this would be more compatible with some underlying libraries
    message: Vec<u8>,
    addr: SocketAddr,
}

impl SerialMessage {
    /// Construct a new SerialMessage and the source or destination address
    pub fn new(message: Vec<u8>, addr: SocketAddr) -> Self {
        Self { message, addr }
    }

    /// Get a reference to the bytes
    pub fn bytes(&self) -> &[u8] {
        &self.message
    }

    /// see `Header::id()`
    pub fn id(&self) -> Option<u16> {
        self.message
            .get(0..2)
            .map(|bytes| u16::from_be_bytes(bytes.try_into().unwrap()))
    }

    /// Get the source or destination address (context dependent)
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Unwrap the Bytes and address
    pub fn into_parts(self) -> (Vec<u8>, SocketAddr) {
        self.into()
    }

    /// Build a `SerialMessage` from some bytes and an address
    pub fn from_parts(message: Vec<u8>, addr: SocketAddr) -> Self {
        (message, addr).into()
    }

    /// Deserializes the inner data into a Message
    pub fn to_message(&self) -> ProtoResult<Message> {
        Message::from_vec(&self.message)
    }
}

impl From<(Vec<u8>, SocketAddr)> for SerialMessage {
    fn from((message, addr): (Vec<u8>, SocketAddr)) -> Self {
        Self { message, addr }
    }
}

impl From<SerialMessage> for (Vec<u8>, SocketAddr) {
    fn from(msg: SerialMessage) -> Self {
        let SerialMessage { message, addr } = msg;
        (message, addr)
    }
}
