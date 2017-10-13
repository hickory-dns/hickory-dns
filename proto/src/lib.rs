// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![warn(missing_docs)]
#![recursion_limit = "1024"]

//! TRust-DNS Protocol library

extern crate chrono;
extern crate data_encoding;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate futures;
#[cfg(feature = "openssl")]
extern crate openssl;
extern crate rand;
#[cfg(feature = "ring")]
extern crate ring;
#[macro_use]
extern crate tokio_core;
extern crate tokio_io;
#[cfg(feature = "ring")]
extern crate untrusted;

use std::net::SocketAddr;

use futures::sync::mpsc::UnboundedSender;

mod dns_handle;
pub mod error;
pub mod op;
pub mod rr;
pub mod serialize;
pub mod tcp;
pub mod udp;

pub use dns_handle::{BasicDnsHandle, DnsFuture, DnsHandle, DnsStreamHandle, StreamHandle};
use op::Message;
use error::*;

// TODO: change to Sink
/// A sender to which serialized DNS Messages can be sent
pub type BufStreamHandle = UnboundedSender<(Vec<u8>, SocketAddr)>;

// TODO: change to Sink
/// A sender to which a Message can be sent
pub type MessageStreamHandle = UnboundedSender<Message>;

/// A buffering stream bound to a `SocketAddr`
pub struct BufDnsStreamHandle {
    name_server: SocketAddr,
    sender: BufStreamHandle,
}

impl BufDnsStreamHandle {
    /// Constructs a new Buffered Stream Handle, used for sending data to the DNS peer.
    ///
    /// # Arguments
    ///
    /// * `name_server` - the address of the DNS server
    /// * `sender` - the handle being used to send data to the server
    pub fn new(name_server: SocketAddr, sender: BufStreamHandle) -> Self {
        BufDnsStreamHandle {
            name_server: name_server,
            sender: sender,
        }
    }
}

impl DnsStreamHandle for BufDnsStreamHandle {
    fn send(&mut self, buffer: Vec<u8>) -> ProtoResult<()> {
        let name_server: SocketAddr = self.name_server;
        let sender: &mut _ = &mut self.sender;
        sender.unbounded_send((buffer, name_server)).map_err(|e| {
            ProtoErrorKind::Msg(format!("mpsc::SendError {}", e)).into()
        })
    }
}