// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![deny(missing_docs)]
#![recursion_limit = "1024"]

//! TRust-DNS Protocol library

extern crate chrono;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate futures;
extern crate rand;
#[macro_use]
extern crate tokio_core;
extern crate tokio_io;

use std::io;
use std::net::SocketAddr;

use futures::Stream;
use futures::sync::mpsc::UnboundedSender;

mod dns_handle;
pub mod error;
pub mod op;
pub mod rr;
pub mod tcp;
pub mod udp;

pub use dns_handle::DnsStreamHandle;
use op::Message;


// FIXME: change io::Error to error::ProtoError
/// A stream of serialized DNS Messages
pub type BufStream = Stream<Item = (Vec<u8>, SocketAddr), Error = io::Error>;

// TODO: change to Sink
/// A sender to which serialized DNS Messages can be sent
pub type BufStreamHandle = UnboundedSender<(Vec<u8>, SocketAddr)>;

/// A stream of messsages
pub type MessageStream = Stream<Item = Message, Error = io::Error>;

// TODO: change to Sink
/// A sender to which a Message can be sent
pub type MessageStreamHandle = UnboundedSender<Message>;

/// A buffering stream bound to a `SocketAddr`
pub struct BufClientStreamHandle {
    name_server: SocketAddr,
    sender: BufStreamHandle,
}

impl BufClientStreamHandle {
    /// Constructs a new Buffered Stream Handle, used for sending data to the DNS peer.
    ///
    /// # Arguments
    ///
    /// * `name_server` - the address of the DNS server
    /// * `sender` - the handle being used to send data to the server
    pub fn new(name_server: SocketAddr, sender: BufStreamHandle) -> Self {
        BufClientStreamHandle {
            name_server: name_server,
            sender: sender,
        }
    }
}

impl DnsStreamHandle for BufClientStreamHandle {
    fn send(&mut self, buffer: Vec<u8>) -> io::Result<()> {
        let name_server: SocketAddr = self.name_server;
        let sender: &mut _ = &mut self.sender;
        sender.unbounded_send((buffer, name_server)).map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "unknown")
        })
    }
}