// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![warn(missing_docs)]
#![recursion_limit = "2048"]

//! TRust-DNS Protocol library

#[cfg(any(feature = "openssl", feature = "ring"))]
extern crate data_encoding;
#[macro_use]
extern crate error_chain;
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
extern crate url;

use std::marker::PhantomData;
use std::net::SocketAddr;

use futures::sync::mpsc::{UnboundedSender, SendError};

mod dns_handle;
pub mod error;
pub mod op;
pub mod rr;
mod retry_dns_handle;
#[cfg(feature = "dnssec")]
mod secure_dns_handle;
pub mod serialize;
pub mod tcp;
pub mod udp;

pub use dns_handle::{BasicDnsHandle, DnsFuture, DnsHandle, DnsStreamHandle, StreamHandle};
pub use retry_dns_handle::RetryDnsHandle;
#[cfg(feature = "dnssec")]
pub use secure_dns_handle::SecureDnsHandle;
use op::Message;
use error::*;

// TODO: change to Sink
/// A sender to which serialized DNS Messages can be sent
#[derive(Clone)]
pub struct BufStreamHandle<E> where E: FromProtoError {
    sender: UnboundedSender<(Vec<u8>, SocketAddr)>,
    phantom: PhantomData<E>
}

impl<E> BufStreamHandle<E> where E: FromProtoError {
    /// Constructs a new BufStreamHandle with the associated ProtoError
    pub fn new(sender: UnboundedSender<(Vec<u8>, SocketAddr)>) -> Self {
        BufStreamHandle { sender, phantom: PhantomData::<E> }
    }

    /// see [`futures::sync::mpsc::UnboundedSender`]
    pub fn unbounded_send(&self, msg: (Vec<u8>, SocketAddr)) -> Result<(), SendError<(Vec<u8>, SocketAddr)>> {
        self.sender.unbounded_send(msg)
    }
}

// TODO: change to Sink
/// A sender to which a Message can be sent
pub type MessageStreamHandle = UnboundedSender<Message>;

/// A buffering stream bound to a `SocketAddr`
pub struct BufDnsStreamHandle<E> where E: FromProtoError {
    name_server: SocketAddr,
    sender: BufStreamHandle<E>,
}

impl<E> BufDnsStreamHandle<E> where E: FromProtoError {
    /// Constructs a new Buffered Stream Handle, used for sending data to the DNS peer.
    ///
    /// # Arguments
    ///
    /// * `name_server` - the address of the DNS server
    /// * `sender` - the handle being used to send data to the server
    pub fn new(name_server: SocketAddr, sender: BufStreamHandle<E>) -> Self {
        BufDnsStreamHandle {
            name_server: name_server,
            sender: sender,
        }
    }
}

impl<E> DnsStreamHandle for BufDnsStreamHandle<E>
where 
    E: FromProtoError
{
    type Error = E;

    fn send(&mut self, buffer: Vec<u8>) -> Result<(), E> {
        let name_server: SocketAddr = self.name_server;
        let sender: &mut _ = &mut self.sender;
        sender.sender.unbounded_send((buffer, name_server)).map_err(|e| {
            E::from(
                ProtoErrorKind::Msg(format!("mpsc::SendError {}", e)).into()
            )
        })
    }
}
