/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#![recursion_limit = "1024"]

//! Trust-DNS is intended to be a fully compliant domain name server and client library.
//!
//! # Goals
//!
//! * Only safe Rust
//! * All errors handled
//! * Simple to manage servers
//! * High level abstraction for clients
//! * Secure dynamic update
//! * New features for securing public information

extern crate backtrace;
#[macro_use]
extern crate error_chain;
extern crate chrono;
extern crate data_encoding;
#[macro_use]
extern crate futures;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[cfg(feature = "native-tls")]
extern crate native_tls;
#[cfg(any(feature = "openssl", all(target_os = "linux", feature = "tls")))]
extern crate openssl;
extern crate rand;
#[cfg(feature = "ring")]
extern crate ring;
extern crate rustc_serialize;
#[cfg(all(target_os = "macos", feature = "security-framework"))]
extern crate security_framework;
extern crate time;
#[macro_use]
extern crate tokio_core;
extern crate tokio_tls;
#[cfg(feature = "ring")]
extern crate untrusted;

pub mod client;
pub mod error;
pub mod logger;
pub mod op;
pub mod rr;
pub mod tcp;
#[cfg(feature = "tls")]
pub mod tls;
pub mod udp;
pub mod serialize;

use std::io;
use std::net::SocketAddr;

use futures::sync::mpsc::UnboundedSender;
use futures::Stream;

use op::Message;
use client::ClientStreamHandle;

/// A stream of serialized DNS Messages
pub type BufStream = Stream<Item = (Vec<u8>, SocketAddr), Error = io::Error>;

/// A sender to which serialized DNS Messages can be sent
pub type BufStreamHandle = UnboundedSender<(Vec<u8>, SocketAddr)>;

/// A stream of messsages
pub type MessageStream = Stream<Item = Message, Error = io::Error>;

/// A sender to which a Message can be sent
pub type MessageStreamHandle = UnboundedSender<Message>;

pub struct BufClientStreamHandle {
    name_server: SocketAddr,
    sender: BufStreamHandle,
}

impl ClientStreamHandle for BufClientStreamHandle {
    fn send(&mut self, buffer: Vec<u8>) -> io::Result<()> {
        let name_server: SocketAddr = self.name_server;
        let sender: &mut _ = &mut self.sender;
        sender.send((buffer, name_server))
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "unknown"))
    }
}

/// this exposes a version function which gives access to the access
include!(concat!(env!("OUT_DIR"), "/version.rs"));

// TODO switch env_logger and remove this
#[test]
fn enable_logging_for_tests() {
    use log::LogLevel;
    logger::TrustDnsLogger::enable_logging(LogLevel::Debug);
}
