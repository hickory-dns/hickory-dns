/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// LIBRARY WARNINGS
#![warn(
    clippy::default_trait_access,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::unimplemented,
    clippy::use_self,
    missing_copy_implementations,
    missing_docs,
    non_snake_case,
    non_upper_case_globals,
    rust_2018_idioms,
    unreachable_pub
)]
#![allow(
    clippy::needless_doctest_main,
    clippy::single_component_path_imports,
    clippy::upper_case_acronyms, // can be removed on a major release boundary
    clippy::bool_to_int_with_if,
)]
#![recursion_limit = "1024"]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

//! Hickory DNS is intended to be a fully compliant domain name server and client library.
//!
//! The Client library is responsible for the basic protocols responsible for communicating with DNS servers (authorities) and resolvers. It can be used for managing DNS records through the use of update operations. It is possible to send raw DNS Messages with the Client, but for ease of use the `query` and various other update operations are recommended for general use.
//!
//! For a system-like resolver, see [hickory-resolver](https://docs.rs/hickory-resolver). This is most likely what you want if all you want to do is lookup IP addresses.
//!
//! For serving DNS serving, see [hickory-server](https://docs.rs/hickory-server).
//!
//! # Goals
//!
//! * Only safe Rust
//! * All errors handled
//! * Simple to manage servers
//! * High level abstraction for clients
//! * Secure dynamic update
//! * New features for securing public information
//!
//! # Usage
//!
//! This shows basic usage of the SyncClient. More examples will be associated directly with other types.
//!
//! ## Dependency
//!
//! ```toml
//! [dependencies]
//! hickory-client = "*"
//! ```
//!
//! By default DNSSEC validation is built in with OpenSSL, this can be disabled with:
//!
//! ```toml
//! [dependencies]
//! hickory-client = { version = "*", default-features = false }
//! ```
//!
//! ## Objects
//!
//! There are two variations of implementations of the client: the [`client::Client`], an
//! async client usually used with the Tokio runtime and the [`client::DnssecClient`], which
//! validates DNSSEC records. For these basic examples we'll only look at the `Client`.
//!
//! First we must decide on the type of connection. For the purpose of this example, we'll
//! show how to set up a TCP-based connection.
//!
//! This example is meant to show basic usage, using the `#[tokio::main]` macro to setup a simple
//! runtime. The Tokio documentation should be reviewed for more advanced usage.
//!
//! ```rust
//! use std::net::Ipv4Addr;
//! use std::str::FromStr;
//! use tokio::net::TcpStream as TokioTcpStream;
//! use hickory_client::client::{Client, ClientHandle};
//! use hickory_client::proto::runtime::TokioRuntimeProvider;
//! use hickory_client::proto::rr::{DNSClass, Name, RData, RecordType};
//! use hickory_client::proto::rr::rdata::A;
//! use hickory_client::proto::tcp::TcpClientStream;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Since we used UDP in the previous examples, let's change things up a bit and use TCP here
//!     let (stream, sender) =
//!         TcpClientStream::new(([8, 8, 8, 8], 53).into(), None, None, TokioRuntimeProvider::new());
//!
//!     // Create a new client, the bg is a background future which handles
//!     //   the multiplexing of the DNS requests to the server.
//!     //   the client is a handle to an unbounded queue for sending requests via the
//!     //   background. The background must be scheduled to run before the client can
//!     //   send any dns requests
//!     let client = Client::new(stream, sender, None);
//!
//!     // await the connection to be established
//!     let (mut client, bg) = client.await.expect("connection failed");
//!
//!     // make sure to run the background task
//!     tokio::spawn(bg);
//!
//!     // Create a query future
//!     let query = client.query(
//!         Name::from_str("www.example.com.").unwrap(),
//!         DNSClass::IN,
//!         RecordType::A,
//!    );
//!
//!     // wait for its response
//!     let response = query.await.unwrap();
//!
//!     // validate it's what we expected
//!     if let RData::A(addr) = response.answers()[0].data() {
//!         assert_eq!(*addr, A::new(93, 184, 215, 14));
//!     }
//! }
//! ```
//!
//! In the above example we successfully queried for a A record. There are many other types, each
//! can be independently queried and the associated [`crate::proto::rr::record_data::RData`]
//! has a variant with the deserialized data for the record stored.
//!
//! ## Dynamic update
//!
//! Currently `hickory-client` supports SIG(0) signed records for authentication and authorization
//! of dynamic DNS updates. Consult the [`client::DnssecClient`] API for more information.

pub mod client;
mod error;
pub use error::{Error as ClientError, ErrorKind as ClientErrorKind};
#[cfg(test)]
mod tests;

pub use hickory_proto as proto;

/// Returns a version as specified in Cargo.toml
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
