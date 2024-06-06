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
#![cfg_attr(docsrs, feature(doc_cfg))]

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
//! There are two variations of implementations of the Client. The `SyncClient`, a synchronous client, and the `AsyncClient`, a Tokio async client. `SyncClient` is an implementation of the `Client` trait, there is another implementation, `SyncDnssecClient`, which validates DNSSEC records. For these basic examples we'll only look at the `SyncClient`
//!
//! First we must decide on the type of connection, there are three supported by Hickory DNS today, UDP, TCP and TLS. TLS requires OpenSSL by default, see also [hickory-dns-native-tls](https://docs.rs/hickory-dns-native-tls) and [hickory-dns-rustls](https://docs.rs/hickory-dns-rustls) for other TLS options.
//!
//! ## Setup a connection
//!
//! ```rust
//! use hickory_proto::DnsStreamHandle;
//! use hickory_client::client::{Client, ClientConnection, SyncClient};
//! use hickory_client::udp::UdpClientConnection;
//!
//! let address = "8.8.8.8:53".parse().unwrap();
//! let conn = UdpClientConnection::new(address).unwrap();
//!
//! // and then create the Client
//! let client = SyncClient::new(conn);
//! ```
//!
//! At this point the client is ready to be used. See also `client::SyncDnssecClient` for DNSSEC validation. The rest of these examples will assume that the above boilerplate has already been performed.
//!
//! ## Querying
//!
//! Using the Client to query for DNS records is easy enough, though it performs no resolution. The `hickory-resolver` has a simpler interface if that's what is desired. Over time that library will gain more features to generically query for different types.
//!
//! ```rust
//! use std::net::Ipv4Addr;
//! use std::str::FromStr;
//! # use hickory_client::client::{Client, SyncClient};
//! # use hickory_client::udp::UdpClientConnection;
//! use hickory_client::op::DnsResponse;
//! use hickory_client::rr::{DNSClass, Name, RData, Record, RecordType};
//! use hickory_client::rr::rdata::A;
//! #
//! # let address = "8.8.8.8:53".parse().unwrap();
//! # let conn = UdpClientConnection::new(address).unwrap();
//! # let client = SyncClient::new(conn);
//!
//! // Specify the name, note the final '.' which specifies it's an FQDN
//! let name = Name::from_str("www.example.com.").unwrap();
//!
//! // NOTE: see 'Setup a connection' example above
//! // Send the query and get a message response, see RecordType for all supported options
//! let response: DnsResponse = client.query(&name, DNSClass::IN, RecordType::A).unwrap();
//!
//! // Messages are the packets sent between client and server in DNS.
//! //  there are many fields to a Message, DnsResponse can be dereferenced into
//! //  a Message. It's beyond the scope of these examples
//! //  to explain all the details of a Message. See hickory_client::op::message::Message for more details.
//! //  generally we will be interested in the Message::answers
//! let answers: &[Record] = response.answers();
//!
//! // Records are generic objects which can contain any data.
//! //  In order to access it we need to first check what type of record it is
//! //  In this case we are interested in A, IPv4 address
//! if let RData::A(ref ip) = answers[0].data() {
//!     assert_eq!(*ip, A::new(93, 184, 215, 14))
//! } else {
//!     assert!(false, "unexpected result")
//! }
//! ```
//!
//! In the above example we successfully queried for a A record. There are many other types, each can be independently queried and the associated `hickory_client::rr::record_data::RData` has a variant with the deserialized data for the record stored.
//!
//! ## Dynamic update
//!
//! Currently `hickory-client` supports SIG(0) signed records for authentication and authorization of dynamic DNS updates. It's beyond the scope of these examples to show how to setup SIG(0) authorization on the server. `hickory-client` is known to work with BIND9 and `hickory-server`. Expect in the future for TLS to become a potentially better option for authorization with certificate chains. These examples show using SIG(0) for auth, requires OpenSSL. It's beyond the scope of these examples to describe the configuration for the server.

//!
//! ```rust,no_run
//!
//! #[cfg(all(feature = "openssl", feature = "dnssec"))]
//! # fn main() {
//!
//! use std::fs::File;
//! use std::io::Read;
//! use std::net::Ipv4Addr;
//! use std::str::FromStr;
//!
//! # #[cfg(feature = "openssl")]
//! use openssl::rsa::Rsa;
//! use hickory_client::client::{Client, SyncClient};
//! use hickory_client::udp::UdpClientConnection;
//! use hickory_client::rr::{Name, RData, Record, RecordType};
//! use hickory_client::proto::rr::dnssec::{Algorithm, SigSigner, KeyPair};
//! use hickory_client::op::ResponseCode;
//! use hickory_client::rr::rdata::{A, key::KEY};
//!
//! # let address = "0.0.0.0:53".parse().unwrap();
//! # let conn = UdpClientConnection::new(address).unwrap();
//!
//! // The format of the key is dependent on the KeyPair type, in this example we're using RSA
//! //  if the key was generated with BIND, the binary in Hickory DNS client lib `dnskey-to-pem`
//! //  can be used to convert this to a pem file
//! let mut pem = File::open("my_private_key.pem").unwrap();
//! let mut pem_buf = Vec::<u8>::new();
//! pem.read_to_end(&mut pem_buf).unwrap();
//!
//! // Create the RSA key
//! let rsa = Rsa::private_key_from_pem(&pem_buf).unwrap();
//! let key = KeyPair::from_rsa(rsa).unwrap();
//!
//! // Create the RData KEY associated with the key. This example uses defaults for all the
//! //  KeyTrust, KeyUsage, UpdateScope, Protocol. Many of these have been deprecated in current
//! //  DNS RFCs, but are still supported by many servers for auth. See auth docs of the remote
//! //  server for help in understanding it's requirements and support of these options.
//! let sig0key = KEY::new(Default::default(),
//!                        Default::default(),
//!                        Default::default(),
//!                        Default::default(),
//!                        Algorithm::RSASHA256,
//!                        key.to_public_bytes().unwrap());
//!
//! // Create the Hickory DNS SIG(0) signing facility. Generally the signer_name is the label
//! //  associated with KEY record in the server.
//! let signer = SigSigner::sig0(sig0key,
//!                           key,
//!                           Name::from_str("update.example.com.").unwrap());
//!
//! // Create the DNS client, see above for creating the connection
//! let client = SyncClient::with_signer(conn, signer);
//!
//! // At this point we should have a client capable of sending signed SIG(0) records.
//!
//! // Now we can send updates... let's create a new Record
//! let mut record = Record::with(Name::from_str("new.example.com").unwrap(),
//!                               RecordType::A,
//!                               300);
//! record.set_data(Some(RData::A(A::new(100, 10, 100, 10))));
//!
//! // the server must be authoritative for this zone
//! let origin = Name::from_str("example.com.").unwrap();
//!
//! // Create the record.
//! let result = client.create(record, origin).unwrap();
//! assert_eq!(result.response_code(), ResponseCode::NoError);
//! # }
//! # #[cfg(not(all(feature = "openssl", feature = "dnssec")))]
//! # fn main() {
//! # }
//! ```
//!
//! *Note*: The dynamic DNS functions defined by Hickory DNS are expressed as atomic operations, but this depends on support of the remote server. For example, the `create` operation shown above, should only succeed if there is no `RecordSet` of the specified type at the specified label. The other update operations are `append`, `compare_and_swap`, `delete_by_rdata`, `delete_rrset`, and `delete_all`. See the documentation for each of these methods on the `Client` trait.
//!
//!
//! ## Async client usage
//!
//! This example is meant to show basic usage, using the #[tokio::main] macro to setup a simple runtime.
//! The Tokio documentation should be reviewed for more advanced usage.
//!
//! ```rust
//! use std::net::Ipv4Addr;
//! use std::str::FromStr;
//! use tokio::net::TcpStream as TokioTcpStream;
//! use hickory_client::client::{AsyncClient, ClientHandle};
//! use hickory_client::proto::iocompat::AsyncIoTokioAsStd;
//! use hickory_client::rr::{DNSClass, Name, RData, RecordType};
//! use hickory_client::rr::rdata::A;
//! use hickory_client::tcp::TcpClientStream;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Since we used UDP in the previous examples, let's change things up a bit and use TCP here
//!     let (stream, sender) =
//!         TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(([8, 8, 8, 8], 53).into());
//!
//!     // Create a new client, the bg is a background future which handles
//!     //   the multiplexing of the DNS requests to the server.
//!     //   the client is a handle to an unbounded queue for sending requests via the
//!     //   background. The background must be scheduled to run before the client can
//!     //   send any dns requests
//!     let client = AsyncClient::new(stream, sender, None);
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

pub mod client;
pub mod error;
#[cfg(feature = "mdns")]
#[cfg_attr(docsrs, doc(cfg(feature = "mdns")))]
pub mod multicast;
pub mod op;
pub mod rr;
pub mod serialize;
pub mod tcp;
pub mod udp;

// TODO: consider removing tcp/udp/https modules...
#[cfg(feature = "dns-over-https")]
mod h2_client_connection;

pub use hickory_proto as proto;

/// The https module which contains all https related connection types
#[cfg(feature = "dns-over-https")]
#[cfg_attr(docsrs, doc(cfg(feature = "dns-over-https")))]
pub mod h2 {
    pub use super::h2_client_connection::HttpsClientConnection;
}

/// Returns a version as specified in Cargo.toml
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
