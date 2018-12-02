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
#![deny(missing_docs)]
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

extern crate bytes;
extern crate chrono;
extern crate env_logger;
extern crate failure;
extern crate futures;
#[macro_use]
extern crate log;
extern crate rusqlite;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[cfg(feature = "dns-over-https")]
extern crate h2;
#[cfg(feature = "dns-over-https")]
extern crate http;
#[cfg(feature = "dns-over-openssl")]
extern crate openssl;
#[cfg(feature = "dns-over-rustls")]
extern crate rustls;
extern crate time;
extern crate tokio;
extern crate tokio_executor;
extern crate tokio_io;
extern crate tokio_reactor;
#[cfg(feature = "dns-over-rustls")]
extern crate tokio_rustls;
extern crate tokio_tcp;
extern crate tokio_timer;
extern crate tokio_udp;
extern crate toml;
extern crate trust_dns;
#[cfg(feature = "dns-over-https")]
extern crate trust_dns_https;
#[cfg(feature = "dns-over-openssl")]
extern crate trust_dns_openssl;
pub extern crate trust_dns_proto as proto;
#[cfg(feature = "dns-over-rustls")]
extern crate trust_dns_rustls;

pub mod authority;
pub mod config;
pub mod error;
pub mod logger;
pub mod server;
pub mod store;

pub use self::server::ServerFuture;

/// Returns the current version of TRust-DNS
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
