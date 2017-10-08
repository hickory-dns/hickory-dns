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

extern crate chrono;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate futures;
#[macro_use]
extern crate log;
extern crate rusqlite;
extern crate rustc_serialize;
extern crate time;
extern crate toml;
extern crate tokio_core;
extern crate trust_dns;
extern crate trust_dns_proto;

#[cfg(feature = "tls")]
extern crate trust_dns_openssl;

pub mod authority;
pub mod config;
pub mod error;
pub mod server;

pub use self::server::ServerFuture;

/// Returns the current version of TRust-DNS
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[test]
fn enable_logging_for_tests() {
    use trust_dns::logger;
    use log::LogLevel;
    logger::TrustDnsLogger::enable_logging(LogLevel::Debug);
}
