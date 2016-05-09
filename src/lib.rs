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
extern crate data_encoding;
#[macro_use] extern crate log;
extern crate mio;
extern crate openssl;
extern crate openssl_sys;
extern crate rustc_serialize;
extern crate toml;


pub mod logger;
pub mod rr;
pub mod authority;
pub mod op;
pub mod udp;
pub mod tcp;
pub mod client;
pub mod server;
pub mod error;
pub mod serialize;
pub mod config;

/// this exposes a version function which gives access to the access
include!(concat!(env!("OUT_DIR"), "/version.rs"));

#[test]
fn enable_logging_for_tests() {
  use log::LogLevel;
  logger::TrustDnsLogger::enable_logging(LogLevel::Debug);
}
