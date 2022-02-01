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

// LIBRARY WARNINGS
#![warn(
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::unimplemented,
    missing_copy_implementations,
    missing_docs,
    non_snake_case,
    non_upper_case_globals,
    rust_2018_idioms,
    unreachable_pub
)]
#![allow(
    clippy::upper_case_acronyms,
    clippy::single_component_path_imports,
    dead_code,
    clippy::needless_borrow,
    clippy::redundant_closure,
    clippy::search_is_some
)]
#![recursion_limit = "2048"]

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

pub use trust_dns_client as client;
pub use trust_dns_proto as proto;
#[cfg(feature = "trust-dns-resolver")]
pub use trust_dns_resolver as resolver;

pub mod authority;
pub mod config;
pub mod error;
pub mod logger;
pub mod server;
pub mod store;

pub use self::server::ServerFuture;

/// Returns the current version of Trust-DNS
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
