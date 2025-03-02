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
    clippy::single_component_path_imports,
    clippy::upper_case_acronyms, // can be removed on a major release boundary
)]
#![recursion_limit = "2048"]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

//! Hickory DNS is intended to be a fully compliant domain name server and client library.
//!
//! # Goals
//!
//! * Only safe Rust
//! * All errors handled
//! * Simple to manage servers
//! * High level abstraction for clients
//! * Secure dynamic update
//! * New features for securing public information

#[cfg(feature = "blocklist")]
pub use crate::store::blocklist;
pub use hickory_proto as proto;
#[cfg(feature = "recursor")]
pub use hickory_recursor as recursor;
#[cfg(any(feature = "resolver", feature = "recursor"))]
pub use hickory_resolver as resolver;

mod access;
pub mod authority;
mod error;
pub use error::{ConfigError, ConfigErrorKind, PersistenceError, PersistenceErrorKind};
pub mod server;
pub mod store;

pub use self::server::ServerFuture;

/// Low-level types for DNSSEC operations
#[cfg(feature = "__dnssec")]
pub mod dnssec {
    use crate::proto::dnssec::Nsec3HashAlgorithm;
    use serde::Deserialize;
    use std::sync::Arc;

    /// The kind of non-existence proof provided by the nameserver
    #[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
    #[serde(rename_all = "lowercase")]
    pub enum NxProofKind {
        /// Use NSEC
        Nsec,
        /// Use NSEC3
        Nsec3 {
            /// The algorithm used to hash the names.
            #[serde(default)]
            algorithm: Nsec3HashAlgorithm,
            /// The salt used for hashing.
            #[serde(default = "default_salt")]
            salt: Arc<[u8]>,
            /// The number of hashing iterations.
            #[serde(default)]
            iterations: u16,
            /// The Opt-Out flag.
            #[serde(default)]
            opt_out: bool,
        },
    }

    // MSRV: works in 1.80, fails in 1.78
    fn default_salt() -> Arc<[u8]> {
        Arc::new([])
    }
}

/// Returns the current version of Hickory DNS
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
