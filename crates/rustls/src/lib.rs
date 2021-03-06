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
#![allow(clippy::single_component_path_imports)]

//! TLS protocol related components for DNS over TLS

#[macro_use]
extern crate log;

pub mod tls_client_stream;
pub mod tls_server;
pub mod tls_stream;

pub use self::tls_client_stream::{tls_client_connect, TlsClientStream};
pub use self::tls_stream::{tls_connect, tls_from_stream, TlsStream};

#[cfg(test)]
mod tests;
