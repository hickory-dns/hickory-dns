// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! A resolver must be constructed with a Client. See the `trust-dns` crate for Client.
//!
//! This as best as possible attempts to abide by the the DNS RFCs, specifically Recursive resolution as defined in 

#![deny(missing_docs)]

extern crate futures;
extern crate tokio_core;
extern crate trust_dns;

mod config;
mod lookup_ip;
mod name_server_pool;
mod resolver;
mod resolver_future;


pub use resolver::Resolver;
pub use resolver_future::ResolverFuture;

/// this exposes a version function which gives access to the access
include!(concat!(env!("OUT_DIR"), "/version.rs"));
