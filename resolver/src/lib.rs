// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The Resolver is responsible for performing recursive queries to lookup domain names.
//!
//! This is a 100% in process DNS resolver. It *does not* use the Host OS' resolver. If what is desired is to use the Host OS' resolver, generally in the system's libc, then the `std::net::ToSocketAddrs` variant over `&str` is what should be used. As of the initial release, `trust-dns-resolver` it does not currently support search paths or ndot recursive lookups. It only supports FQDN, where the name must be specified with the final dot, e.g. `www.example.com.`. This limitation will be removed in future releases.
//!
//! Unlike the `trust-dns` client, this tries to provide a simpler interface to perform DNS queries. For update options, i.e. Dynamic DNS, the `trust-dns` crate must be used directly.
//!
//! There are two types for performing DNS queries, `Resolver` and `ResolverFuture`. `Resolver` is the easiest to work with, it is a wrapper around `ResolverFuture`. `ResolverFuture` is a `Tokio` based async resolver, and can be used inside any `Tokio` based system.
//!
//! *Notes on current limitations*: DNSSec is not yet supported in the Resolver, use the `trust-dns` Client if DNSSec validation is needed. Many standard system options and configurations are not yet supported. The host system `/etc/resolv.conf` is not yet being used. Recursion is not yet built, i.e. CNAME chains will not be fully resolved if an address is not returned. IPv6 lookups are not included in queries. Due to many of these limitations, you may not yet want to use this library.
//!
//! This as best as possible attempts to abide by the the DNS RFCs, please file issues at https://github.com/bluejekyll/trust-dns .
//!
//! ## Example
//! 
//! ```rust
//! use std::net::*;
//! use trust_dns_resolver::Resolver;
//! use trust_dns_resolver::config::*;
//!
//! let mut resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
//! 
//! // NOTE: do not forget the final dot, as the resolver does not yet support search paths.
//! let mut response = resolver.lookup_ip("www.example.com.").unwrap();
//!
//! let address = response.next().expect("no addresses returned!");
//! assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))); 
//! ```

#![deny(missing_docs)]

extern crate futures;
#[macro_use]
extern crate log;
extern crate tokio_core;
extern crate trust_dns;

pub mod config;
pub mod lookup_ip;
mod name_server_pool;
mod resolver;
mod resolver_future;


pub use resolver::Resolver;
pub use resolver_future::ResolverFuture;

/// returns a version as specified in Cargo.toml
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
