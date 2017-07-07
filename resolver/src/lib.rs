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
//! # Usage
//!
//! ## Declare dependency
//!
//! ```toml
//! [dependency]
//! trust-dns-resolver = "^0.1"
//! ```
//!
//! ## Extern the crate for usage in the library
//!
//! ```rust
//! extern crate trust_dns_resolver;
//! ```
//!
//! ## Using the Synchronous Resolver
//!
//! This uses the default configuration. Currently this sets the google resolvers as the upstream resolvers.
//!
//! ```rust
//! use std::net::*;
//! use trust_dns_resolver::Resolver;
//! use trust_dns_resolver::config::*;
//!
//! // Construct a new Resolver with default configuration options
//! let mut resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
//! 
//! // Lookup the IP addresses associated with a name.
//! // NOTE: do not forget the final dot, as the resolver does not yet support search paths.
//! let mut response = resolver.lookup_ip("www.example.com.").unwrap();
//!
//! // There can be many addresses associated with the name,
//! //  this can return IPv4 and/or IPv6 addresses
//! let address = response.next().expect("no addresses returned!");
//! if address.is_ipv4() {
//!     assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
//! } else {
//!     assert_eq!(address, IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946)));
//! }
//! ```
//!
//! ## Using the Tokio/Async Resolver
//!
//! For more advanced asynchronous usage, the ResolverFuture is integrated with Tokio. In fact, the ResolverFuture is used by the synchronous Resolver for all lookups.
//!
//! ```rust
//! # extern crate futures;
//! # extern crate tokio_core;
//! # extern crate trust_dns_resolver;
//! # fn main() {
//! use std::net::*;
//! use tokio_core::reactor::Core;
//! use trust_dns_resolver::ResolverFuture;
//! use trust_dns_resolver::config::*;
//!
//! // We need a Tokio reactor::Core to run the resolver
//! //  this is responsible for running all Future tasks and registering interest in IO channels
//! let mut io_loop = Core::new().unwrap(); 
//!
//! // Construct a new Resolver with default configuration options
//! let mut resolver = ResolverFuture::new(ResolverConfig::default(), ResolverOpts::default(), io_loop.handle());
//! 
//! // Lookup the IP addresses associated with a name.
//! // NOTE: do not forget the final dot, as the resolver does not yet support search paths.
//! // This returns a future that will lookup the IP addresses, it must be run in the Core to
//! //  to get the actual result.
//! let lookup_future = resolver.lookup_ip("www.example.com.");
//!
//! // Run the lookup until it resolves or errors
//! let mut response = io_loop.run(lookup_future).unwrap();
//!
//! // There can be many addresses associated with the name,
//! //  this can return IPv4 and/or IPv6 addresses
//! let address = response.next().expect("no addresses returned!");
//! if address.is_ipv4() {
//!     assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
//! } else {
//!     assert_eq!(address, IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946)));
//! }
//! # }
//! ```
//!
//! Generaally after a lookup in an asynchornous context, there would probably be a connection made to a server, for example:
//!
//! ```c
//! let result = io_loop.run(lookup_future.and_then(|ips| {
//!                              let ip = ips.next().unwrap();
//!                              TcpStream::connect()
//!                          }).and_then(|conn| /* do something with the connection... */)
//! ).unwrap();
//! ```
//! 
//! It's beyond the scope of these examples to show how to deal with connection failures and looping etc. But if you wanted to say try a different address from the result set after a connection failure, it will be necessary to create a type that implements the `Future` trait. Inside the `Future::poll` method would be the place to implement a loop over the different IP addresses.

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
