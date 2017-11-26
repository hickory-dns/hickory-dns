// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The Resolver is responsible for performing recursive queries to lookup domain names.
//!
//! This is a 100% in process DNS resolver. It *does not* use the Host OS' resolver. If what is desired is to use the Host OS' resolver, generally in the system's libc, then the `std::net::ToSocketAddrs` variant over `&str` should be used.
//!
//! Unlike the `trust-dns` client, this tries to provide a simpler interface to perform DNS queries. For update options, i.e. Dynamic DNS, the `trust-dns` crate must be used directly. The Resolver library is capable of searching multiple domains (this can be disabled by using an FQDN during lookup), dual-stack IPv4/IPv6 lookups, performing chained CNAME lookups, and features connection metric tracking for attempting to pick the best upstream DNS resolver.
//!
//! There are two types for performing DNS queries, `Resolver` and `ResolverFuture`. `Resolver` is the easiest to work with, it is a wrapper around `ResolverFuture`. `ResolverFuture` is a `Tokio` based async resolver, and can be used inside any `Tokio` based system.
//!
//! This as best as possible attempts to abide by the the DNS RFCs, please file issues at https://github.com/bluejekyll/trust-dns .
//!
//! # Usage
//!
//! ## Declare dependency
//!
//! ```toml
//! [dependency]
//! trust-dns-resolver = "^0.6"
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
//! This uses the default configuration, which sets the [Google Public DNS](https://developers.google.com/speed/public-dns/) as the upstream resolvers. Please see their [privacy statement](https://developers.google.com/speed/public-dns/privacy) for important information about what they track, many ISP's track similar information in DNS.
//!
//! ```rust
//! use std::net::*;
//! use trust_dns_resolver::Resolver;
//! use trust_dns_resolver::config::*;
//!
//! // Construct a new Resolver with default configuration options
//! let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
//!
//! // Lookup the IP addresses associated with a name.
//! // The final dot forces this to be an FQDN, otherwise the search rules as specified
//! //  in `ResolverOpts` will take effect. FQDN's are generally cheaper queries.
//! let response = resolver.lookup_ip("www.example.com.").unwrap();
//!
//! // There can be many addresses associated with the name,
//! //  this can return IPv4 and/or IPv6 addresses
//! let address = response.iter().next().expect("no addresses returned!");
//! if address.is_ipv4() {
//!     assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
//! } else {
//!     assert_eq!(address, IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946)));
//! }
//! ```
//!
//! ## Using the host system config
//!
//! On Unix systems, the `/etc/resolv.conf` can be used for configuration. Not all options specified in the host systems `resolv.conf` are applicable or compatible with this software. In addition there may be additional options supported which the host system does not. Example:
//!
//! ```rust,no_run
//! # use std::net::*;
//! # use trust_dns_resolver::Resolver;
//! // Use the host OS'es `/etc/resolv.conf`
//! # #[cfg(unix)]
//! let resolver = Resolver::from_system_conf().unwrap();
//! # #[cfg(unix)]
//! let response = resolver.lookup_ip("www.example.com.").unwrap();
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
//! let resolver = ResolverFuture::new(ResolverConfig::default(), ResolverOpts::default(), &io_loop.handle());
//!
//! // Lookup the IP addresses associated with a name.
//! // This returns a future that will lookup the IP addresses, it must be run in the Core to
//! //  to get the actual result.
//! let lookup_future = resolver.lookup_ip("www.example.com.");
//!
//! // Run the lookup until it resolves or errors
//! let mut response = io_loop.run(lookup_future).unwrap();
//!
//! // There can be many addresses associated with the name,
//! //  this can return IPv4 and/or IPv6 addresses
//! let address = response.iter().next().expect("no addresses returned!");
//! if address.is_ipv4() {
//!     assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
//! } else {
//!     assert_eq!(address, IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946)));
//! }
//! # }
//! ```
//!
//! Generally after a lookup in an asynchornous context, there would probably be a connection made to a server, for example:
//!
//! ```c
//! let result = io_loop.run(lookup_future.and_then(|ips| {
//!                                  let ip = ips.next().unwrap();
//!                                  TcpStream::connect()
//!                              }).and_then(|conn| /* do something with the connection... */)
//!                          ).unwrap();
//! ```
//!
//! It's beyond the scope of these examples to show how to deal with connection failures and looping etc. But if you wanted to say try a different address from the result set after a connection failure, it will be necessary to create a type that implements the `Future` trait. Inside the `Future::poll` method would be the place to implement a loop over the different IP addresses.

#![deny(missing_docs)]

#[macro_use]
extern crate error_chain;
extern crate futures;
#[cfg(all(feature = "ipconfig", target_os = "windows", target_pointer_width = "64"))]
extern crate ipconfig;
extern crate lalrpop_util;
#[macro_use]
extern crate log;
extern crate lru_cache;
extern crate tokio_core;
extern crate trust_dns_proto;

pub mod config;
pub mod error;
pub mod lookup_ip;
pub mod lookup;
pub mod lookup_state;
#[doc(hidden)]
pub mod name_server_pool;
mod resolver;
pub mod system_conf;
mod resolver_future;
mod hosts;

pub use resolver::Resolver;
pub use resolver_future::ResolverFuture;
pub use hosts::Hosts;

/// returns a version as specified in Cargo.toml
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
