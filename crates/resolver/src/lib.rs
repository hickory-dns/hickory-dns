// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The Resolver is responsible for performing recursive queries to lookup domain names.
//!
//! This is a 100% in process DNS resolver. It *does not* use the Host OS' resolver. If what is
//! desired is to use the Host OS' resolver, generally in the system's libc, then the
//! `std::net::ToSocketAddrs` variant over `&str` should be used.
//!
//! Unlike the `hickory-client`, this tries to provide a simpler interface to perform DNS
//! queries. For update options, i.e. Dynamic DNS, the `hickory-client` crate must be used
//! instead. The Resolver library is capable of searching multiple domains (this can be disabled by
//! using an FQDN during lookup), dual-stack IPv4/IPv6 lookups, performing chained CNAME lookups,
//! and features connection metric tracking for attempting to pick the best upstream DNS resolver.
//!
//! There are two types for performing DNS queries, [`Resolver`] and [`AsyncResolver`]. `Resolver`
//! is the easiest to work with, it is a wrapper around [`AsyncResolver`]. `AsyncResolver` is a
//! `Tokio` based async resolver, and can be used inside any `Tokio` based system.
//!
//! This as best as possible attempts to abide by the DNS RFCs, please file issues at
//! <https://github.com/hickory-dns/hickory-dns>.
//!
//! # Usage
//!
//! ## Declare dependency
//!
//! ```toml
//! [dependency]
//! hickory-resolver = "*"
//! ```
//!
//! ## Using the Synchronous Resolver
//!
//! This uses the default configuration, which sets the [Google Public
//! DNS](https://developers.google.com/speed/public-dns/) as the upstream resolvers. Please see
//! their [privacy statement](https://developers.google.com/speed/public-dns/privacy) for important
//! information about what they track, many ISP's track similar information in DNS.
//!
//! ```rust
//! # fn main() {
//! # #[cfg(feature = "tokio-runtime")]
//! # {
//! use std::net::*;
//! use hickory_resolver::Resolver;
//! use hickory_resolver::config::*;
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
//!     assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)));
//! } else {
//!     assert_eq!(address, IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c)));
//! }
//! # }
//! # }
//! ```
//!
//! ## Using the host system config
//!
//! On Unix systems, the `/etc/resolv.conf` can be used for configuration. Not all options
//! specified in the host systems `resolv.conf` are applicable or compatible with this software. In
//! addition there may be additional options supported which the host system does not. Example:
//!
//! ```rust,no_run
//! # fn main() {
//! # #[cfg(feature = "tokio-runtime")]
//! # {
//! # use std::net::*;
//! # use hickory_resolver::Resolver;
//! // Use the host OS'es `/etc/resolv.conf`
//! # #[cfg(unix)]
//! let resolver = Resolver::from_system_conf().unwrap();
//! # #[cfg(unix)]
//! let response = resolver.lookup_ip("www.example.com.").unwrap();
//! # }
//! # }
//! ```
//!
//! ## Using the Tokio/Async Resolver
//!
//! For more advanced asynchronous usage, the `AsyncResolver`] is integrated with Tokio. In fact,
//! the [`AsyncResolver`] is used by the synchronous Resolver for all lookups.
//!
//! ```rust
//! # fn main() {
//! # #[cfg(feature = "tokio-runtime")]
//! # {
//! use std::net::*;
//! use tokio::runtime::Runtime;
//! use hickory_resolver::TokioAsyncResolver;
//! use hickory_resolver::config::*;
//!
//! // We need a Tokio Runtime to run the resolver
//! //  this is responsible for running all Future tasks and registering interest in IO channels
//! let mut io_loop = Runtime::new().unwrap();
//!
//! // Construct a new Resolver with default configuration options
//! let resolver = io_loop.block_on(async {
//!     TokioAsyncResolver::tokio(
//!         ResolverConfig::default(),
//!         ResolverOpts::default())
//! });
//!
//! // Lookup the IP addresses associated with a name.
//! // This returns a future that will lookup the IP addresses, it must be run in the Core to
//! //  to get the actual result.
//! let lookup_future = resolver.lookup_ip("www.example.com.");
//!
//! // Run the lookup until it resolves or errors
//! let mut response = io_loop.block_on(lookup_future).unwrap();
//!
//! // There can be many addresses associated with the name,
//! //  this can return IPv4 and/or IPv6 addresses
//! let address = response.iter().next().expect("no addresses returned!");
//! if address.is_ipv4() {
//!     assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)));
//! } else {
//!     assert_eq!(address, IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c)));
//! }
//! # }
//! # }
//! ```
//!
//! Generally after a lookup in an asynchronous context, there would probably be a connection made
//! to a server, for example:
//!
//! ```rust,no_run
//! # fn main() {
//! # #[cfg(feature = "tokio-runtime")]
//! # {
//! # use std::net::*;
//! # use tokio::runtime::Runtime;
//! # use hickory_resolver::TokioAsyncResolver;
//! # use hickory_resolver::config::*;
//! # use futures_util::TryFutureExt;
//! #
//! # let mut io_loop = Runtime::new().unwrap();
//! #
//! # let resolver = io_loop.block_on(async {
//! #    TokioAsyncResolver::tokio(
//! #        ResolverConfig::default(),
//! #        ResolverOpts::default())
//! # });
//! #
//! let ips = io_loop.block_on(resolver.lookup_ip("www.example.com.")).unwrap();
//!
//! let result = io_loop.block_on(async {
//!     let ip = ips.iter().next().unwrap();
//!     TcpStream::connect((ip, 443))
//! })
//! .and_then(|conn| Ok(conn) /* do something with the connection... */)
//! .unwrap();
//! # }
//! # }
//! ```
//!
//! It's beyond the scope of these examples to show how to deal with connection failures and
//! looping etc. But if you wanted to say try a different address from the result set after a
//! connection failure, it will be necessary to create a type that implements the `Future` trait.
//! Inside the `Future::poll` method would be the place to implement a loop over the different IP
//! addresses.
//!
//! ## DNS-over-TLS and DNS-over-HTTPS
//!
//! DNS-over-TLS and DNS-over-HTTPS are supported in the Hickory DNS Resolver library. The underlying
//! implementations are available as addon libraries. *WARNING* The hickory-dns developers make no
//! claims on the security and/or privacy guarantees of this implementation.
//!
//! To use DNS-over-TLS one of the `dns-over-tls` features must be enabled at compile time. There
//! are three: `dns-over-openssl`, `dns-over-native-tls`, and `dns-over-rustls`. For DNS-over-HTTPS
//! only rustls is supported with the `dns-over-https-rustls`, this implicitly enables support for
//! DNS-over-TLS as well. The reason for each is to make the Hickory DNS libraries flexible for
//! different deployments, and/or security concerns. The easiest to use will generally be
//! `dns-over-rustls` which utilizes the `*ring*` Rust cryptography library (a rework of the
//! `boringssl` project), this should compile and be usable on most ARM and x86 platforms.
//! `dns-over-native-tls` will utilize the hosts TLS implementation where available or fallback to
//! `openssl` where not supported. `dns-over-openssl` will specify that `openssl` should be used
//! (which is a perfectly fine option if required). If more than one is specified, the precedence
//! will be in this order (i.e. only one can be used at a time) `dns-over-rustls`,
//! `dns-over-native-tls`, and then `dns-over-openssl`. **NOTICE** the Hickory DNS developers are not
//! responsible for any choice of library that does not meet required security requirements.
//!
//! ### Example
//!
//! Enable the TLS library through the dependency on `hickory-resolver`:
//!
//! ```toml
//! hickory-resolver = { version = "*", features = ["dns-over-rustls"] }
//! ```
//!
//! A default TLS configuration is available for Cloudflare's `1.1.1.1` DNS service (Quad9 as
//! well):
//!
//! ```rust,no_run
//! # fn main() {
//! # #[cfg(feature = "tokio-runtime")]
//! # {
//! use hickory_resolver::Resolver;
//! use hickory_resolver::config::*;
//!
//! // Construct a new Resolver with default configuration options
//! # #[cfg(feature = "dns-over-tls")]
//! let mut resolver = Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap();
//!
//! // see example above...
//! # }
//! # }
//! ```
//!
//! ## mDNS (multicast DNS)
//!
//! Multicast DNS is an experimental feature in Hickory DNS at the moment. Its support on different
//! platforms is not yet ideal. Initial support is only for IPv4 mDNS, as there are some
//! complexities to figure out with IPv6. Once enabled, an mDNS `NameServer` will automatically be
//! added to the `Resolver` and used for any lookups performed in the `.local.` zone.

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
#![recursion_limit = "128"]
#![allow(clippy::needless_doctest_main, clippy::single_component_path_imports)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

#[cfg(feature = "dns-over-tls")]
#[macro_use]
extern crate cfg_if;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;
pub extern crate hickory_proto as proto;

mod async_resolver;
pub mod caching_client;
pub mod config;
pub mod dns_lru;
pub mod error;
#[cfg(feature = "dns-over-https-rustls")]
mod h2;
#[cfg(feature = "dns-over-h3")]
mod h3;
mod hosts;
pub mod lookup;
pub mod lookup_ip;
// TODO: consider #[doc(hidden)]
pub mod name_server;
#[cfg(feature = "dns-over-quic")]
mod quic;
#[cfg(feature = "tokio-runtime")]
mod resolver;
pub mod system_conf;
#[cfg(feature = "dns-over-tls")]
mod tls;

// reexports from proto
pub use self::proto::rr::{IntoName, Name, TryParseIp};

#[cfg(feature = "testing")]
pub use async_resolver::testing;
pub use async_resolver::AsyncResolver;
#[cfg(feature = "tokio-runtime")]
pub use async_resolver::TokioAsyncResolver;
pub use hosts::Hosts;
#[cfg(feature = "tokio-runtime")]
pub use resolver::Resolver;

/// This is an alias for [`AsyncResolver`], which replaced the type previously
/// called `ResolverFuture`.
#[deprecated(note = "use [`hickory_resolver::AsyncResolver`] instead")]
#[cfg(feature = "tokio-runtime")]
pub type ResolverFuture = TokioAsyncResolver;

/// returns a version as specified in Cargo.toml
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
