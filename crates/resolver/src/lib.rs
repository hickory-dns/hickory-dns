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
//! ## Using the host system config
//!
//! On Unix systems, the `/etc/resolv.conf` can be used for configuration. Not all options
//! specified in the host systems `resolv.conf` are applicable or compatible with this software. In
//! addition there may be additional options supported which the host system does not. Example:
//!
//! ```rust,no_run
//! # #[tokio::main]
//! # async fn main() {
//! # #[cfg(feature = "tokio")]
//! # {
//! # use std::net::*;
//! # use hickory_resolver::Resolver;
//! // Use the host OS'es `/etc/resolv.conf`
//! # #[cfg(unix)]
//! let resolver = Resolver::tokio_from_system_conf().unwrap();
//! # #[cfg(unix)]
//! let response = resolver.lookup_ip("www.example.com.").await.unwrap();
//! # }
//! # }
//! ```
//!
//! ## Using the Tokio/Async Resolver
//!
//! ```rust
//! # fn main() {
//! # #[cfg(feature = "tokio")]
//! # {
//! use std::net::*;
//! use tokio::runtime::Runtime;
//! use hickory_resolver::TokioResolver;
//! use hickory_resolver::config::*;
//!
//! // We need a Tokio Runtime to run the resolver
//! //  this is responsible for running all Future tasks and registering interest in IO channels
//! let mut io_loop = Runtime::new().unwrap();
//!
//! // Construct a new Resolver with default configuration options
//! let resolver = io_loop.block_on(async {
//!     TokioResolver::tokio(
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
//! let _address = response.iter().next().expect("no addresses returned!");
//! # }
//! # }
//! ```
//!
//! Generally after a lookup in an asynchronous context, there would probably be a connection made
//! to a server, for example:
//!
//! ```rust,no_run
//! # fn main() {
//! # #[cfg(feature = "tokio")]
//! # {
//! # use std::net::*;
//! # use tokio::runtime::Runtime;
//! # use hickory_resolver::TokioResolver;
//! # use hickory_resolver::config::*;
//! # use futures_util::TryFutureExt;
//! #
//! # let mut io_loop = Runtime::new().unwrap();
//! #
//! # let resolver = io_loop.block_on(async {
//! #    TokioResolver::tokio(
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
//! ## Optional protocol support
//!
//! The following DNS protocols are optionally supported:
//!
//! - Enable `tls` for DNS over TLS (DoT)
//! - Enable `https-rustls` for DNS over HTTP/2 (DoH)
//! - Enable `quic` for DNS over QUIC (DoQ)
//! - Enable `h3` for DNS over HTTP/3 (DoH3)
//!
//! ### Example
//!
//! Enable the TLS library through the dependency on `hickory-resolver`:
//!
//! ```toml
//! hickory-resolver = { version = "*", features = ["tls"] }
//! ```
//!
//! A default TLS configuration is available for Cloudflare's `1.1.1.1` DNS service (Quad9 as
//! well):
//!
//! ```rust,no_run
//! # fn main() {
//! # #[cfg(feature = "tokio")]
//! # {
//! use hickory_resolver::TokioResolver;
//! use hickory_resolver::config::*;
//!
//! // Construct a new Resolver with default configuration options
//! # #[cfg(feature = "__tls")]
//! let mut resolver = TokioResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default());
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

pub use hickory_proto as proto;
// reexports from proto
pub use proto::rr::{IntoName, Name};

#[cfg(feature = "async-std")]
pub mod async_std;
pub mod caching_client;
pub mod config;
pub mod dns_lru;
mod error;
pub use error::{ResolveError, ResolveErrorKind};
#[cfg(feature = "__https")]
mod h2;
#[cfg(feature = "__h3")]
mod h3;
mod hosts;
pub use hosts::Hosts;
pub mod lookup;
pub mod lookup_ip;
// TODO: consider #[doc(hidden)]
pub mod name_server;
#[cfg(feature = "tokio")]
use name_server::TokioConnectionProvider;
#[cfg(feature = "__quic")]
mod quic;
mod resolver;
pub use resolver::LookupFuture;
pub use resolver::Resolver;
#[cfg(feature = "tokio")]
pub use resolver::TokioResolver;
pub mod system_conf;
#[cfg(test)]
mod tests;
#[cfg(feature = "__tls")]
mod tls;

#[doc(hidden)]
#[deprecated(since = "0.25.0", note = "use `Resolver` instead")]
pub type AsyncResolver<P> = Resolver<P>;

#[doc(hidden)]
#[deprecated(since = "0.25.0", note = "use `TokioResolver` instead")]
#[cfg(feature = "tokio")]
pub type TokioAsyncResolver = Resolver<TokioConnectionProvider>;

/// returns a version as specified in Cargo.toml
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
