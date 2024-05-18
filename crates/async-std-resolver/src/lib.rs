// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

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
#![allow(clippy::needless_doctest_main)]

//! The Resolver is responsible for performing recursive queries to lookup domain names.
//!
//! This is a 100% in process DNS resolver. It *does not* use the Host OS' resolver. If what is desired is to use the Host OS' resolver, generally in the system's libc, then the `std::net::ToSocketAddrs` variant over `&str` should be used.
//!
//! Unlike the `hickory-client`, this tries to provide a simpler interface to perform DNS queries. For update options, i.e. Dynamic DNS, the `hickory-client` crate must be used instead. The Resolver library is capable of searching multiple domains (this can be disabled by using an FQDN during lookup), dual-stack IPv4/IPv6 lookups, performing chained CNAME lookups, and features connection metric tracking for attempting to pick the best upstream DNS resolver.
//!
//! Use [`AsyncResolver`] for performing DNS queries. `AsyncResolver` is a `async-std` based async resolver, and can be used inside any `asyn-std` based system.
//!
//! This as best as possible attempts to abide by the DNS RFCs, please file issues at <https://github.com/hickory-dns/hickory-dns>.
//!
//! # Usage
//!
//! ## Declare dependency
//!
//! ```toml
//! [dependency]
//! async-std-resolver = "*"
//! ```
//!
//! ## Using the async-std Resolver
//!
//! For more advanced asynchronous usage, the [`AsyncResolver`] is integrated with async-std.
//!
//! ```rust
//! use std::net::*;
//! use async_std::prelude::*;
//! use async_std_resolver::{resolver, config};
//!
//! #[async_std::main]
//! async fn main() {
//!   // Construct a new Resolver with default configuration options
//!   let resolver = resolver(
//!     config::ResolverConfig::default(),
//!     config::ResolverOpts::default(),
//!   ).await;
//!
//!   // Lookup the IP addresses associated with a name.
//!   // This returns a future that will lookup the IP addresses, it must be run in the Core to
//!   //  to get the actual result.
//!   let mut response = resolver.lookup_ip("www.example.com.").await.unwrap();
//!
//!   // There can be many addresses associated with the name,
//!   //  this can return IPv4 and/or IPv6 addresses
//!   let address = response.iter().next().expect("no addresses returned!");
//!   if address.is_ipv4() {
//!     assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)));
//!   } else {
//!     assert_eq!(address, IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c)));
//!   }
//! }
//! ```
//!
//! ## Using the host system config
//!
//! On Unix systems, the `/etc/resolv.conf` can be used for configuration. Not all options specified in the host systems `resolv.conf` are applicable or compatible with this software. In addition there may be additional options supported which the host system does not. Example:
//!
//! ```
//! use std::net::*;
//! use async_std::prelude::*;
//! # #[cfg(feature = "system-config")]
//! use async_std_resolver::{resolver_from_system_conf, config};
//!
//! #[async_std::main]
//! async fn main() {
//! # #[cfg(feature = "system-config")]
//! # {
//!   // Use the host OS'es `/etc/resolv.conf`
//!   let resolver = resolver_from_system_conf().await.unwrap();
//!   let response = resolver.lookup_ip("www.example.com.").await.unwrap();
//! # }
//! }
//! ```

use hickory_resolver::AsyncResolver;

use crate::runtime::AsyncStdConnectionProvider;

mod net;
mod runtime;
#[cfg(test)]
mod tests;
mod time;

pub use hickory_resolver::config;
pub use hickory_resolver::error::ResolveError;
pub use hickory_resolver::lookup;
pub use hickory_resolver::lookup_ip;
pub use hickory_resolver::proto;

/// An AsyncResolver used with async_std
pub type AsyncStdResolver = AsyncResolver<AsyncStdConnectionProvider>;

/// Construct a new async-std based `AsyncResolver` with the provided configuration.
///
/// # Arguments
///
/// * `config` - configuration, name_servers, etc. for the Resolver
/// * `options` - basic lookup options for the resolver
///
/// # Returns
///
/// A tuple containing the new `AsyncResolver` and a future that drives the
/// background task that runs resolutions for the `AsyncResolver`. See the
/// documentation for `AsyncResolver` for more information on how to use
/// the background future.
pub async fn resolver(
    config: config::ResolverConfig,
    options: config::ResolverOpts,
) -> AsyncStdResolver {
    AsyncStdResolver::new(config, options, AsyncStdConnectionProvider::default())
}

/// Constructs a new async-std based Resolver with the system configuration.
///
/// This will use `/etc/resolv.conf` on Unix OSes and the registry on Windows.
#[cfg(any(unix, target_os = "windows"))]
#[cfg(feature = "system-config")]
pub async fn resolver_from_system_conf() -> Result<AsyncStdResolver, ResolveError> {
    AsyncStdResolver::from_system_conf(AsyncStdConnectionProvider::default())
}
