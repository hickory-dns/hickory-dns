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
//! Unlike the `trust-dns` client, this tries to provide a simpler interface to perform DNS queries. For update options, i.e. Dynamic DNS, the `trust-dns` crate must be used instead. The Resolver library is capable of searching multiple domains (this can be disabled by using an FQDN during lookup), dual-stack IPv4/IPv6 lookups, performing chained CNAME lookups, and features connection metric tracking for attempting to pick the best upstream DNS resolver.
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
//! trust-dns-resolver = "^0.9"
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
//! # extern crate tokio;
//! # extern crate trust_dns_resolver;
//! # fn main() {
//! use std::net::*;
//! use tokio::runtime::current_thread::Runtime;
//! use trust_dns_resolver::AsyncResolver;
//! use trust_dns_resolver::config::*;
//!
//! // We need a Tokio Runtime to run the resolver
//! //  this is responsible for running all Future tasks and registering interest in IO channels
//! let mut io_loop = Runtime::new().unwrap();
//!
//! // Construct a new Resolver with default configuration options
//! let (resolver, background) = AsyncResolver::new(
//!     ResolverConfig::default(),
//!     ResolverOpts::default()
//! );
//! // AsyncResolver::new returns a handle for sending resolve requests and a background task
//! // that must be spawned on an executor.
//! io_loop.spawn(background);
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
//! let result = io_loop.block_on(lookup_future.and_then(|ips| {
//!                                  let ip = ips.next().unwrap();
//!                                  TcpStream::connect()
//!                              }).and_then(|conn| /* do something with the connection... */)
//!                          ).unwrap();
//! ```
//!
//! It's beyond the scope of these examples to show how to deal with connection failures and looping etc. But if you wanted to say try a different address from the result set after a connection failure, it will be necessary to create a type that implements the `Future` trait. Inside the `Future::poll` method would be the place to implement a loop over the different IP addresses.
//!
//! ## DNS-over-TLS
//!
//! DNS over TLS is experimental in the TRust-DNS Resolver library. The underlying implementations have been available as addon libraries to the Client and Server, but the configuration is experimental in TRust-DNS Resolver. *WARNING* The trust-dns developers make no claims on the security and/or privacy guarantees of this implementation.
//!
//! To use you must compile in support with one of the `dns-over-tls` features. There are three: `dns-over-openssl`, `dns-over-native-tls`, and `dns-over-rustls`. The reason for each is to make the TRust-DNS libraries flexible for different deployments, and/or security concerns. The easiest to use will generally be `dns-over-rustls` which utilizes the native Rust library (a rework of the `boringssl` project), this should compile and be usable on most ARM and x86 platforms. `dns-over-native-tls` will utilize the hosts TLS implementation where available or fallback to `openssl` where not. `dns-over-openssl` will specify that `openssl` should be used (which is a perfect fine option if required). If more than one is specified, the presidence will be in this order (i.e. only one can be used at a time) `dns-over-rustls`, `dns-over-native-tls`, and then `dns-over-openssl`. *NOTICE* thetrust-dns developers are not responsible for any choice of library that does not meet required security requirements.
//!
//! ### Example
//!
//! Enable the TLS library through the dependency on `trust-dns-resolver`:
//!
//! ```toml
//! trust-dns-resolver = { version = "*", features = ["dns-over-rustls"] }
//! ```
//!
//! A default TLS configuration is available for Cloudflare's `1.1.1.1` DNS service (Quad9 as well):
//!
//! ```rust,no_run
//! # extern crate trust_dns_resolver;
//! # fn main() {
//! use trust_dns_resolver::Resolver;
//! use trust_dns_resolver::config::*;
//!
//! // Construct a new Resolver with default configuration options
//! # #[cfg(feature = "dns-over-tls")]
//! let mut resolver = Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap();
//!
//! // see example above...
//! # }
//! ```
//!
//! ## mDNS (multicast DNS)
//!
//! Multicast DNS is an experimental feature in TRust-DNS at the moment. It's support on different platforms is not yet ideal. Initial support is only for IPv4 mDNS, as there are some complexities to figure out with IPv6. Once enabled, an mDNS `NameServer` will automatically be added to the `Resolver` and used for any lookups performed in the `.local.` zone.

#![warn(missing_docs)]
#![recursion_limit = "128"]

#[cfg(feature = "dns-over-tls")]
#[macro_use]
extern crate cfg_if;
extern crate failure;
#[macro_use]
extern crate futures;
#[cfg(target_os = "windows")]
extern crate ipconfig;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate lru_cache;
extern crate resolv_conf;
#[cfg(feature = "serde-config")]
#[macro_use]
extern crate serde_derive;
#[cfg(feature = "serde-config")]
extern crate serde;
extern crate smallvec;
extern crate tokio;
#[cfg(feature = "dns-over-https")]
extern crate trust_dns_https;
#[cfg(feature = "dns-over-native-tls")]
extern crate trust_dns_native_tls;
#[cfg(feature = "dns-over-openssl")]
extern crate trust_dns_openssl;
pub extern crate trust_dns_proto as proto;
#[cfg(feature = "dns-over-rustls")]
extern crate trust_dns_rustls;

mod async_resolver;
pub mod config;
mod dns_lru;
pub mod dns_sd;
pub mod error;
mod hosts;
#[cfg(feature = "dns-over-https")]
mod https;
pub mod lookup;
pub mod lookup_ip;
pub mod lookup_state;
#[doc(hidden)]
pub mod name_server_pool;
mod resolver;
pub mod system_conf;
#[cfg(feature = "dns-over-tls")]
mod tls;

// reexports from proto
pub use self::proto::rr::{IntoName, Name, TryParseIp};

pub use async_resolver::{AsyncResolver, Background, BackgroundLookup, BackgroundLookupIp};
pub use hosts::Hosts;
pub use resolver::Resolver;

/// This is an alias for [`AsyncResolver`], which replaced the type previously
/// called `ResolverFuture`.
///
/// # Note
///
/// For users of `ResolverFuture`, the return type for `ResolverFuture::new`
/// has changed since version 0.9 of `trust-dns-resolver`. It now returns
/// a tuple of an [`AsyncResolver`] _and_ a background future, which must
/// be spawned on a reactor before any lookup futures will run.
///
/// See the [`AsyncResolver`] documentation for more information on how to
/// use the background future.
#[deprecated(note = "use [`trust_dns_resolver::AsyncResolver`] instead")]
pub type ResolverFuture = AsyncResolver;

/// returns a version as specified in Cargo.toml
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
