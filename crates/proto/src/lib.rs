// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
// Copyright 2017 Google LLC.
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![no_std]
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
    clippy::bool_to_int_with_if,
)]
#![recursion_limit = "2048"]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

//! Hickory DNS Protocol library

#[cfg(feature = "std")]
extern crate std;

#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
pub(crate) use core::net;
#[cfg(feature = "std")]
pub(crate) use std::net;

#[cfg(feature = "std")]
macro_rules! try_ready_stream {
    ($e:expr) => {{
        match $e {
            Poll::Ready(Some(Ok(t))) => t,
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(From::from(e)))),
        }
    }};
}

#[cfg(feature = "dnssec-ring")]
pub mod dnssec;
mod error;
#[cfg(feature = "dns-over-https-rustls")]
pub mod h2;
#[cfg(feature = "dns-over-h3")]
pub mod h3;
#[cfg(any(feature = "dns-over-https-rustls", feature = "dns-over-h3"))]
pub mod http;
#[cfg(feature = "mdns")]
pub mod multicast;
pub mod op;
#[cfg(all(feature = "dns-over-quic", feature = "tokio-runtime"))]
pub mod quic;
pub mod rr;
#[cfg(feature = "std")]
pub mod runtime;
#[cfg(feature = "dns-over-rustls")]
pub mod rustls;
pub mod serialize;
#[cfg(feature = "std")]
pub mod tcp;
#[cfg(feature = "std")]
#[cfg(any(test, feature = "testing"))]
pub mod tests;
#[cfg(feature = "std")]
pub mod udp;
pub mod xfer;

#[doc(hidden)]
pub use crate::xfer::dns_handle::{DnsHandle, DnsStreamHandle};
#[doc(hidden)]
#[cfg(feature = "std")]
pub use crate::xfer::dns_multiplexer::DnsMultiplexer;
#[doc(hidden)]
pub use crate::xfer::retry_dns_handle::RetryDnsHandle;
#[doc(hidden)]
#[cfg(feature = "std")]
pub use crate::xfer::BufDnsStreamHandle;
#[cfg(feature = "backtrace")]
pub use error::{ExtBacktrace, ENABLE_BACKTRACE};
pub use error::{ForwardData, ForwardNSData, ProtoError, ProtoErrorKind};

#[cfg(feature = "std")]
pub(crate) use rand::random;

#[cfg(not(feature = "std"))]
pub(crate) use no_std_rand::random;
#[cfg(not(feature = "std"))]
pub use no_std_rand::seed_rng;

/// A simple shim that allows us to use a [`StdRng`] in `no_std` environments.
#[cfg(not(feature = "std"))]
mod no_std_rand {

    use core::cell::RefCell;

    use critical_section::Mutex;
    use once_cell::sync::Lazy;
    use rand::distr::{Distribution, StandardUniform};
    use rand::{rngs::StdRng, Rng, SeedableRng};

    static SEEDED_RNG: Lazy<Mutex<RefCell<StdRng>>> =
        Lazy::new(|| Mutex::new(RefCell::new(StdRng::seed_from_u64(0x050BAD533D))));

    /// Seed the RNG used to create random DNS IDs throughout the lib (no_std-only).
    pub fn seed_rng(seed: u64) {
        critical_section::with(|cs| {
            *SEEDED_RNG.borrow(cs).borrow_mut() = StdRng::seed_from_u64(seed)
        });
    }

    /// Generates a random value on `no_std`.
    ///
    /// ** WARNING **
    /// The random value is predictable, unless seeded using [`crate::seed_rng`]!
    ///
    /// Depending on the usage of this library, this may yield predictable DNS requests that attackers can
    /// use to feed wrong responses to hickory.
    /// Always seed this library before using in `no_std` environments.
    pub(crate) fn random<T>() -> T
    where
        StandardUniform: Distribution<T>,
    {
        critical_section::with(|cs| SEEDED_RNG.borrow(cs).borrow_mut().random())
    }
}
