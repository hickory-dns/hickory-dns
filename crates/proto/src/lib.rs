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
    clippy::alloc_instead_of_core,
    clippy::default_trait_access,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
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

#[cfg(feature = "access-control")]
pub mod access_control;
#[cfg(any(feature = "dnssec-aws-lc-rs", feature = "dnssec-ring"))]
pub mod dnssec;
mod error;
#[cfg(feature = "__https")]
pub mod h2;
#[cfg(feature = "__h3")]
pub mod h3;
#[cfg(any(feature = "__https", feature = "__h3"))]
pub mod http;
#[cfg(feature = "mdns")]
pub mod multicast;
pub mod op;
#[cfg(all(feature = "__quic", feature = "tokio"))]
pub mod quic;
pub mod rr;
#[cfg(feature = "std")]
pub mod runtime;
#[cfg(feature = "__tls")]
pub mod rustls;
pub mod serialize;
#[cfg(feature = "std")]
pub mod tcp;
#[cfg(feature = "std")]
pub mod udp;
pub mod xfer;

#[doc(hidden)]
#[cfg(feature = "std")]
pub use crate::xfer::BufDnsStreamHandle;
#[doc(hidden)]
#[cfg(feature = "std")]
pub use crate::xfer::dns_handle::{DnsHandle, DnsStreamHandle};
#[doc(hidden)]
#[cfg(feature = "std")]
pub use crate::xfer::dns_multiplexer::DnsMultiplexer;
#[doc(hidden)]
#[cfg(feature = "std")]
pub use crate::xfer::retry_dns_handle::RetryDnsHandle;
pub use error::{DnsError, ForwardNSData, NoRecords, ProtoError, ProtoErrorKind};
#[cfg(feature = "backtrace")]
pub use error::{ENABLE_BACKTRACE, ExtBacktrace};

#[cfg(feature = "std")]
pub(crate) use rand::random;

#[cfg(all(not(feature = "std"), feature = "no-std-rand"))]
pub(crate) use no_std_rand::random;
#[cfg(all(not(feature = "std"), feature = "no-std-rand"))]
pub use no_std_rand::seed;

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A simple shim that allows us to use a [`random`] in `no_std` environments.
#[cfg(all(not(feature = "std"), feature = "no-std-rand"))]
mod no_std_rand {
    use core::cell::RefCell;

    use critical_section::Mutex;
    use rand::distr::{Distribution, StandardUniform};
    use rand::{Rng, SeedableRng, rngs::StdRng};

    /// Generates a random value on `no_std`.
    ///
    /// # Panics
    /// This function will panic if the rng has not been seeded.
    /// The rng needs to be seeded using [`crate::seed`] before it can be used!
    pub(crate) fn random<T>() -> T
    where
        StandardUniform: Distribution<T>,
    {
        critical_section::with(|cs| {
            RNG.borrow_ref_mut(cs)
                .as_mut()
                .expect("the no_std rng was not seeded using `hickory_proto::seed()`")
                .random()
        })
    }

    /// Seed the rng that is used to create random DNS IDs throughout the lib (no_std-only).
    pub fn seed(seed: u64) {
        critical_section::with(|cs| *RNG.borrow_ref_mut(cs) = Some(StdRng::seed_from_u64(seed)));
    }

    static RNG: Mutex<RefCell<Option<StdRng>>> = Mutex::new(RefCell::new(None));

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn test_no_std_rand() {
            // In practice, the seed needs to be a secure random number.
            seed(0x1337);
            let _ = random::<u32>();
        }
    }
}

/// Authoritative DNS root servers.
///
/// <https://www.iana.org/domains/root/servers>
pub const ROOTS: &[IpAddr] = &[
    // a.root-servers.net
    IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)),
    IpAddr::V6(Ipv6Addr::new(
        0x2001, 0x503, 0xba3e, 0x0, 0x0, 0x0, 0x2, 0x30,
    )),
    // b.root-servers.net
    IpAddr::V4(Ipv4Addr::new(170, 247, 170, 2)),
    IpAddr::V6(Ipv6Addr::new(0x2801, 0x1b8, 0x10, 0x0, 0x0, 0x0, 0x0, 0xb)),
    // c.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 33, 4, 12)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x2, 0x0, 0x0, 0x0, 0x0, 0xc)),
    // d.root-servers.net
    IpAddr::V4(Ipv4Addr::new(199, 7, 91, 13)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x2d, 0x0, 0x0, 0x0, 0x0, 0xd)),
    // e.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 203, 230, 10)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0xa8, 0x0, 0x0, 0x0, 0x0, 0xe)),
    // f.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 5, 5, 241)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x2f, 0x0, 0x0, 0x0, 0x0, 0xf)),
    // g.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 112, 36, 4)),
    IpAddr::V6(Ipv6Addr::new(
        0x2001, 0x500, 0x12, 0x0, 0x0, 0x0, 0x0, 0xd0d,
    )),
    // h.root-servers.net
    IpAddr::V4(Ipv4Addr::new(198, 97, 190, 53)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x1, 0x0, 0x0, 0x0, 0x0, 0x53)),
    // i.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 36, 148, 17)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x7fe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x53)),
    // j.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 58, 128, 30)),
    IpAddr::V6(Ipv6Addr::new(
        0x2001, 0x503, 0xc27, 0x0, 0x0, 0x0, 0x2, 0x30,
    )),
    // k.root-servers.net
    IpAddr::V4(Ipv4Addr::new(193, 0, 14, 129)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x7fd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1)),
    // l.root-servers.net
    IpAddr::V4(Ipv4Addr::new(199, 7, 83, 42)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x9f, 0x0, 0x0, 0x0, 0x0, 0x42)),
    // m.root-servers.net
    IpAddr::V4(Ipv4Addr::new(202, 12, 27, 33)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdc3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x35)),
];
