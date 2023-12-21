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
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), feature(error_in_core))]
#![cfg_attr(not(feature = "std"), feature(ip_in_core))]

//! Hickory DNS Protocol library

#[cfg(not(any(feature = "std", feature = "unstable")))]
compile_error!(
    "Currently, no_std support only works with unstable features. Use a nightly toolchain and the `unstable` feature, or enable the `std` feature."
);

#[cfg(feature = "std")]
extern crate std;

#[macro_use]
extern crate alloc;

use async_trait::async_trait;

#[cfg(not(feature = "std"))]
use const_random::const_random;
#[cfg(not(feature = "std"))]
use core::cell::RefCell;
#[cfg(not(feature = "std"))]
use critical_section::Mutex;
#[cfg(not(feature = "std"))]
use once_cell::sync::Lazy;

use futures_util::future::Future;

use alloc::boxed::Box;
#[cfg(feature = "std")]
use core::marker::Send;
use core::time::Duration;

#[cfg(any(test, feature = "tokio-runtime"))]
use tokio::runtime::Runtime;
#[cfg(any(test, feature = "tokio-runtime"))]
use tokio::task::JoinHandle;

#[cfg(not(feature = "std"))]
use rand::{rngs::StdRng, Rng, SeedableRng};

#[cfg(not(feature = "std"))]
pub(crate) use core::net;
#[cfg(feature = "std")]
pub(crate) use rand::random;
#[cfg(feature = "std")]
pub(crate) use std::net;

#[cfg(not(feature = "std"))]
use rand::distributions::{Distribution, Standard};

#[cfg(not(feature = "std"))]
static SEEDED_RNG: Lazy<Mutex<RefCell<StdRng>>> =
    Lazy::new(|| Mutex::new(RefCell::new(StdRng::seed_from_u64(const_random!(u64)))));

/// Seed the RNG used to create random DNS IDs throughout the lib (no_std-only).
#[cfg(not(feature = "std"))]
pub fn seed_rng(seed: u64) {
    critical_section::with(|cs| *SEEDED_RNG.borrow(cs).borrow_mut() = StdRng::seed_from_u64(seed));
}

/// Generates a random value on `no_std`.
/// The random value is predictable for each compilation unit (using [`const_random`],
/// unless seeded using [`crate::seed_rng`]!
/// Depending on the usage of this library, this may yield predictable DNS requests that attackers can
/// use to feed wrong responses to hickory.
/// Always seed this library before using in `no_std` environments, if possible.
#[cfg(not(feature = "std"))]
pub(crate) fn random<T>() -> T
where
    Standard: Distribution<T>,
{
    critical_section::with(|cs| SEEDED_RNG.borrow(cs).borrow_mut().gen())
}

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

/// Spawn a background task, if it was present
#[cfg(any(test, feature = "tokio-runtime"))]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio-runtime")))]
pub fn spawn_bg<F: Future<Output = R> + Send + 'static, R: Send + 'static>(
    runtime: &Runtime,
    background: F,
) -> JoinHandle<R> {
    runtime.spawn(background)
}

pub mod error;
#[cfg(feature = "dns-over-https")]
#[cfg_attr(docsrs, doc(cfg(feature = "dns-over-https")))]
pub mod h2;
#[cfg(feature = "dns-over-h3")]
#[cfg_attr(docsrs, doc(cfg(feature = "dns-over-h3")))]
pub mod h3;
#[cfg(any(feature = "dns-over-https", feature = "dns-over-h3"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "dns-over-https", feature = "dns-over-h3")))
)]
pub mod http;
#[cfg(feature = "mdns")]
#[cfg_attr(docsrs, doc(cfg(feature = "mdns")))]
pub mod multicast;
#[cfg(feature = "dns-over-native-tls")]
#[cfg_attr(docsrs, doc(cfg(feature = "dns-over-native-tls")))]
pub mod native_tls;
pub mod op;
#[cfg(feature = "dns-over-openssl")]
#[cfg_attr(docsrs, doc(cfg(feature = "dns-over-openssl")))]
pub mod openssl;
#[cfg(all(feature = "dns-over-quic", feature = "tokio-runtime"))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(feature = "dns-over-quic", feature = "tokio-runtime")))
)]
pub mod quic;
pub mod rr;
#[cfg(feature = "dns-over-rustls")]
#[cfg_attr(docsrs, doc(cfg(feature = "dns-over-rustls")))]
pub mod rustls;
pub mod serialize;
#[cfg(feature = "std")]
pub mod tcp;
#[cfg(feature = "std")]
#[cfg(any(test, feature = "testing"))]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
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
#[cfg(feature = "dnssec")]
pub use crate::xfer::dnssec_dns_handle::DnssecDnsHandle;
#[doc(hidden)]
pub use crate::xfer::retry_dns_handle::RetryDnsHandle;
#[doc(hidden)]
#[cfg(feature = "std")]
pub use crate::xfer::BufDnsStreamHandle;
#[cfg(feature = "backtrace")]
#[cfg_attr(docsrs, doc(cfg(feature = "backtrace")))]
pub use error::ExtBacktrace;

#[cfg(feature = "tokio-runtime")]
#[doc(hidden)]
pub mod iocompat {
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use std::io;

    use futures_io::{AsyncRead, AsyncWrite};
    use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite, ReadBuf};

    /// Conversion from `tokio::io::{AsyncRead, AsyncWrite}` to `std::io::{AsyncRead, AsyncWrite}`
    pub struct AsyncIoTokioAsStd<T: TokioAsyncRead + TokioAsyncWrite>(pub T);

    impl<T: TokioAsyncRead + TokioAsyncWrite + Unpin> Unpin for AsyncIoTokioAsStd<T> {}
    impl<R: TokioAsyncRead + TokioAsyncWrite + Unpin> AsyncRead for AsyncIoTokioAsStd<R> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut buf = ReadBuf::new(buf);
            let polled = Pin::new(&mut self.0).poll_read(cx, &mut buf);

            polled.map_ok(|_| buf.filled().len())
        }
    }

    impl<W: TokioAsyncRead + TokioAsyncWrite + Unpin> AsyncWrite for AsyncIoTokioAsStd<W> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    /// Conversion from `std::io::{AsyncRead, AsyncWrite}` to `tokio::io::{AsyncRead, AsyncWrite}`
    pub struct AsyncIoStdAsTokio<T: AsyncRead + AsyncWrite>(pub T);

    impl<T: AsyncRead + AsyncWrite + Unpin> Unpin for AsyncIoStdAsTokio<T> {}
    impl<R: AsyncRead + AsyncWrite + Unpin> TokioAsyncRead for AsyncIoStdAsTokio<R> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0)
                .poll_read(cx, buf.initialized_mut())
                .map_ok(|len| buf.advance(len))
        }
    }

    impl<W: AsyncRead + AsyncWrite + Unpin> TokioAsyncWrite for AsyncIoStdAsTokio<W> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Pin::new(&mut self.get_mut().0).poll_close(cx)
        }
    }
}

/// Generic executor.
// This trait is created to facilitate running the tests defined in the tests mod using different types of
// executors. It's used in Fuchsia OS, please be mindful when update it.
pub trait Executor {
    /// Create the implementor itself.
    fn new() -> Self;

    /// Spawns a future object to run synchronously or asynchronously depending on the specific
    /// executor.
    fn block_on<F: Future>(&mut self, future: F) -> F::Output;
}

#[cfg(feature = "tokio-runtime")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio-runtime")))]
impl Executor for Runtime {
    fn new() -> Self {
        Self::new().expect("failed to create tokio runtime")
    }

    fn block_on<F: Future>(&mut self, future: F) -> F::Output {
        Self::block_on(self, future)
    }
}

/// Generic Time for Delay and Timeout.
// This trait is created to allow to use different types of time systems. It's used in Fuchsia OS, please be mindful when update it.
#[async_trait]
pub trait Time {
    /// Return a type that implements `Future` that will wait until the specified duration has
    /// elapsed.
    async fn delay_for(duration: Duration);

    /// Return a type that implement `Future` to complete before the specified duration has elapsed.
    #[cfg(feature = "std")]
    async fn timeout<F: 'static + Future + Send>(
        duration: Duration,
        future: F,
    ) -> Result<F::Output, std::io::Error>;
}

/// New type which is implemented using tokio::time::{Delay, Timeout}
#[cfg(feature = "std")]
#[cfg(any(test, feature = "tokio-runtime"))]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio-runtime")))]
#[derive(Clone, Copy, Debug)]
pub struct TokioTime;

#[cfg(feature = "std")]
#[cfg(any(test, feature = "tokio-runtime"))]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio-runtime")))]
#[async_trait]
impl Time for TokioTime {
    async fn delay_for(duration: Duration) {
        tokio::time::sleep(duration).await
    }

    async fn timeout<F: 'static + Future + Send>(
        duration: Duration,
        future: F,
    ) -> Result<F::Output, std::io::Error> {
        tokio::time::timeout(duration, future)
            .await
            .map_err(move |_| std::io::Error::new(std::io::ErrorKind::TimedOut, "future timed out"))
    }
}
