// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
// Copyright 2017 Google LLC.
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![warn(
    missing_docs,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::unimplemented
)]
#![recursion_limit = "2048"]

//! Trust-DNS Protocol library

use async_trait::async_trait;
use futures::Future;

use std::marker::Send;
use std::time::Duration;
#[cfg(any(test, feature = "tokio-runtime"))]
use tokio::runtime::Runtime;
#[cfg(any(test, feature = "tokio-runtime"))]
use tokio::task::JoinHandle;

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
pub fn spawn_bg<F: Future<Output = R> + Send + 'static, R: Send + 'static>(
    runtime: &Runtime,
    background: F,
) -> JoinHandle<R> {
    runtime.spawn(background)
}

pub mod error;
#[cfg(feature = "mdns")]
pub mod multicast;
pub mod op;
pub mod rr;
pub mod serialize;
pub mod tcp;
#[cfg(any(test, feature = "testing"))]
pub mod tests;
pub mod udp;
pub mod xfer;

#[doc(hidden)]
pub use crate::xfer::dns_handle::{DnsHandle, DnsStreamHandle, StreamHandle};
#[doc(hidden)]
pub use crate::xfer::dns_multiplexer::DnsMultiplexer;
#[doc(hidden)]
#[cfg(feature = "dnssec")]
pub use crate::xfer::dnssec_dns_handle::DnssecDnsHandle;
#[doc(hidden)]
pub use crate::xfer::retry_dns_handle::RetryDnsHandle;
#[doc(hidden)]
pub use crate::xfer::{BufDnsStreamHandle, BufStreamHandle};
pub use error::ExtBacktrace;

#[cfg(feature = "tokio-runtime")]
#[doc(hidden)]
pub mod iocompat {
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use futures::io::{AsyncRead, AsyncWrite};
    use tokio::io::{AsyncRead as AsyncRead02, AsyncWrite as AsyncWrite02};

    /// Conversion from `tokio::io::{AsyncRead, AsyncWrite}` to `std::io::{AsyncRead, AsyncWrite}`
    pub struct AsyncIo02As03<T>(pub T);

    impl<T> Unpin for AsyncIo02As03<T> {}
    impl<R: AsyncRead02 + Unpin> AsyncRead for AsyncIo02As03<R> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl<W: AsyncWrite02 + Unpin> AsyncWrite for AsyncIo02As03<W> {
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
impl Executor for Runtime {
    fn new() -> Self {
        Runtime::new().expect("failed to create tokio runtime")
    }

    fn block_on<F: Future>(&mut self, future: F) -> F::Output {
        self.block_on(future)
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
    async fn timeout<F: 'static + Future + Send>(
        duration: Duration,
        future: F,
    ) -> Result<F::Output, std::io::Error>;
}

/// New type which is implemented using tokio::time::{Delay, Timeout}
#[cfg(any(test, feature = "tokio-runtime"))]
pub struct TokioTime;

#[cfg(any(test, feature = "tokio-runtime"))]
#[async_trait]
impl Time for TokioTime {
    async fn delay_for(duration: Duration) {
        tokio::time::delay_for(duration).await
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
