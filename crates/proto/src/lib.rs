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

#[cfg(any(test, feature = "testing"))]
use std::future::Future;

#[cfg(any(test, feature = "testing"))]
#[cfg(feature = "tokio-runtime")]
use tokio::runtime::Runtime;
#[cfg(any(test, feature = "testing"))]
#[cfg(feature = "tokio-runtime")]
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
#[cfg(any(test, feature = "testing"))]
#[cfg(feature = "tokio-runtime")]
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
pub use crate::xfer::dns_handle::{BasicDnsHandle, DnsHandle, DnsStreamHandle, StreamHandle};
#[doc(hidden)]
pub use crate::xfer::dns_multiplexer::DnsMultiplexer;
#[doc(hidden)]
pub use crate::xfer::retry_dns_handle::RetryDnsHandle;
#[doc(hidden)]
#[cfg(feature = "dnssec")]
pub use crate::xfer::secure_dns_handle::SecureDnsHandle;
#[doc(hidden)]
pub use crate::xfer::{BufDnsStreamHandle, BufStreamHandle};

/// Generic executor.
// This trait is created to facilitate running the tests defined in the tests mod using different types of
// executors. It's used in Fuchsia OS, please be mindful when update it.
#[cfg(any(test, feature = "testing"))]
pub trait Executor {
    /// Spawns a future object to run synchronously or asynchronously depending on the specific
    /// executor.
    fn block_on<F: Future>(&mut self, future: F) -> F::Output;
}

#[cfg(any(test, feature = "testing"))]
#[cfg(feature = "tokio-runtime")]
impl Executor for Runtime {
    fn block_on<F: Future>(&mut self, future: F) -> F::Output {
        self.block_on(future)
    }
}
