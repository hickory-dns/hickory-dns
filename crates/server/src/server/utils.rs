// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Helpers shared by the server request pipeline and the transports.

use std::io;
#[cfg(any(feature = "__https", feature = "__quic", feature = "__h3"))]
use std::{future::Future, time::Duration};

/// Returns `true` if an `accept()` error means the listener itself is no longer usable.
pub(super) fn is_unrecoverable_socket_error(err: &io::Error) -> bool {
    matches!(err.kind(), io::ErrorKind::NotConnected)
}

/// With no deadline configured, preserve the operation's own timeout and cancellation behavior.
#[cfg(any(feature = "__https", feature = "__quic", feature = "__h3"))]
pub(super) async fn timeout<T>(
    timeout: Option<Duration>,
    future: impl Future<Output = T>,
) -> Result<T, tokio::time::error::Elapsed> {
    match timeout {
        Some(duration) => tokio::time::timeout(duration, future).await,
        None => Ok(future.await),
    }
}
