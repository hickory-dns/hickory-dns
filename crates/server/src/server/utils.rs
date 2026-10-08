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

use tokio::task::JoinSet;

/// Reap finished tasks from a `JoinSet`, without awaiting or blocking.
pub(super) fn reap_tasks(join_set: &mut JoinSet<()>) {
    while join_set.try_join_next().is_some() {}
}

/// Returns `true` if an `accept()` error means the listener itself is no longer usable.
pub(super) fn is_unrecoverable_socket_error(err: &io::Error) -> bool {
    matches!(err.kind(), io::ErrorKind::NotConnected)
}

/// With no deadline configured, preserve the operation's own timeout and cancellation behavior.
#[cfg(any(feature = "__https", feature = "__quic", feature = "__h3"))]
pub(super) async fn optional_timeout<T>(
    timeout: Option<Duration>,
    future: impl Future<Output = T>,
) -> Result<T, tokio::time::error::Elapsed> {
    match timeout {
        Some(duration) => tokio::time::timeout(duration, future).await,
        None => Ok(future.await),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::task::JoinSet;

    use super::reap_tasks;

    #[test]
    fn task_reap_on_empty_joinset() {
        let mut joinset = JoinSet::new();

        // this should return immediately
        reap_tasks(&mut joinset);
    }

    #[tokio::test]
    async fn task_reap_on_nonempty_joinset() {
        let mut joinset = JoinSet::new();
        let t = joinset.spawn(tokio::time::sleep(Duration::from_secs(2)));

        // this should return immediately since no task is ready
        reap_tasks(&mut joinset);
        t.abort();

        // this should also return immediately since the task has been aborted
        reap_tasks(&mut joinset);
    }
}
