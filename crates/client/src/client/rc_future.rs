// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::lock::Mutex;
use futures_util::stream::{Fuse, Stream, StreamExt};
use futures_util::{ready, FutureExt};

// FIXME: rename to RcStream, hmmm, this probably needs a queue per cloned stream...
#[allow(clippy::type_complexity)]
#[must_use = "futures do nothing unless polled"]
pub(crate) struct RcFuture<S: Stream>
where
    S: Stream + Send + Unpin,
    S::Item: Clone + Send,
{
    // FIXME: rather than a future and restult, this should be a Stream and mpscs...
    future_and_result: Arc<Mutex<(Fuse<S>, Option<Option<S::Item>>)>>,
}

pub(crate) fn rc_future<S>(stream: S) -> RcFuture<S>
where
    S: Stream + Unpin,
    S::Item: Clone + Send,
    S: Send,
{
    let future_and_result = Arc::new(Mutex::new((stream.fuse(), None)));

    RcFuture { future_and_result }
}

impl<S> Stream for RcFuture<S>
where
    S: Stream + Send + Unpin,
    S::Item: Clone + Send,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // try and get a mutable reference to execute the future
        // at least one caller should be able to get a mut reference... others will
        //  wait for it to complete.
        let mut future_and_result = ready!(self.future_and_result.lock().poll_unpin(cx));
        let (ref mut future, ref mut stored_result) = *future_and_result;

        // if pending it's either done, or it's actually pending
        match future.poll_next_unpin(cx) {
            Poll::Pending => (),
            Poll::Ready(result) => {
                *stored_result = Some(result.clone());
                return Poll::Ready(result);
            }
        };

        // check if someone else stored the result
        if let Some(result) = stored_result.as_ref() {
            Poll::Ready(result.clone())
        } else {
            // the poll on the future should wake this thread
            Poll::Pending
        }
    }
}

impl<S> Clone for RcFuture<S>
where
    S: Stream + Send + Unpin,
    S::Item: Clone + Send + Unpin,
{
    fn clone(&self) -> Self {
        RcFuture {
            future_and_result: Arc::clone(&self.future_and_result),
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;
    use futures::{future, stream};

    use super::*;

    #[test]
    fn test_rc_future() {
        let future = stream::once(future::ok::<usize, usize>(1_usize));

        let mut rc = rc_future(future);

        let i = block_on(rc.clone().next())
            .expect("where's the once?")
            .ok()
            .unwrap();
        assert_eq!(i, 1);

        let i = block_on(rc.next())
            .expect("where's the once?")
            .ok()
            .unwrap();
        assert_eq!(i, 1);
    }

    #[test]
    fn test_rc_future_failed() {
        let future = stream::once(future::err::<usize, usize>(2));

        let mut rc = rc_future(future);

        let i = block_on(rc.clone().next())
            .expect("where's the once?")
            .err()
            .unwrap();
        assert_eq!(i, 2);

        let i = block_on(rc.next())
            .expect("where's the once?")
            .err()
            .unwrap();
        assert_eq!(i, 2);
    }
}
