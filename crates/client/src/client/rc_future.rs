// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::sync::Arc;
use std::pin::Pin;
use std::task::Context;

use futures::{future::Fuse, Future, FutureExt, Poll};
use futures::lock::Mutex;

#[allow(clippy::type_complexity)]
pub struct RcFuture<F: Future>
where
    F: Future + Send + Unpin,
    F::Output: Clone + Send,
{
    future_and_result: Arc<Mutex<(Fuse<F>, Option<F::Output>)>>,
}

pub fn rc_future<F>(future: F) -> RcFuture<F>
where
    F: Future + Unpin,
    F::Output: Clone + Send,
    F: Send,
{
    let future_and_result = Arc::new(Mutex::new((future.fuse(), None)));

    RcFuture {
        future_and_result,
    }
}

impl<F> Future for RcFuture<F>
where
    F: Future + Send + Unpin,
    F::Output: Clone + Send,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        // try and get a mutable reference to execute the future
        // at least one caller should be able to get a mut reference... others will
        //  wait for it to complete.
        if let Some(mut future_and_result) = self.future_and_result.try_lock() {
            let (ref mut future, ref mut stored_result) = *future_and_result;
            
            // if pending it's either done, or it's actually pending
            match future.poll_unpin(cx) {
                Poll::Pending => (),
                Poll::Ready(result) => {
                    *stored_result = Some(result.clone());
                    return Poll::Ready(result);
                }
            };

            // check if someone else stored the result
            if let Some(result) = stored_result.as_ref() {
                return Poll::Ready(result.clone());
            } else {
                // the poll on the future should wake this thread
                return Poll::Pending
            }
        } else {
            // TODO: track wakers in a queue instead...
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
    }
}

impl<F> Clone for RcFuture<F>
where
    F: Future + Send + Unpin,
    F::Output: Clone + Send + Unpin,
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
    use futures::future;

    use super::*;

    #[test]
    fn test_rc_future() {
        let future = future::ok::<usize, usize>(1_usize);

        let rc = rc_future(future);

        let i = block_on(rc.clone()).ok().unwrap();
        assert_eq!(i, 1);

        let i = block_on(rc).ok().unwrap();
        assert_eq!(i, 1);
    }

    #[test]
    fn test_rc_future_failed() {
        let future = future::err::<usize, usize>(2);

        let rc = rc_future(future);

        let i = block_on(rc.clone()).err().unwrap();
        assert_eq!(i, 2);

        let i = block_on(rc).err().unwrap();
        assert_eq!(i, 2);
    }
}