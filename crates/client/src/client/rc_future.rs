// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::sync::{Arc, Mutex};
use std::pin::Pin;
use std::task::Context;

use futures::{future::Fuse, Future, FutureExt, Poll};

#[allow(clippy::type_complexity)]
pub struct RcFuture<F: Future>
where
    F: Future + Send + Unpin,
    F::Output: Clone + Send,
{
    rc_future: Arc<Mutex<Fuse<F>>>,
    result: Arc<Mutex<Option<Poll<F::Output>>>>,
}

pub fn rc_future<F>(future: F) -> RcFuture<F>
where
    F: Future + Unpin,
    F::Output: Clone + Send,
    F: Send,
{
    let rc_future = Arc::new(Mutex::new(future.fuse()));

    RcFuture {
        rc_future,
        result: Arc::new(Mutex::new(None)),
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
        if self.result.lock().expect("poisoned").is_some() {
            return self
                .result
                .lock()
                .expect("poisoned")
                .as_ref()
                .unwrap()
                .clone();
        }

        // TODO convert this to try_borrow_mut when that stabilizes...
        match self.rc_future.lock().expect("poisoned").poll_unpin(cx) {
            result @ Poll::Pending => result,
            result => {
                let mut store = self.result.lock().expect("poisoned");
                *store = Some(result.clone());
                result
            }
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
            rc_future: Arc::clone(&self.rc_future),
            result: Arc::clone(&self.result),
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