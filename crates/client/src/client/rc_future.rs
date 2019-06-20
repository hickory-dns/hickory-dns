// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::sync::{Arc, Mutex};

use futures::{Async, Fuse, Future, IntoFuture, Poll};

#[allow(clippy::type_complexity)]
pub struct RcFuture<F: Future>
where
    F: Future + Send,
    F::Item: Clone + Send,
{
    rc_future: Arc<Mutex<Fuse<F>>>,
    result: Arc<Mutex<Option<Poll<F::Item, F::Error>>>>,
}

pub fn rc_future<I>(future: I) -> RcFuture<I::Future>
where
    I: IntoFuture,
    <I as IntoFuture>::Item: Clone + Send,
    <I as IntoFuture>::Future: Send,
{
    let rc_future = Arc::new(Mutex::new(future.into_future().fuse()));

    RcFuture {
        rc_future,
        result: Arc::new(Mutex::new(None)),
    }
}

impl<F> Future for RcFuture<F>
where
    F: Future + Send,
    F::Item: Clone + Send,
    F::Error: Clone + Send,
{
    type Item = F::Item;
    type Error = F::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
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
        match self.rc_future.lock().expect("poisoned").poll() {
            result @ Ok(Async::NotReady) => result,
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
    F: Future + Send,
    F::Item: Clone + Send,
{
    fn clone(&self) -> Self {
        RcFuture {
            rc_future: Arc::clone(&self.rc_future),
            result: Arc::clone(&self.result),
        }
    }
}

#[cfg(test)]
use futures::{failed, finished};

#[test]
fn test_rc_future() {
    let future = finished::<usize, usize>(1_usize);

    let rc = rc_future(future);

    let i = rc.clone().wait().ok().unwrap();
    assert_eq!(i, 1);

    let i = rc.wait().ok().unwrap();
    assert_eq!(i, 1);
}

#[test]
fn test_rc_future_failed() {
    let future = failed::<usize, usize>(2);

    let rc = rc_future(future);

    let i = rc.clone().wait().err().unwrap();
    assert_eq!(i, 2);

    let i = rc.wait().err().unwrap();
    assert_eq!(i, 2);
}
