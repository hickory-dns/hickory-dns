// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Arc;

use futures_util::lock::Mutex;
use futures_util::stream::{Fuse, Stream, StreamExt};
use futures_util::{FutureExt, ready};

#[allow(clippy::type_complexity)]
#[must_use = "stream do nothing unless polled"]
pub(crate) struct RcStream<S: Stream>
where
    S: Stream + Send + Unpin,
    S::Item: Clone + Send,
{
    stream_and_result: Arc<Mutex<(Fuse<S>, Vec<S::Item>)>>,
    pos: usize,
}

pub(crate) fn rc_stream<S>(stream: S) -> RcStream<S>
where
    S: Stream + Unpin + Send,
    S::Item: Clone + Send,
{
    let stream_and_result = Arc::new(Mutex::new((stream.fuse(), vec![])));

    RcStream {
        stream_and_result,
        pos: 0,
    }
}

impl<S> Stream for RcStream<S>
where
    S: Stream + Send + Unpin,
    S::Item: Clone + Send,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // try and get a mutable reference to execute the future
        // at least one caller should be able to get a mut reference... others will
        //  wait for it to complete.
        let mut stream_and_result = ready!(self.stream_and_result.lock().poll_unpin(cx));
        let (stream, stored_result) = &mut *stream_and_result;
        if stored_result.len() > self.pos {
            let result = stored_result[self.pos].clone();
            drop(stream_and_result);
            self.pos += 1;
            return Poll::Ready(Some(result));
        }

        // if pending it's either done, or it's actually pending
        match stream.poll_next_unpin(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                if let Some(result) = &result {
                    stored_result.push(result.clone());
                }
                Poll::Ready(result)
            }
        }
    }
}

impl<S> Clone for RcStream<S>
where
    S: Stream + Send + Unpin,
    S::Item: Clone + Send + Unpin,
{
    fn clone(&self) -> Self {
        Self {
            stream_and_result: Arc::clone(&self.stream_and_result),
            pos: 0, // index is not kept to allow to read first messages
        }
    }
}

#[cfg(test)]
mod tests {
    use futures_executor::block_on;
    use futures_util::future;
    use futures_util::stream::once;

    use super::*;
    use crate::NetError;
    use crate::xfer::FirstAnswer;

    #[test]
    fn test_rc_stream() {
        let future = future::ok::<usize, NetError>(1_usize);

        let rc = rc_stream(once(future));

        let i = block_on(rc.clone().first_answer()).unwrap();
        assert_eq!(i, 1);

        let i = block_on(rc.first_answer()).unwrap();
        assert_eq!(i, 1);
    }

    #[test]
    fn test_rc_stream_failed() {
        let future = future::err::<usize, NetError>(NetError::Busy);

        let rc = rc_stream(once(future));

        let i = block_on(rc.clone().first_answer()).unwrap_err();
        assert!(matches!(i, NetError::Busy));

        let i = block_on(rc.first_answer()).unwrap_err();
        assert!(matches!(i, NetError::Busy));
    }
}
