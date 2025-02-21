// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

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
        let (ref mut stream, ref mut stored_result) = *stream_and_result;
        if stored_result.len() > self.pos {
            let result = stored_result[self.pos].clone();
            drop(stream_and_result); // release lock early to please borrow checker
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
    use futures::executor::block_on;
    use futures::future;
    use futures_util::stream::once;

    use crate::proto::xfer::FirstAnswer;
    use crate::proto::{ProtoError, ProtoErrorKind};

    use super::*;

    #[test]
    fn test_rc_stream() {
        let future = future::ok::<usize, ProtoError>(1_usize);

        let rc = rc_stream(once(future));

        let i = block_on(rc.clone().first_answer()).ok().unwrap();
        assert_eq!(i, 1);

        let i = block_on(rc.first_answer()).ok().unwrap();
        assert_eq!(i, 1);
    }

    #[test]
    fn test_rc_stream_failed() {
        let future = future::err::<usize, ProtoError>(ProtoError::from(ProtoErrorKind::Busy));

        let rc = rc_stream(once(future));

        let i = block_on(rc.clone().first_answer()).err().unwrap();
        assert!(matches!(i.kind(), ProtoErrorKind::Busy));

        let i = block_on(rc.first_answer()).err().unwrap();
        assert!(matches!(i.kind(), ProtoErrorKind::Busy));
    }
}
