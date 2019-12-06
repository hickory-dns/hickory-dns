use std::io;
use std::mem;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::{FutureExt, Stream, StreamExt};
use tokio::time::Delay;

/// This wraps the underlying Stream in a timeout.
///
/// Any `Ok(Poll::Ready(_))` from the underlying Stream will reset the timeout.
pub struct TimeoutStream<S> {
    stream: S,
    timeout_duration: Duration,
    timeout: Option<Delay>,
}

impl<S> TimeoutStream<S> {
    /// Returns a new TimeoutStream
    ///
    /// # Arguments
    ///
    /// * `stream` - stream to wrap
    /// * `timeout_duration` - timeout between each request, once exceed the connection is killed
    /// * `reactor_handle` - reactor used for registering new timeouts
    pub fn new(stream: S, timeout_duration: Duration) -> Self {
        TimeoutStream {
            stream,
            timeout_duration,
            timeout: None,
        }
    }

    fn timeout(timeout_duration: Duration) -> Option<Delay> {
        if timeout_duration > Duration::from_millis(0) {
            Some(tokio::time::delay_for(timeout_duration))
        } else {
            None
        }
    }
}

impl<S, I> Stream for TimeoutStream<S>
where
    S: Stream<Item = Result<I, io::Error>> + Unpin,
{
    type Item = Result<I, io::Error>;

    // somehow insert a timeout here...
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        // if the timer isn't set, set one now
        if self.timeout.is_none() {
            let timeout = Self::timeout(self.timeout_duration);
            mem::replace(&mut self.timeout, timeout);
        }

        match self.stream.poll_next_unpin(cx) {
            r @ Poll::Ready(_) => {
                // reset the timeout to wait for the next request...
                let timeout = if let Some(mut timeout) = Self::timeout(self.timeout_duration) {
                    // ensure that interest in the Timeout is registered
                    match timeout.poll_unpin(cx) {
                        Poll::Ready(_) => {
                            warn!("timeout fired immediately!");
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "timeout fired immediately!",
                            ))));
                        }
                        Poll::Pending => (), // this is the expected state...
                    }

                    Some(timeout)
                } else {
                    None
                };

                drop(mem::replace(&mut self.timeout, timeout));

                r
            }
            Poll::Pending => {
                if let Some(ref mut timeout) = self.timeout {
                    match timeout.poll_unpin(cx) {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(()) => {
                            debug!("timeout on stream");
                            Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                format!("nothing ready in {:?}", self.timeout_duration),
                            ))))
                        }
                    }
                } else {
                    Poll::Pending
                }
            }
        }
    }
}
