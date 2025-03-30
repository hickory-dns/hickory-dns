use std::io;
use std::mem;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::FutureExt;
use futures_util::stream::{Stream, StreamExt};
use tokio::time::Sleep;
use tracing::{debug, warn};

/// This wraps the underlying Stream in a timeout.
///
/// Any `Ok(Poll::Ready(_))` from the underlying Stream will reset the timeout.
pub struct TimeoutStream<S> {
    stream: S,
    timeout_duration: Duration,
    timeout: Option<Pin<Box<Sleep>>>,
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
        Self {
            stream,
            timeout_duration,
            timeout: None,
        }
    }

    fn timeout(timeout_duration: Duration) -> Option<Pin<Box<Sleep>>> {
        if timeout_duration > Duration::from_millis(0) {
            Some(Box::pin(tokio::time::sleep(timeout_duration)))
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
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // if the timer isn't set, set one now
        if self.timeout.is_none() {
            let timeout = Self::timeout(self.timeout_duration);
            self.as_mut().timeout = timeout;
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
                if let Some(timeout) = &mut self.timeout {
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

#[cfg(test)]
mod tests {
    use futures_util::stream::{TryStreamExt, iter};
    use test_support::subscribe;
    use tokio::runtime::Runtime;

    use super::*;

    #[test]
    fn test_no_timeout() {
        subscribe();

        #[allow(deprecated)]
        let sequence = iter(vec![Ok(1), Err("error"), Ok(2)])
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e));
        let core = Runtime::new().expect("could not get core");

        let timeout_stream = TimeoutStream::new(sequence, Duration::from_secs(360));

        let (val, timeout_stream) = core.block_on(timeout_stream.into_future());
        assert_eq!(val.expect("nothing in stream").ok(), Some(1));

        let (error, timeout_stream) = core.block_on(timeout_stream.into_future());
        assert!(error.expect("nothing in stream").is_err());

        let (val, timeout_stream) = core.block_on(timeout_stream.into_future());
        assert_eq!(val.expect("nothing in stream").ok(), Some(2));

        let (val, _) = core.block_on(timeout_stream.into_future());
        assert!(val.is_none())
    }

    struct NeverStream {}

    impl Stream for NeverStream {
        type Item = Result<(), io::Error>;

        // somehow insert a timeout here...
        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    #[test]
    fn test_timeout() {
        subscribe();

        let core = Runtime::new().expect("could not get core");
        let timeout_stream = TimeoutStream::new(NeverStream {}, Duration::from_millis(1));

        assert!(
            core.block_on(timeout_stream.into_future())
                .0
                .expect("nothing in stream")
                .is_err()
        );
    }
}
