use std::io;
use std::mem;
use std::time::{Duration, Instant};

use futures::{Async, Future, Poll, Stream};
use tokio_timer::Delay;

/// This wraps the underlying Stream in a timeout.
///
/// Any `Ok(Async::Ready(_))` from the underlying Stream will reset the timeout.
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
        // store a Timeout for this message before sending
        let timeout = Self::timeout(timeout_duration);

        TimeoutStream {
            stream: stream,
            timeout_duration: timeout_duration,
            timeout: timeout,
        }
    }

    fn timeout(timeout_duration: Duration) -> Option<Delay> {
        if timeout_duration > Duration::from_millis(0) {
            Some(Delay::new(Instant::now() + timeout_duration))
        } else {
            None
        }
    }
}

impl<S, I> Stream for TimeoutStream<S>
where
    S: Stream<Item = I, Error = io::Error>,
{
    type Item = I;
    type Error = io::Error;

    // somehow insert a timeout here...
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.stream.poll() {
            r @ Ok(Async::Ready(_)) | r @ Err(_) => {
                // reset the timeout to wait for the next request...
                let mut timeout = Self::timeout(self.timeout_duration);

                // ensure that interest in the Timeout is registered
                match timeout.poll() {
                    Ok(Async::Ready(_)) => {
                        warn!("timeout fired immediately!");
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("timeout fired immediately!"),
                        ));
                    }
                    Err(e) => {
                        error!("could not register interest in Timeout: {}", e);
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("could not register interest in Timeout: {}", e),
                        ));
                    }
                    Ok(Async::NotReady) => (), // this is the exepcted state...
                }

                drop(mem::replace(&mut self.timeout, timeout));

                r
            }
            Ok(Async::NotReady) => {
                if let Some(ref mut timeout) = self.timeout {
                    match timeout.poll() {
                        Ok(Async::NotReady) => return Ok(Async::NotReady),
                        Ok(Async::Ready(())) => {
                            debug!("timeout on stream");
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                format!("nothing ready in {:?}", self.timeout_duration),
                            ));
                        }
                        Err(_) => {
                            return Err(io::Error::new(io::ErrorKind::Other, "timer internal error"));
                        }
                    }
                } else {
                    return Ok(Async::NotReady);
                }
            }
        }
    }
}
