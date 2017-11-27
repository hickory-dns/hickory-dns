use std::io;
use std::mem;
use std::time::Duration;

use futures::{Async, Future, Poll, Stream};
use tokio_core::reactor::{Handle, Timeout};

/// This wraps the underlying Stream in a timeout.
///
/// Any `Ok(Async::Ready(_))` from the underlying Stream will reset the timeout.
pub struct TimeoutStream<S> {
    stream: S,
    reactor_handle: Handle,
    timeout_duration: Duration,
    timeout: Option<Timeout>,
}

impl<S> TimeoutStream<S> {
    /// Returns a new TimeoutStream
    ///
    /// # Arguments
    ///
    /// * `stream` - stream to wrap
    /// * `timeout_duration` - timeout between each request, once exceed the connection is killed
    /// * `reactor_handle` - reactor used for registering new timeouts
    pub fn new(stream: S, timeout_duration: Duration, reactor_handle: &Handle) -> io::Result<Self> {
        // store a Timeout for this message before sending

        let timeout = Self::timeout(timeout_duration, reactor_handle)?;

        Ok(TimeoutStream {
            stream: stream,
            reactor_handle: reactor_handle.clone(),
            timeout_duration: timeout_duration,
            timeout: timeout,
        })
    }

    fn timeout(timeout_duration: Duration, reactor_handle: &Handle) -> io::Result<Option<Timeout>> {
        if timeout_duration > Duration::from_millis(0) {
            Ok(Some(Timeout::new(timeout_duration, reactor_handle)?))
        } else {
            Ok(None)
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
                let timeout = Self::timeout(self.timeout_duration, &self.reactor_handle)?;
                drop(mem::replace(&mut self.timeout, timeout));

                return r;
            }
            Ok(Async::NotReady) => {
                if self.timeout.is_none() {
                    return Ok(Async::NotReady);
                }

                // otherwise check if the timeout has expired.
                match try_ready!(self.timeout.as_mut().unwrap().poll()) {
                    () => {
                        debug!("timeout on stream");
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("nothing ready in {:?}", self.timeout_duration),
                        ));
                    }
                }
            }
        }
    }
}
