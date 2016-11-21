use std::io;
use std::mem;
use std::time::Duration;

use futures::{Async, Future, Poll};
use futures::stream::Stream;
use tokio_core::reactor::{Handle, Timeout};

/// This wraps the underlying Stream in a timeout.
///
/// Any `Ok(Async::Ready(_))` from the underlying Stream will reset the timeout.
pub struct TimeoutStream<S> {
  stream: S,
  reactor_handle: Handle,
  timeout_duration: Duration,
  timeout: Timeout,
}

impl<S> TimeoutStream<S> {
  pub fn new(stream: S, timeout_duration: Duration, reactor_handle: Handle) -> io::Result<Self> {
    // store a Timeout for this message before sending
    let timeout = try!(Timeout::new(timeout_duration, &reactor_handle));
    Ok(TimeoutStream{ stream: stream, reactor_handle: reactor_handle, timeout_duration: timeout_duration, timeout: timeout })
  }
}

impl<S, I> Stream for TimeoutStream<S>
where S: Stream<Item=I, Error=io::Error> {
  type Item = I;
  type Error = io::Error;

  // somehow insert a timeout here...
  fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
    match self.stream.poll() {
      r @ Ok(Async::Ready(_)) | r @ Err(_) => {
        // reset the timeout to wait for the next request...
        let timeout = try!(Timeout::new(self.timeout_duration, &self.reactor_handle));
        drop(mem::replace(&mut self.timeout, timeout));

        return r
      },
      Ok(Async::NotReady) => {
        // otherwise poll the timeout
        match try_ready!(self.timeout.poll()) {
          () => return Err(io::Error::new(io::ErrorKind::TimedOut, format!("nothing ready in {:?}", self.timeout_duration))),
        }
      }
    }
  }
}
