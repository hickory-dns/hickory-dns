// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `RetryDnsHandle` allows for DnsQueries to be reattempted on failure

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{Future, FutureExt};

use crate::error::ProtoError;
use crate::xfer::{DnsRequest, DnsResponse};
use crate::DnsHandle;

/// Can be used to reattempt a queries if they fail
///
/// *note* Current value of this is not clear, it may be removed
#[derive(Clone)]
#[must_use = "queries can only be sent through a ClientHandle"]
pub struct RetryDnsHandle<H: DnsHandle + Unpin + Send> {
    handle: H,
    attempts: usize,
}

impl<H: DnsHandle + Unpin> RetryDnsHandle<H> {
    /// Creates a new Client handler for reattempting requests on failures.
    ///
    /// # Arguments
    ///
    /// * `handle` - handle to the dns connection
    /// * `attempts` - number of attempts before failing
    pub fn new(handle: H, attempts: usize) -> Self {
        RetryDnsHandle { handle, attempts }
    }
}

impl<H> DnsHandle for RetryDnsHandle<H>
where
    H: DnsHandle + Send + Unpin + 'static,
{
    type Response = Pin<Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send + Unpin>>;

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> Self::Response {
        let request = request.into();

        // need to clone here so that the retry can resend if necessary...
        //  obviously it would be nice to be lazy about this...
        let future = self.handle.send(request.clone());

        Box::pin(RetrySendFuture {
            request,
            handle: self.handle.clone(),
            future,
            remaining_attempts: self.attempts,
        })
    }
}

/// A future for retrying (on failure, for the remaining number of times specified)
struct RetrySendFuture<H: DnsHandle> {
    request: DnsRequest,
    handle: H,
    future: <H as DnsHandle>::Response,
    remaining_attempts: usize,
}

impl<H: DnsHandle + Unpin> Future for RetrySendFuture<H> {
    type Output = Result<DnsResponse, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        // loop over the future, on errors, spawn a new future
        //  on ready and not ready return.
        loop {
            match self.future.poll_unpin(cx) {
                Poll::Ready(Err(e)) => {
                    if self.remaining_attempts == 0 {
                        return Poll::Ready(Err(e));
                    }

                    self.remaining_attempts -= 1;
                    // TODO: if the "sent" Message is part of the error result,
                    //  then we can just reuse it... and no clone necessary
                    let request = self.request.clone();
                    self.future = self.handle.send(request);
                }
                poll => return poll,
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::error::*;
    use crate::op::*;
    use futures::executor::block_on;
    use futures::future::*;
    use std::sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    };
    use DnsHandle;

    #[derive(Clone)]
    struct TestClient {
        last_succeed: bool,
        retries: u16,
        attempts: Arc<AtomicU16>,
    }

    impl DnsHandle for TestClient {
        type Response = Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send + Unpin>;

        fn send<R: Into<DnsRequest>>(&mut self, _: R) -> Self::Response {
            let i = self.attempts.load(Ordering::SeqCst);

            if (i > self.retries || self.retries - i == 0) && self.last_succeed {
                let mut message = Message::new();
                message.set_id(i);
                return Box::new(ok(message.into()));
            }

            self.attempts.fetch_add(1, Ordering::SeqCst);
            Box::new(err(ProtoError::from("last retry set to fail")))
        }
    }

    #[test]
    fn test_retry() {
        let mut handle = RetryDnsHandle::new(
            TestClient {
                last_succeed: true,
                retries: 1,
                attempts: Arc::new(AtomicU16::new(0)),
            },
            2,
        );
        let test1 = Message::new();
        let result = block_on(handle.send(test1)).expect("should have succeeded");
        assert_eq!(result.id(), 1); // this is checking the number of iterations the TestClient ran
    }

    #[test]
    fn test_error() {
        let mut client = RetryDnsHandle::new(
            TestClient {
                last_succeed: false,
                retries: 1,
                attempts: Arc::new(AtomicU16::new(0)),
            },
            2,
        );
        let test1 = Message::new();
        assert!(block_on(client.send(test1)).is_err());
    }
}
