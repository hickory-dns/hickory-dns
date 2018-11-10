// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `RetryDnsHandle` allows for DnsQueries to be reattempted on failure

use futures::{Future, Poll};

use error::ProtoError;
use xfer::{DnsRequest, DnsResponse};
use DnsHandle;

/// Can be used to reattempt a queries if they fail
///
/// *note* Current value of this is not clear, it may be removed
#[derive(Clone)]
#[must_use = "queries can only be sent through a ClientHandle"]
pub struct RetryDnsHandle<H: DnsHandle> {
    handle: H,
    attempts: usize,
}

impl<H: DnsHandle> RetryDnsHandle<H> {
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
    H: DnsHandle + 'static,
{
    type Response = Box<Future<Item = DnsResponse, Error = ProtoError> + Send>;

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> Self::Response {
        let request = request.into();

        // need to clone here so that the retry can resend if necessary...
        //  obviously it would be nice to be lazy about this...
        let future = self.handle.send(request.clone());

        Box::new(RetrySendFuture {
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

impl<H: DnsHandle> Future for RetrySendFuture<H> {
    type Item = DnsResponse;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // loop over the future, on errors, spawn a new future
        //  on ready and not ready return.
        loop {
            match self.future.poll() {
                r @ Ok(_) => return r,
                Err(e) => {
                    if self.remaining_attempts == 0 {
                        return Err(e);
                    }

                    self.remaining_attempts -= 1;
                    // FIXME: if the "sent" Message is part of the error result,
                    //  then we can just reuse it... and no clone necessary
                    self.future = self.handle.send(self.request.clone());
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use error::*;
    use futures::*;
    use op::*;
    use std::cell::Cell;
    use DnsHandle;

    #[derive(Clone)]
    struct TestClient {
        last_succeed: bool,
        retries: u16,
        attempts: Cell<u16>,
    }

    impl DnsHandle for TestClient {
        type Response = Box<Future<Item = DnsResponse, Error = ProtoError> + Send>;

        fn send<R: Into<DnsRequest>>(&mut self, _: R) -> Self::Response {
            let i = self.attempts.get();

            if (i > self.retries || self.retries - i == 0) && self.last_succeed {
                let mut message = Message::new();
                message.set_id(i);
                return Box::new(finished(message.into()));
            }

            self.attempts.set(i + 1);
            Box::new(failed(ProtoError::from("last retry set to fail")))
        }
    }

    #[test]
    fn test_retry() {
        let mut handle = RetryDnsHandle::new(
            TestClient {
                last_succeed: true,
                retries: 1,
                attempts: Cell::new(0),
            },
            2,
        );
        let test1 = Message::new();
        let result = handle.send(test1).wait().expect("should have succeeded");
        assert_eq!(result.id(), 1); // this is checking the number of iterations the TestCient ran
    }

    #[test]
    fn test_error() {
        let mut client = RetryDnsHandle::new(
            TestClient {
                last_succeed: false,
                retries: 1,
                attempts: Cell::new(0),
            },
            2,
        );
        let test1 = Message::new();
        assert!(client.send(test1).wait().is_err());
    }
}
