// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use futures::{Future, Poll};

use error::FromProtoError;
use DnsHandle;
use op::Message;

/// Can be used to reattempt a queries if they fail
///
/// *note* Current value of this is not clear, it may be removed
#[derive(Clone)]
#[must_use = "queries can only be sent through a ClientHandle"]
pub struct RetryDnsHandle<H: DnsHandle<Error = E>, E = <H as DnsHandle>::Error>
where
    E: FromProtoError + 'static,
{
    handle: H,
    attempts: usize,
}

impl<H, E> RetryDnsHandle<H, E>
where
    H: DnsHandle<Error = E>,
    E: FromProtoError + 'static,
{
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

impl<H, E> DnsHandle for RetryDnsHandle<H>
where
    H: DnsHandle<Error = E> + 'static,
    E: FromProtoError + 'static,
{
    type Error = <H as DnsHandle>::Error;

    fn send(&mut self, message: Message) -> Box<Future<Item = Message, Error = Self::Error>> {
        // need to clone here so that the retry can resend if necessary...
        //  obviously it would be nice to be lazy about this...
        let future = self.handle.send(message.clone());

        Box::new(RetrySendFuture {
            message: message,
            handle: self.handle.clone(),
            future: future,
            remaining_attempts: self.attempts,
        })
    }
}

/// A future for retrying (on failure, for the remaining number of times specified)
struct RetrySendFuture<H: DnsHandle, E> {
    message: Message,
    handle: H,
    future: Box<Future<Item = Message, Error = E>>,
    remaining_attempts: usize,
}

impl<H, E> Future for RetrySendFuture<H, E>
where
    H: DnsHandle<Error = E>,
    E: FromProtoError,
{
    type Item = Message;
    type Error = <H as DnsHandle>::Error;

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
                    // TODO: if the "sent" Message is part of the error result,
                    //  then we can just reuse it... and no clone necessary
                    self.future = self.handle.send(self.message.clone());
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::cell::Cell;
    use error::*;
    use op::*;
    use futures::*;
    use DnsHandle;
    use super::*;

    #[derive(Clone)]
    struct TestClient {
        last_succeed: bool,
        retries: u16,
        attempts: Cell<u16>,
    }

    impl DnsHandle for TestClient {
        type Error = ProtoError;

        fn send(&mut self, _: Message) -> Box<Future<Item = Message, Error = Self::Error>> {
            let i = self.attempts.get();

            if i > self.retries || self.retries - i == 0 {
                if self.last_succeed {
                    let mut message = Message::new();
                    message.set_id(i);
                    return Box::new(finished(message));
                }
            }

            self.attempts.set(i + 1);
            return Box::new(failed(
                ProtoErrorKind::Message("last retry set to fail").into(),
            ));
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
        let result = handle
            .send(test1)
            .wait()
            .ok()
            .expect("should have succeeded");
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
