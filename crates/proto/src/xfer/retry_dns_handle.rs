// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `RetryDnsHandle` allows for DnsQueries to be reattempted on failure

use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::stream::{Stream, StreamExt};

use crate::error::{ProtoError, ProtoErrorKind};
use crate::xfer::{DnsRequest, DnsResponse};
use crate::DnsHandle;

/// Can be used to reattempt queries if they fail
///
/// Note: this does not reattempt queries that fail with a negative response.
/// For example, if a query gets a `NODATA` response from a name server, the
/// query will not be retried. It only reattempts queries that effectively
/// failed to get a response, such as queries that resulted in IO or timeout
/// errors.
///
/// Whether an error is retryable by the [`RetryDnsHandle`] is determined by the
/// [`RetryableError`] trait.
///
/// *note* Current value of this is not clear, it may be removed
#[derive(Clone)]
#[must_use = "queries can only be sent through a ClientHandle"]
pub struct RetryDnsHandle<H>
where
    H: DnsHandle + Unpin + Send,
    H::Error: RetryableError,
{
    handle: H,
    attempts: usize,
}

impl<H> RetryDnsHandle<H>
where
    H: DnsHandle + Unpin + Send,
    H::Error: RetryableError,
{
    /// Creates a new Client handler for reattempting requests on failures.
    ///
    /// # Arguments
    ///
    /// * `handle` - handle to the dns connection
    /// * `attempts` - number of attempts before failing
    pub fn new(handle: H, attempts: usize) -> Self {
        Self { handle, attempts }
    }
}

impl<H> DnsHandle for RetryDnsHandle<H>
where
    H: DnsHandle + Send + Unpin + 'static,
    H::Error: RetryableError,
{
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, Self::Error>> + Send + Unpin>>;
    type Error = <H as DnsHandle>::Error;

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> Self::Response {
        let request = request.into();

        // need to clone here so that the retry can resend if necessary...
        //  obviously it would be nice to be lazy about this...
        let stream = self.handle.send(request.clone());

        Box::pin(RetrySendStream {
            request,
            handle: self.handle.clone(),
            stream,
            remaining_attempts: self.attempts,
        })
    }
}

/// A stream for retrying (on failure, for the remaining number of times specified)
struct RetrySendStream<H>
where
    H: DnsHandle,
{
    request: DnsRequest,
    handle: H,
    stream: <H as DnsHandle>::Response,
    remaining_attempts: usize,
}

impl<H: DnsHandle + Unpin> Stream for RetrySendStream<H>
where
    <H as DnsHandle>::Error: RetryableError,
{
    type Item = Result<DnsResponse, <H as DnsHandle>::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // loop over the stream, on errors, spawn a new stream
        //  on ready and not ready return.
        loop {
            match self.stream.poll_next_unpin(cx) {
                Poll::Ready(Some(Err(e))) => {
                    if self.remaining_attempts == 0 || !e.should_retry() {
                        return Poll::Ready(Some(Err(e)));
                    }

                    if e.attempted() {
                        self.remaining_attempts -= 1;
                    }

                    // TODO: if the "sent" Message is part of the error result,
                    //  then we can just reuse it... and no clone necessary
                    let request = self.request.clone();
                    self.stream = self.handle.send(request);
                }
                poll => return poll,
            }
        }
    }
}

/// What errors should be retried
pub trait RetryableError {
    /// Whether the query should be retried after this error
    fn should_retry(&self) -> bool;
    /// Whether this error should count as an attempt
    fn attempted(&self) -> bool;
}

impl RetryableError for ProtoError {
    fn should_retry(&self) -> bool {
        true
    }

    fn attempted(&self) -> bool {
        !matches!(self.kind(), ProtoErrorKind::Busy)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::error::*;
    use crate::op::*;
    use crate::xfer::FirstAnswer;
    use futures_executor::block_on;
    use futures_util::future::*;
    use futures_util::stream::*;
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
        type Response = Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin>;
        type Error = ProtoError;

        fn send<R: Into<DnsRequest>>(&mut self, _: R) -> Self::Response {
            let i = self.attempts.load(Ordering::SeqCst);

            if (i > self.retries || self.retries - i == 0) && self.last_succeed {
                let mut message = Message::new();
                message.set_id(i);
                return Box::new(once(ok(message.into())));
            }

            self.attempts.fetch_add(1, Ordering::SeqCst);
            Box::new(once(err(ProtoError::from("last retry set to fail"))))
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
        let result = block_on(handle.send(test1).first_answer()).expect("should have succeeded");
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
        assert!(block_on(client.send(test1).first_answer()).is_err());
    }
}
