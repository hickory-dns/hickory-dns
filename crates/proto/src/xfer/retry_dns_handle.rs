// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `RetryDnsHandle` allows for DnsQueries to be reattempted on failure

use alloc::boxed::Box;
use core::pin::Pin;
use core::task::{Context, Poll};

use futures_util::stream::{Stream, StreamExt};

use crate::error::ProtoError;
use crate::xfer::{DnsHandle, DnsRequest, DnsResponse};
use crate::{DnsError, ProtoErrorKind};

/// Can be used to reattempt queries if they fail
///
/// Note: this does not reattempt queries that fail with a negative response.
/// For example, if a query gets a `NODATA` response from a name server, the
/// query will not be retried. It only reattempts queries that effectively
/// failed to get a response, such as queries that resulted in IO or timeout
/// errors.
///
/// *note* Current value of this is not clear, it may be removed
#[derive(Clone)]
#[must_use = "queries can only be sent through a ClientHandle"]
#[allow(dead_code)]
pub struct RetryDnsHandle<H> {
    handle: H,
    attempts: usize,
}

impl<H> RetryDnsHandle<H> {
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

impl<H: DnsHandle> DnsHandle for RetryDnsHandle<H> {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin>>;
    type Runtime = H::Runtime;

    fn send(&self, request: DnsRequest) -> Self::Response {
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
struct RetrySendStream<H: DnsHandle> {
    request: DnsRequest,
    handle: H,
    stream: <H as DnsHandle>::Response,
    remaining_attempts: usize,
}

impl<H: DnsHandle> Stream for RetrySendStream<H> {
    type Item = Result<DnsResponse, ProtoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // loop over the stream, on errors, spawn a new stream
        //  on ready and not ready return.
        loop {
            let err = match self.stream.poll_next_unpin(cx) {
                Poll::Ready(Some(Err(e))) => e,
                poll => return poll,
            };

            use ProtoErrorKind::*;
            match (self.remaining_attempts, err) {
                // No attempts left, return the error
                (0, err) => return Poll::Ready(Some(Err(err))),
                // Don't retry some kinds of errors
                (
                    _,
                    err @ ProtoError {
                        kind: NoConnections | Dns(DnsError::NoRecordsFound { .. }),
                        ..
                    },
                ) => return Poll::Ready(Some(Err(err))),
                // Don't count `Busy` as an attempt
                (_, ProtoError { kind: Busy, .. }) => {}
                // Try again and count this as one attempt
                (_, _) => self.remaining_attempts -= 1,
            }

            // TODO: if the "sent" Message is part of the error result,
            //  then we can just reuse it... and no clone necessary
            let request = self.request.clone();
            self.stream = self.handle.send(request);
        }
    }
}

#[cfg(all(test, feature = "tokio"))]
mod test {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU16, Ordering};

    use futures_executor::block_on;
    use futures_util::future::{err, ok};
    use futures_util::stream::{Stream, once};

    use super::*;
    use crate::error::ProtoError;
    use crate::op::Message;
    use crate::runtime::TokioRuntimeProvider;
    use crate::xfer::{DnsHandle, DnsRequest, DnsResponse, FirstAnswer};
    use test_support::subscribe;

    #[derive(Clone)]
    struct TestClient {
        last_succeed: bool,
        retries: u16,
        attempts: Arc<AtomicU16>,
    }

    impl DnsHandle for TestClient {
        type Response = Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin>;
        type Runtime = TokioRuntimeProvider;

        fn send(&self, _: DnsRequest) -> Self::Response {
            let i = self.attempts.load(Ordering::SeqCst);

            if (i > self.retries || self.retries - i == 0) && self.last_succeed {
                let mut message = Message::query();
                message.set_id(i);
                return Box::new(once(ok(DnsResponse::from_message(message).unwrap())));
            }

            self.attempts.fetch_add(1, Ordering::SeqCst);
            Box::new(once(err(ProtoError::from("last retry set to fail"))))
        }
    }

    #[test]
    fn test_retry() {
        subscribe();
        let handle = RetryDnsHandle::new(
            TestClient {
                last_succeed: true,
                retries: 1,
                attempts: Arc::new(AtomicU16::new(0)),
            },
            2,
        );
        let test1 = DnsRequest::from(Message::query());
        let result = block_on(handle.send(test1).first_answer()).expect("should have succeeded");
        assert_eq!(result.id(), 1); // this is checking the number of iterations the TestClient ran
    }

    #[test]
    fn test_error() {
        subscribe();
        let client = RetryDnsHandle::new(
            TestClient {
                last_succeed: false,
                retries: 1,
                attempts: Arc::new(AtomicU16::new(0)),
            },
            2,
        );
        let test1 = DnsRequest::from(Message::query());
        assert!(block_on(client.send(test1).first_answer()).is_err());
    }
}
