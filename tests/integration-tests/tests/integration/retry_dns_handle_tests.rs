use std::sync::{
    Arc,
    atomic::{AtomicU16, Ordering},
};

use futures::{Future, executor::block_on, future};

use hickory_net::{DnsError, DnsHandle, NetError, RetryDnsHandle, runtime::TokioRuntimeProvider};
use hickory_proto::op::{DnsRequest, DnsResponse, Message, OpCode, ResponseCode};
use test_support::subscribe;

#[derive(Clone)]
struct TestClient {
    retries: u16,
    error_response: NetError,
    attempts: Arc<AtomicU16>,
}

impl DnsHandle for TestClient {
    type Runtime = TokioRuntimeProvider;

    fn send(&self, _: DnsRequest) -> impl Future<Output = Result<DnsResponse, NetError>> + Send {
        let i = self.attempts.load(Ordering::SeqCst);

        if i > self.retries || self.retries - i == 0 {
            return future::ok(
                DnsResponse::from_message(Message::response(i, OpCode::Query)).unwrap(),
            );
        }

        self.attempts.fetch_add(1, Ordering::SeqCst);
        future::err(self.error_response.clone())
    }
}

// The RetryDnsHandle should retry the same nameserver on IO errors, e.g. timeouts.
#[test]
fn retry_on_retryable_error() {
    subscribe();
    let handle = RetryDnsHandle::new(
        TestClient {
            retries: 1,
            error_response: NetError::from(std::io::Error::from(std::io::ErrorKind::TimedOut)),
            attempts: Arc::new(AtomicU16::new(0)),
        },
        2,
    );
    let test1 = DnsRequest::from(Message::query());
    let result = block_on(handle.send(test1)).expect("should have succeeded");
    assert_eq!(result.metadata.id, 1); // this is checking the number of iterations the TestClient ran
}

// The RetryDnsHandle should not retry the same name server(s) on a negative response, such as
// `NODATA`.
#[test]
fn dont_retry_on_negative_response() {
    subscribe();
    let mut response = Message::response(10, OpCode::Update);
    response.metadata.response_code = ResponseCode::NoError;
    let error = DnsError::from_response(DnsResponse::from_message(response).unwrap())
        .expect_err("NODATA should be an error");
    let client = RetryDnsHandle::new(
        TestClient {
            retries: 1,
            error_response: error.into(),
            attempts: Arc::new(AtomicU16::new(0)),
        },
        2,
    );
    let test1 = DnsRequest::from(Message::query());
    assert!(block_on(client.send(test1)).is_err());
}
