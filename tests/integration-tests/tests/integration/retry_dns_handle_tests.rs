use std::sync::{
    Arc,
    atomic::{AtomicU16, Ordering},
};

use futures::{Stream, executor::block_on, future, stream};

use hickory_proto::{
    DnsHandle, ProtoError, RetryDnsHandle,
    op::{Message, MessageType, OpCode, ResponseCode},
    xfer::{DnsRequest, DnsResponse, FirstAnswer},
};
use test_support::subscribe;

#[derive(Clone)]
struct TestClient {
    retries: u16,
    error_response: ProtoError,
    attempts: Arc<AtomicU16>,
}

impl DnsHandle for TestClient {
    type Response = Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin>;

    fn send<R: Into<DnsRequest>>(&self, _: R) -> Self::Response {
        let i = self.attempts.load(Ordering::SeqCst);

        if i > self.retries || self.retries - i == 0 {
            let mut message = Message::new();
            message.set_id(i);
            return Box::new(stream::once(future::ok(
                DnsResponse::from_message(message).unwrap(),
            )));
        }

        self.attempts.fetch_add(1, Ordering::SeqCst);
        Box::new(stream::once(future::err(self.error_response.clone())))
    }
}

// The RetryDnsHandle should retry the same nameserver on IO errors, e.g. timeouts.
#[test]
fn retry_on_retryable_error() {
    subscribe();
    let handle = RetryDnsHandle::new(
        TestClient {
            retries: 1,
            error_response: ProtoError::from(std::io::Error::from(std::io::ErrorKind::TimedOut)),
            attempts: Arc::new(AtomicU16::new(0)),
        },
        2,
    );
    let test1 = Message::new();
    let result = block_on(handle.send(test1).first_answer()).expect("should have succeeded");
    assert_eq!(result.id(), 1); // this is checking the number of iterations the TestClient ran
}

// The RetryDnsHandle should not retry the same name server(s) on a negative response, such as
// `NODATA`.
#[test]
fn dont_retry_on_negative_response() {
    subscribe();
    let mut response = Message::new();
    response
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Update)
        .set_response_code(ResponseCode::NoError);
    let error = ProtoError::from_response(DnsResponse::from_message(response).unwrap(), false)
        .expect_err("NODATA should be an error");
    let client = RetryDnsHandle::new(
        TestClient {
            retries: 1,
            error_response: error,
            attempts: Arc::new(AtomicU16::new(0)),
        },
        2,
    );
    let test1 = Message::new();
    assert!(block_on(client.send(test1).first_answer()).is_err());
}
