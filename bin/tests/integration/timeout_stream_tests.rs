use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::stream::{Stream, StreamExt, TryStreamExt, iter};
use test_support::subscribe;
use tokio::runtime::Runtime;

use hickory_server::server::TimeoutStream;

#[test]
fn test_no_timeout() {
    subscribe();

    #[allow(deprecated)]
    let sequence =
        iter(vec![Ok(1), Err("error"), Ok(2)]).map_err(|e| io::Error::new(io::ErrorKind::Other, e));
    let core = Runtime::new().expect("could not get core");

    let timeout_stream = TimeoutStream::new(sequence, Duration::from_secs(360));

    let (val, timeout_stream) = core.block_on(timeout_stream.into_future());
    assert_eq!(val.expect("nothing in stream").ok(), Some(1));

    let (error, timeout_stream) = core.block_on(timeout_stream.into_future());
    assert!(error.expect("nothing in stream").is_err());

    let (val, timeout_stream) = core.block_on(timeout_stream.into_future());
    assert_eq!(val.expect("nothing in stream").ok(), Some(2));

    let (val, _) = core.block_on(timeout_stream.into_future());
    assert!(val.is_none())
}

struct NeverStream {}

impl Stream for NeverStream {
    type Item = Result<(), io::Error>;

    // somehow insert a timeout here...
    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}

#[test]
fn test_timeout() {
    subscribe();

    let core = Runtime::new().expect("could not get core");
    let timeout_stream = TimeoutStream::new(NeverStream {}, Duration::from_millis(1));

    assert!(
        core.block_on(timeout_stream.into_future())
            .0
            .expect("nothing in stream")
            .is_err()
    );
}
