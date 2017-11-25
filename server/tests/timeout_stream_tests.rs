extern crate futures;
extern crate tokio_core;
extern crate trust_dns_proto;
extern crate trust_dns_server;

use std::io;
use std::time::Duration;
use futures::{Async, Poll};
#[allow(deprecated)]
use futures::stream::{iter, Stream};
use tokio_core::reactor::Core;

use trust_dns_server::server::TimeoutStream;

#[test]
fn test_no_timeout() {
    #[allow(deprecated)]
    let sequence =
        iter(vec![Ok(1), Err("error"), Ok(2)]).map_err(|e| io::Error::new(io::ErrorKind::Other, e));
    let mut core = Core::new().expect("could not get core");

    let timeout_stream = TimeoutStream::new(sequence, Duration::from_secs(360), &core.handle())
        .expect("could not create timeout_stream");

    let (val, timeout_stream) = core.run(timeout_stream.into_future())
        .ok()
        .expect("first run failed");
    assert_eq!(val, Some(1));

    let error = core.run(timeout_stream.into_future());
    assert!(error.is_err());

    let (_, timeout_stream) = error.err().unwrap();

    let (val, timeout_stream) = core.run(timeout_stream.into_future())
        .ok()
        .expect("third run failed");
    assert_eq!(val, Some(2));

    let (val, _) = core.run(timeout_stream.into_future())
        .ok()
        .expect("fourth run failed");
    assert!(val.is_none())
}

struct NeverStream {}

impl Stream for NeverStream {
    type Item = ();
    type Error = io::Error;

    // somehow insert a timeout here...
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        Ok(Async::NotReady)
    }
}

#[test]
fn test_timeout() {
    let mut core = Core::new().expect("could not get core");
    let timeout_stream =
        TimeoutStream::new(NeverStream {}, Duration::from_millis(1), &core.handle())
            .expect("could not create timeout_stream");

    assert!(core.run(timeout_stream.into_future()).is_err());
}
