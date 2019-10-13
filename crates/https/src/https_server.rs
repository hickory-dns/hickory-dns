// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! HTTPS related server items

use std::borrow::Borrow;
use std::fmt::Debug;
use std::sync::Arc;
use std::pin::Pin;
use std::task::Context;

use bytes::Bytes;
use futures::{Future, FutureExt, Poll, Stream, StreamExt};
use h2;
use http::{Method, Request};
use typed_headers::{ContentLength, HeaderMapExt};

use crate::HttpsError;

/// Given an HTTP request, return a future that will result in the next sequence of bytes.
///
/// To allow downstream clients to do something interesting with the lifetime of the bytes, this doesn't
///   perform a conversion to a Message, only collects all the bytes.
pub async fn message_from<R>(this_server_name: Arc<String>, request: Request<R>) -> Result<Bytes, HttpsError>
where
    R: Stream<Item = Result<Bytes, h2::Error>> + 'static + Send + Debug + Unpin,
{
    debug!("Received request: {:#?}", request);

    let this_server_name: &String = this_server_name.borrow();
    match crate::request::verify(this_server_name, &request) {
        Ok(_) => (),
        Err(err) => return Err(err),
    }

    // attempt to get the content length
    let content_length: Option<ContentLength> = match request.headers().typed_get() {
        Ok(l) => l,
        Err(err) => return Err(err.into()),
    };

    let content_length: Option<usize> = content_length.map(|c| {
        let length = *c as usize;
        debug!("got message length: {}", length);
        length
    });

    match *request.method() {
        Method::GET => Err(format!("GET unimplemented: {}", request.method()).into()),
        Method::POST => message_from_post(request.into_body(), content_length).await,
        _ => Err(format!("bad method: {}", request.method()).into()),
    }
}

/// Deserialize the message from a POST message
pub(crate) async fn message_from_post<R>(mut request_stream: R, length: Option<usize>) -> Result<Bytes, HttpsError>
where
    R: Stream<Item = Result<Bytes, h2::Error>> + 'static + Send + Debug + Unpin,
{

    let mut bytes = Bytes::with_capacity(length.unwrap_or(0).min(512).max(4096));

    loop {
        match request_stream.next().await {
            Some(Ok(frame)) => bytes.extend_from_slice(&frame.slice_from(0)),
            Some(Err(err)) => return Err(err.into()),
            None => {
                return if let Some(length) = length {
                    // wait until we have all the bytes
                    if bytes.len() == length {
                        Ok(bytes)
                    } else {
                        Err("not all bytes received".into())
                    }
                } else {
                    Ok(bytes)
                };
            }
        };

        if let Some(length) = length {
            // wait until we have all the bytes
            if bytes.len() == length {
                return Ok(bytes);
            }
        }
    }
}

#[must_use = "futures do nothing unless polled"]
struct MessageFromPost<R> {
    stream: R,
    length: Option<usize>,
}

impl<R> Future for MessageFromPost<R>
where
    R: Stream<Item = Result<Bytes, h2::Error>> + 'static + Send + Unpin,
{
    type Output = Result<Bytes, HttpsError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            let bytes = match self.stream.next().poll_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(bytes))) => bytes,
                Poll::Ready(None) => return Poll::Ready(Err("not all bytes received".into())),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e.into())),
            };

            let bytes = if let Some(length) = self.length {
                // wait until we have all the bytes
                if bytes.len() < length {
                    continue;
                }

                // this will trim the bytes back to whatever we didn't consume
                bytes.slice_to(length)
            } else {
                warn!("no content-length, assuming we have all the bytes");
                bytes.slice_from(0)
            };

            //let message = Message::from_vec(&bytes)?;
            return Poll::Ready(Ok(bytes));
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;
    use trust_dns_proto::op::Message;

    use crate::request;

    use super::*;

    #[derive(Debug)]
    struct TestBytesStream(Vec<Result<Bytes, h2::Error>>);

    impl Stream for TestBytesStream {
        type Item = Result<Bytes, h2::Error>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Option<Self::Item>> {
            match self.0.pop() {
                Some(Ok(bytes)) => Poll::Ready(Some(Ok(bytes))),
                Some(Err(err)) => Poll::Ready(Some(Err(err))),
                None => Poll::Ready(None),
            }
        }
    }

    #[test]
    fn test_from_post() {
        let message = Message::new();
        let msg_bytes = message.to_vec().unwrap();
        let len = msg_bytes.len();
        let stream = TestBytesStream(vec![Ok(Bytes::from(msg_bytes))]);
        let request = request::new("ns.example.com", len).unwrap();
        let request = request.map(|()| stream);

        // FIXME: generic stream impl is issue...

 
        let from_post = message_from(Arc::new("ns.example.com".to_string()), request);
        let bytes = match block_on(from_post) {
            Ok(bytes) => bytes,
            e => panic!("{:#?}", e),
        };

        let msg_from_post = Message::from_vec(bytes.as_ref()).expect("bytes failed");
        assert_eq!(message, msg_from_post);
    }
}
