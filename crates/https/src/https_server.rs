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
pub fn message_from<R>(this_server_name: Arc<String>, request: Request<R>) -> HttpsToMessage<R>
where
    R: Stream<Item = Result<Bytes, h2::Error>> + 'static + Send + Debug,
{
    debug!("Received request: {:#?}", request);

    let this_server_name: &String = this_server_name.borrow();
    match crate::request::verify(this_server_name, &request) {
        Ok(_) => (),
        Err(err) => return HttpsToMessageInner::HttpsError(Some(err)).into(),
    }

    // attempt to get the content length
    let content_length: Option<ContentLength> = match request.headers().typed_get() {
        Ok(l) => l,
        Err(err) => return HttpsToMessageInner::HttpsError(Some(err.into())).into(),
    };

    let content_length: Option<usize> = content_length.map(|c| {
        let length = *c as usize;
        debug!("got message length: {}", length);
        length
    });

    match *request.method() {
        Method::GET => HttpsToMessageInner::HttpsError(Some(
            format!("GET unimplemented: {}", request.method()).into(),
        ))
        .into(),
        Method::POST => message_from_post(request, content_length).into(),
        _ => HttpsToMessageInner::HttpsError(Some(
            format!("bad method: {}", request.method()).into(),
        ))
        .into(),
    }
}

/// A Future result of the bytes of a DNS message
#[must_use = "futures do nothing unless polled"]
pub struct HttpsToMessage<R>(HttpsToMessageInner<R>);

impl<R> From<HttpsToMessageInner<R>> for HttpsToMessage<R> {
    fn from(inner: HttpsToMessageInner<R>) -> Self {
        HttpsToMessage(inner)
    }
}

impl<R> From<MessageFromPost<R>> for HttpsToMessage<R> {
    fn from(inner: MessageFromPost<R>) -> Self {
        HttpsToMessage(HttpsToMessageInner::FromPost(inner))
    }
}

impl<R> Future for HttpsToMessage<R>
where
    R: Stream<Item = Result<Bytes, h2::Error>> + 'static + Send + Unpin,
{
    type Output = Result<Bytes, HttpsError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.0.poll_unpin(cx)
    }
}

#[must_use = "futures do nothing unless polled"]
enum HttpsToMessageInner<R> {
    FromPost(MessageFromPost<R>),
    HttpsError(Option<HttpsError>),
}

impl<R> Future for HttpsToMessageInner<R>
where
    R: Stream<Item = Result<Bytes, h2::Error>> + 'static + Send + Unpin,
{
    type Output = Result<Bytes, HttpsError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match *self {
            HttpsToMessageInner::FromPost(ref mut from_post) => from_post.poll_unpin(cx),
            HttpsToMessageInner::HttpsError(ref mut error) => {
                Poll::Ready(Err(error.take().expect("cannot poll after complete")))
            }
        }
    }
}

fn message_from_post<R>(request: Request<R>, length: Option<usize>) -> MessageFromPost<R> {
    let body = request.into_body();
    MessageFromPost {
        stream: body,
        length,
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
        use futures::executor::block_on;

        let message = Message::new();
        let msg_bytes = message.to_vec().unwrap();
        let len = msg_bytes.len();
        let stream = TestBytesStream(vec![Ok(Bytes::from(msg_bytes))]);
        let request = request::new("ns.example.com", len).unwrap();
        let request = request.map(|()| stream);

        let from_post = message_from(Arc::new("ns.example.com".to_string()), request);
        let bytes = match block_on(from_post) {
            Ok(bytes) => bytes,
            e => panic!("{:#?}", e),
        };

        let msg_from_post = Message::from_vec(bytes.as_ref()).expect("bytes failed");
        assert_eq!(message, msg_from_post);
    }
}
