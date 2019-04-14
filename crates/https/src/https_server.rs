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

use bytes::Bytes;
use futures::{Async, Future, Poll, Stream};
use h2;
use http::{Method, Request};
use typed_headers::{ContentLength, HeaderMapExt};

use HttpsError;

/// Given an HTTP request, return a future that will result in the next sequence of bytes.
///
/// To allow downstream clients to do something interesting with the lifetime of the bytes, this doesn't
///   perform a conversion to a Message, only collects all the bytes.
pub fn message_from<R>(this_server_name: Arc<String>, request: Request<R>) -> HttpsToMessage<R>
where
    R: Stream<Item = Bytes, Error = h2::Error> + 'static + Send + Debug,
{
    debug!("Received request: {:#?}", request);

    let this_server_name: &String = this_server_name.borrow();
    match ::request::verify(this_server_name, &request) {
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
    R: Stream<Item = Bytes, Error = h2::Error> + 'static + Send,
{
    type Item = Bytes;
    type Error = HttpsError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

#[must_use = "futures do nothing unless polled"]
enum HttpsToMessageInner<R> {
    FromPost(MessageFromPost<R>),
    HttpsError(Option<HttpsError>),
}

impl<R> Future for HttpsToMessageInner<R>
where
    R: Stream<Item = Bytes, Error = h2::Error> + 'static + Send,
{
    type Item = Bytes;
    type Error = HttpsError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self {
            HttpsToMessageInner::FromPost(from_post) => from_post.poll(),
            HttpsToMessageInner::HttpsError(error) => {
                Err(error.take().expect("cannot poll after complete"))
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
    R: Stream<Item = Bytes, Error = h2::Error> + 'static + Send,
{
    type Item = Bytes;
    type Error = HttpsError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            let bytes = match self.stream.poll() {
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(Some(bytes))) => bytes,
                Ok(Async::Ready(None)) => return Err("not all bytes received".into()),
                Err(e) => return Err(e.into()),
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
            return Ok(Async::Ready(bytes));
        }
    }
}

#[cfg(test)]
mod tests {
    use request;
    use trust_dns_proto::op::Message;

    use super::*;

    #[derive(Debug)]
    struct TestBytesStream(Vec<Result<Bytes, h2::Error>>);

    impl Stream for TestBytesStream {
        type Item = Bytes;
        type Error = h2::Error;

        fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
            match self.0.pop() {
                Some(Ok(bytes)) => Ok(Async::Ready(Some(bytes))),
                Some(Err(err)) => Err(err),
                None => Ok(Async::Ready(None)),
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

        let mut from_post = message_from(Arc::new("ns.example.com".to_string()), request);
        let bytes = match from_post.poll() {
            Ok(Async::Ready(bytes)) => bytes,
            e => panic!("{:#?}", e),
        };

        let msg_from_post = Message::from_vec(bytes.as_ref()).expect("bytes failed");
        assert_eq!(message, msg_from_post);
    }
}
