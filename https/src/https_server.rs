// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::borrow::Borrow;
use std::fmt::Debug;
use std::sync::Arc;

use bytes::Bytes;
use futures::{Async, Future, Poll, Stream};
use h2::RecvStream;
use http::{Method, Request};
use typed_headers::{ContentLength, HeaderMapExt};

use trust_dns_proto::op::Message;
use {HttpsError, HttpsResult};

// TODO: change RecvStream to Generic over Stream of Bytes
pub fn message_from(this_server_name: Arc<String>, request: Request<RecvStream>) -> HttpsToMessage {
    debug!("Received request: {:#?}", request);

    let this_server_name: &String = this_server_name.borrow();
    match ::request::verify(this_server_name, &request) {
        Ok(_) => (),
        Err(err) => return HttpsToMessageInner::Error(Some(err)).into(),
    }

    // attempt to get the content length
    let content_length: Option<ContentLength> = match request.headers().typed_get() {
        Ok(l) => l,
        Err(err) => return HttpsToMessageInner::Error(Some(err.into())).into(),
    };

    let content_length: Option<usize> = content_length.map(|c| {
        let length = *c as usize;
        debug!("got message length: {}", length);
        length
    });

    match *request.method() {
        Method::GET => HttpsToMessageInner::Error(Some(
            format!("GET unimplemented: {}", request.method()).into(),
        )).into(),
        Method::POST => message_from_post(request, content_length).into(),
        _ => HttpsToMessageInner::Error(Some(format!("bad method: {}", request.method()).into()))
            .into(),
    }
}

pub struct HttpsToMessage(HttpsToMessageInner);

impl From<HttpsToMessageInner> for HttpsToMessage {
    fn from(inner: HttpsToMessageInner) -> Self {
        HttpsToMessage(inner)
    }
}

impl From<MessageFromPost> for HttpsToMessage {
    fn from(inner: MessageFromPost) -> Self {
        HttpsToMessage(HttpsToMessageInner::FromPost(inner))
    }
}

impl Future for HttpsToMessage {
    type Item = Bytes;
    type Error = HttpsError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

enum HttpsToMessageInner {
    FromPost(MessageFromPost),
    Error(Option<HttpsError>),
}

impl Future for HttpsToMessageInner {
    type Item = Bytes;
    type Error = HttpsError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self {
            HttpsToMessageInner::FromPost(from_post) => from_post.poll(),
            HttpsToMessageInner::Error(error) => {
                Err(error.take().expect("cannot poll after complete"))
            }
        }
    }
}

fn message_from_post(request: Request<RecvStream>, length: Option<usize>) -> MessageFromPost {
    let body = request.into_body();
    MessageFromPost {
        stream: body,
        length: length,
    }
}

struct MessageFromPost {
    stream: RecvStream,
    length: Option<usize>,
}

impl Future for MessageFromPost {
    type Item = Bytes;
    type Error = HttpsError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            let mut bytes = match self.stream.poll() {
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
    #[test]
    fn test_from_post() {
        panic!("need test")
    }
}
