// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use futures::{Future, Poll};

use ::client::ClientHandle;
use ::error::*;
use ::op::Message;

#[derive(Clone)]
pub struct RetryClientHandle<H: ClientHandle> {
  client: H,
  attempts: usize,
}

impl<H> RetryClientHandle<H> where H: ClientHandle {
  pub fn new(client: H, attempts: usize) -> RetryClientHandle<H> {
    RetryClientHandle { client: client, attempts: attempts }
  }
}

impl<H> ClientHandle for RetryClientHandle<H> where H: ClientHandle + 'static {
  fn send(&self, message: Message) -> Box<Future<Item=Message, Error=ClientError>> {
    // need to clone here so that the retry can resend if necessary...
    //  obviously it would be nice to be lazy about this...
    let future = self.client.send(message.clone());

    return Box::new(RetrySendFuture{
      message: message,
      client: self.client.clone(),
      future: future,
      remaining_attempts: self.attempts
    });
  }
}

/// A future for retrying (on failure, for the remaining number of times specified)
struct RetrySendFuture<H: ClientHandle> {
  message: Message,
  client: H,
  future: Box<Future<Item=Message, Error=ClientError>>,
  remaining_attempts: usize,
}

impl<H> Future for RetrySendFuture<H> where H: ClientHandle {
  type Item = Message;
  type Error = ClientError;

  fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
    // loop over the future, on errors, spawn a new future
    //  on ready and not ready return.
    loop {
      match self.future.poll() {
        r @ Ok(_) => return r,
        Err(e) => {
          if self.remaining_attempts == 0 {
            return Err(e);
          }

          self.remaining_attempts = self.remaining_attempts - 1;
          // TODO: if the "sent" Message is part of the error result,
          //  then we can just reuse it... and no clone necessary
          self.future = self.client.send(self.message.clone());
        }
      }
    }
  }
}

#[cfg(test)]
mod test {
  use std::cell::Cell;
  use super::RetryClientHandle;
  use ::client::*;
  use ::error::*;
  use ::op::*;
  use futures::*;

  #[derive(Clone)]
  struct TestClient { last_succeed: bool, retries: u16, attempts: Cell<u16> }

  impl ClientHandle for TestClient {
    fn send(&self, _: Message) -> Box<Future<Item=Message, Error=ClientError>> {
      let i = self.attempts.get();
      self.attempts.set(i + 1);

      if self.retries - i == 0 && self.last_succeed {
        let mut message = Message::new();
        message.id(i);
        return Box::new(finished(message))
      }

      return Box::new(failed(ClientErrorKind::Message("last retry set to fail").into()))
    }
  }

  #[test]
  fn test_retry() {
    let client = RetryClientHandle::new(TestClient{last_succeed: true, retries: 1, attempts: Cell::new(0)}, 2);
    let test1 = Message::new();
    let result = client.send(test1).wait().ok().expect("should have succeeded");
    assert_eq!(result.get_id(), 1); // this is checking the number of iterations the TestCient ran
  }

  #[test]
  fn test_error() {
    let client = RetryClientHandle::new(TestClient{last_succeed: false, retries: 1, attempts: Cell::new(0)}, 2);
    let test1 = Message::new();
    assert!(client.send(test1).wait().is_err());

  }
}
