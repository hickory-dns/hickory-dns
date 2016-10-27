// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::cell::RefCell;
use std::rc::Rc;
use std::collections::HashMap;

use futures::Future;

use ::client::ClientHandle;
use ::client::rc_future::{rc_future, RcFuture};
use ::error::*;
use ::op::{Message, Query};

pub struct MemoizeClientHandle<H: ClientHandle> {
  client: H,
  active_queries: Rc<RefCell<HashMap<Query, RcFuture<Box<Future<Item=Message, Error=ClientError>>>>>>,
}

impl<H> MemoizeClientHandle<H> where H: ClientHandle {
  pub fn new(client: H) -> MemoizeClientHandle<H> {
    MemoizeClientHandle { client: client, active_queries: Rc::new(RefCell::new(HashMap::new())) }
  }

}

impl<H> Clone for MemoizeClientHandle<H> where H: ClientHandle + Clone {
  fn clone(&self) -> Self {
    MemoizeClientHandle {
      client: self.client.clone(),
      active_queries: self.active_queries.clone(),
    }
  }
}

impl<H> ClientHandle for MemoizeClientHandle<H> where H: ClientHandle {
  // TODO: should send be &mut so that we don't need RefCell here?
  fn send(&self, message: Message) -> Box<Future<Item=Message, Error=ClientError>> {
    let query = message.get_queries().first().expect("no query!").clone();

    if let Some(rc_future) = self.active_queries.borrow().get(&query) {
      // TODO check TTLs?
      return Box::new(rc_future.clone());
    }

    // TODO: it should be safe to loop here until the entry.or_insert_with returns...
    // check if there are active queries
    let mut map = self.active_queries.borrow_mut();
    let rc_future = map.entry(query).or_insert_with(move ||{
      rc_future(self.client.send(message))
    });

    return Box::new(rc_future.clone());
  }
}
