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

use client::ClientHandle;
use client::rc_future::{rc_future, RcFuture};
use error::*;
use op::{Message, Query};

/// A ClienHandle for memoized (cached) responses to queries.
///
/// This wraps a ClientHandle, changing the implementation `send()` to store the response against
///  the Message.Query that was sent. This should reduce network traffic especially during things
///  like DNSSec validation. *Warning* this will currently cache for the life of the Client.
#[derive(Clone)]
#[must_use = "queries can only be sent through a ClientHandle"]
pub struct MemoizeClientHandle<H: ClientHandle> {
    client: H,
    active_queries: Rc<RefCell<HashMap<Query,
                                       RcFuture<Box<Future<Item = Message,
                                                           Error = ClientError>>>>>>,
}

impl<H> MemoizeClientHandle<H>
    where H: ClientHandle
{
    /// Returns a new handle wrapping the specified client
    pub fn new(client: H) -> MemoizeClientHandle<H> {
        MemoizeClientHandle {
            client: client,
            active_queries: Rc::new(RefCell::new(HashMap::new())),
        }
    }
}

impl<H> ClientHandle for MemoizeClientHandle<H>
    where H: ClientHandle
{
    fn send(&mut self, message: Message) -> Box<Future<Item = Message, Error = ClientError>> {
        let query = message.queries()
            .first()
            .expect("no query!")
            .clone();

        if let Some(rc_future) = self.active_queries.borrow().get(&query) {
            // FIXME check TTLs?
            return Box::new(rc_future.clone());
        }

        // check if there are active queries
        {
            let map = self.active_queries.borrow();
            let request = map.get(&query);
            if request.is_some() {
                return Box::new(request.unwrap().clone());
            }
        }

        let request = rc_future(self.client.send(message));
        let mut map = self.active_queries.borrow_mut();
        map.insert(query, request.clone());

        return Box::new(request);
    }
}

#[cfg(test)]
mod test {
    use std::cell::Cell;
    use client::*;
    use error::*;
    use op::*;
    use rr::*;
    use futures::*;

    #[derive(Clone)]
    struct TestClient {
        i: Cell<u16>,
    }

    impl ClientHandle for TestClient {
        fn send(&mut self, _: Message) -> Box<Future<Item = Message, Error = ClientError>> {
            let mut message = Message::new();
            let i = self.i.get();

            message.set_id(i);
            self.i.set(i + 1);

            Box::new(finished(message))
        }
    }

    #[test]
    fn test_memoized() {
        let mut client = MemoizeClientHandle::new(TestClient { i: Cell::new(0) });

        let mut test1 = Message::new();
        test1.add_query(Query::new().set_query_type(RecordType::A).clone());

        let mut test2 = Message::new();
        test2.add_query(Query::new().set_query_type(RecordType::AAAA).clone());

        let result = client.send(test1.clone())
            .wait()
            .ok()
            .unwrap();
        assert_eq!(result.id(), 0);

        let result = client.send(test2.clone())
            .wait()
            .ok()
            .unwrap();
        assert_eq!(result.id(), 1);

        // should get the same result for each...
        let result = client.send(test1)
            .wait()
            .ok()
            .unwrap();
        assert_eq!(result.id(), 0);

        let result = client.send(test2)
            .wait()
            .ok()
            .unwrap();
        assert_eq!(result.id(), 1);
    }

}
