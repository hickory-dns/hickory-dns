// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures::Future;
use trust_dns_proto::xfer::{DnsHandle, DnsRequest, DnsResponse};

use client::rc_future::{rc_future, RcFuture};
use client::ClientHandle;
use error::*;
use op::Query;

// TODO: move to proto
/// A ClienHandle for memoized (cached) responses to queries.
///
/// This wraps a ClientHandle, changing the implementation `send()` to store the response against
///  the Message.Query that was sent. This should reduce network traffic especially during things
///  like DNSSec validation. *Warning* this will currently cache for the life of the Client.
#[derive(Clone)]
#[must_use = "queries can only be sent through a ClientHandle"]
pub struct MemoizeClientHandle<H: ClientHandle> {
    client: H,
    active_queries: Arc<Mutex<HashMap<Query, RcFuture<<H as DnsHandle>::Response>>>>,
}

impl<H> MemoizeClientHandle<H>
where
    H: ClientHandle,
{
    /// Returns a new handle wrapping the specified client
    pub fn new(client: H) -> MemoizeClientHandle<H> {
        MemoizeClientHandle {
            client: client,
            active_queries: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<H> DnsHandle for MemoizeClientHandle<H>
where
    H: ClientHandle,
{
    type Error = ClientError;
    type Response = Box<Future<Item = DnsResponse, Error = Self::Error> + Send>;

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> Self::Response {
        let request = request.into();
        let query = request.queries().first().expect("no query!").clone();

        if let Some(rc_future) = self.active_queries.lock().expect("poisoned").get(&query) {
            // FIXME check TTLs?
            return Box::new(rc_future.clone().map_err(ClientError::from));
        }

        // check if there are active queries
        {
            let map = self.active_queries.lock().expect("poisoned");
            let request = map.get(&query);
            if request.is_some() {
                return Box::new(request.unwrap().clone().map_err(ClientError::from));
            }
        }

        let request = rc_future(self.client.send(request));
        let mut map = self.active_queries.lock().expect("poisoned");
        map.insert(query, request.clone());

        Box::new(request)
    }
}

#[cfg(test)]
mod test {
    use client::*;
    use error::*;
    use futures::*;
    use op::*;
    use rr::*;
    use std::cell::Cell;
    use trust_dns_proto::xfer::{DnsHandle, DnsRequest, DnsResponse};

    #[derive(Clone)]
    struct TestClient {
        i: Cell<u16>,
    }

    impl DnsHandle for TestClient {
        type Error = ClientError;
        type Response = Box<Future<Item = DnsResponse, Error = Self::Error> + Send>;

        fn send<R: Into<DnsRequest>>(&mut self, _: R) -> Self::Response {
            let mut message = Message::new();
            let i = self.i.get();

            message.set_id(i);
            self.i.set(i + 1);

            Box::new(finished(message.into()))
        }
    }

    #[test]
    fn test_memoized() {
        let mut client = MemoizeClientHandle::new(TestClient { i: Cell::new(0) });

        let mut test1 = Message::new();
        test1.add_query(Query::new().set_query_type(RecordType::A).clone());

        let mut test2 = Message::new();
        test2.add_query(Query::new().set_query_type(RecordType::AAAA).clone());

        let result = client.send(test1.clone()).wait().ok().unwrap();
        assert_eq!(result.id(), 0);

        let result = client.send(test2.clone()).wait().ok().unwrap();
        assert_eq!(result.id(), 1);

        // should get the same result for each...
        let result = client.send(test1).wait().ok().unwrap();
        assert_eq!(result.id(), 0);

        let result = client.send(test2).wait().ok().unwrap();
        assert_eq!(result.id(), 1);
    }

}
