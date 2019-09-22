// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::pin::Pin;

use futures::Future;
use proto::error::ProtoError;
use proto::xfer::{DnsHandle, DnsRequest, DnsResponse};

use crate::client::rc_future::{rc_future, RcFuture};
use crate::client::ClientHandle;
use crate::op::Query;

// TODO: move to proto
/// A ClientHandle for memoized (cached) responses to queries.
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
            client,
            active_queries: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<H> DnsHandle for MemoizeClientHandle<H>
where
    H: ClientHandle,
{
    type Response = Pin<Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send>>;

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> Self::Response {
        let request = request.into();
        let query = request.queries().first().expect("no query!").clone();

        if let Some(rc_future) = self.active_queries.lock().expect("poisoned").get(&query) {
            // FIXME check TTLs?
            return Box::pin(rc_future.clone());
        }

        // check if there are active queries
        {
            let map = self.active_queries.lock().expect("poisoned");
            let request = map.get(&query);

            if let Some(request) = request {
                return Box::pin(request.clone());
            }
        }

        let request = rc_future(self.client.send(request));
        let mut map = self.active_queries.lock().expect("poisoned");
        map.insert(query, request.clone());

        Box::pin(request)
    }
}

#[cfg(test)]
mod test {
    use std::cell::Cell;
    use std::pin::Pin;

    use futures::*;
    use proto::error::ProtoError;
    use proto::xfer::{DnsHandle, DnsRequest, DnsResponse};

    use crate::client::*;
    use crate::op::*;
    use crate::rr::*;

    #[derive(Clone)]
    struct TestClient {
        i: Cell<u16>,
    }

    impl DnsHandle for TestClient {
        type Response = Pin<Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send>>;

        fn send<R: Into<DnsRequest>>(&mut self, _: R) -> Self::Response {
            let mut message = Message::new();
            let i = self.i.get();

            message.set_id(i);
            self.i.set(i + 1);

            Box::pin(future::ok(message.into()))
        }
    }

    #[test]
    fn test_memoized() {
        use futures::executor::block_on;

        let mut client = MemoizeClientHandle::new(TestClient { i: Cell::new(0) });

        let mut test1 = Message::new();
        test1.add_query(Query::new().set_query_type(RecordType::A).clone());

        let mut test2 = Message::new();
        test2.add_query(Query::new().set_query_type(RecordType::AAAA).clone());

        let result = block_on(client.send(test1.clone())).ok().unwrap();
        assert_eq!(result.id(), 0);

        let result = block_on(client.send(test2.clone())).ok().unwrap();
        assert_eq!(result.id(), 1);

        // should get the same result for each...
        let result = block_on(client.send(test1)).ok().unwrap();
        assert_eq!(result.id(), 0);

        let result = block_on(client.send(test2)).ok().unwrap();
        assert_eq!(result.id(), 1);
    }

}
