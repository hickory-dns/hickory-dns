// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::collections::HashMap;
use std::sync::Arc;

use futures_util::future::{BoxFuture, FutureExt, Shared};
use futures_util::lock::Mutex;

use super::ClientHandle;
use crate::{
    NetError,
    proto::op::{DnsRequest, DnsResponse, Query},
    xfer::DnsHandle,
};

// TODO: move to proto
/// A ClientHandle for memoized (cached) responses to queries.
///
/// This wraps a ClientHandle, changing the implementation `send()` to store the response against
///  the Message.Query that was sent. This should reduce network traffic especially during things
///  like DNSSEC validation. *Warning* this will currently cache for the life of the Client.
#[derive(Clone)]
#[must_use = "queries can only be sent through a ClientHandle"]
pub struct MemoizeClientHandle<H: ClientHandle> {
    client: H,
    active_queries: Arc<Mutex<HashMap<Query, SharedResponse>>>,
}

impl<H> MemoizeClientHandle<H>
where
    H: ClientHandle,
{
    /// Returns a new handle wrapping the specified client
    pub fn new(client: H) -> Self {
        Self {
            client,
            active_queries: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<H: ClientHandle> DnsHandle for MemoizeClientHandle<H> {
    type Runtime = H::Runtime;

    async fn send(&self, request: DnsRequest) -> Result<DnsResponse, NetError> {
        // TODO: what if we want to support multiple queries (non-standard)?
        let query = request.queries.first().expect("no query!").clone();

        // lock all the currently running queries
        let mut active_queries = self.active_queries.lock().await;

        // TODO: we need to consider TTL on the records here at some point
        // If the query is running, grab that existing one, otherwise issue a new query and
        // store it in the map
        let response = active_queries
            .entry(query)
            .or_insert_with(|| {
                let client = self.client.clone();
                async move { client.send(request).await }.boxed().shared()
            })
            .clone();

        drop(active_queries);
        response.await
    }
}

type SharedResponse = Shared<BoxFuture<'static, Result<DnsResponse, NetError>>>;

#[cfg(test)]
mod test {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use std::sync::Arc;

    use futures_util::lock::Mutex;

    use super::*;
    use crate::{
        proto::{
            op::{DnsRequest, DnsResponse, Message, MessageType, OpCode, Query},
            rr::{Name, RecordType},
        },
        runtime::TokioRuntimeProvider,
        xfer::DnsHandle,
    };
    use test_support::subscribe;

    #[derive(Clone)]
    struct TestClient {
        i: Arc<Mutex<u16>>,
    }

    impl DnsHandle for TestClient {
        type Runtime = TokioRuntimeProvider;

        async fn send(&self, request: DnsRequest) -> Result<DnsResponse, NetError> {
            let mut i = self.i.lock().await;
            let message = Message::new(*i, MessageType::Query, OpCode::Query).into_response();
            std::println!(
                "sending {}: {}",
                *i,
                request.queries.first().expect("no query!").clone()
            );

            *i += 1;

            Ok(DnsResponse::from_message(message).unwrap())
        }
    }

    #[test]
    fn test_memoized() {
        use futures_executor::block_on;

        subscribe();

        let client = MemoizeClientHandle::new(TestClient {
            i: Arc::new(Mutex::new(0)),
        });

        let mut test1 = Message::query();
        test1.add_query(Query::new(Name::root(), RecordType::A));

        let mut test2 = Message::query();
        test2.add_query(Query::new(Name::root(), RecordType::AAAA));

        let result = block_on(client.send(DnsRequest::from(test1.clone()))).unwrap();
        assert_eq!(result.id, 0);

        let result = block_on(client.send(DnsRequest::from(test2.clone()))).unwrap();
        assert_eq!(result.id, 1);

        // should get the same result for each...
        let result = block_on(client.send(DnsRequest::from(test1))).unwrap();
        assert_eq!(result.id, 0);

        let result = block_on(client.send(DnsRequest::from(test2))).unwrap();
        assert_eq!(result.id, 1);
    }
}
