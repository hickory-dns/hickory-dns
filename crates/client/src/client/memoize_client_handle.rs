// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use futures_util::future::FutureExt;
use futures_util::lock::Mutex;
use futures_util::stream::Stream;
use hickory_proto::{
    ProtoError,
    op::Query,
    xfer::{DnsHandle, DnsRequest, DnsResponse},
};

use crate::client::ClientHandle;
use crate::client::rc_stream::{RcStream, rc_stream};

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
    active_queries: Arc<Mutex<HashMap<Query, RcStream<<H as DnsHandle>::Response>>>>,
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

    async fn inner_send(
        request: DnsRequest,
        active_queries: Arc<Mutex<HashMap<Query, RcStream<<H as DnsHandle>::Response>>>>,
        client: H,
    ) -> impl Stream<Item = Result<DnsResponse, ProtoError>> {
        // TODO: what if we want to support multiple queries (non-standard)?
        let query = request.queries().first().expect("no query!").clone();

        // lock all the currently running queries
        let mut active_queries = active_queries.lock().await;

        // TODO: we need to consider TTL on the records here at some point
        // If the query is running, grab that existing one...
        if let Some(rc_stream) = active_queries.get(&query) {
            return rc_stream.clone();
        };

        // Otherwise issue a new query and store in the map
        active_queries
            .entry(query)
            .or_insert_with(|| rc_stream(client.send(request)))
            .clone()
    }
}

impl<H> DnsHandle for MemoizeClientHandle<H>
where
    H: ClientHandle,
{
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send>>;

    fn send<R: Into<DnsRequest>>(&self, request: R) -> Self::Response {
        let request = request.into();

        Box::pin(
            Self::inner_send(
                request,
                Arc::clone(&self.active_queries),
                self.client.clone(),
            )
            .flatten_stream(),
        )
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use std::pin::Pin;
    use std::sync::Arc;

    use futures::lock::Mutex;
    use futures::*;
    use hickory_proto::{
        ProtoError,
        op::{Message, Query},
        rr::RecordType,
        xfer::{DnsHandle, DnsRequest, DnsResponse},
    };
    use test_support::subscribe;

    use crate::client::*;
    use hickory_proto::xfer::FirstAnswer;

    #[derive(Clone)]
    struct TestClient {
        i: Arc<Mutex<u16>>,
    }

    impl DnsHandle for TestClient {
        type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send>>;

        fn send<R: Into<DnsRequest> + Send + 'static>(&self, request: R) -> Self::Response {
            let i = Arc::clone(&self.i);
            let future = async {
                let i = i;
                let request = request;
                let mut message = Message::new();

                let mut i = i.lock().await;

                message.set_id(*i);
                println!(
                    "sending {}: {}",
                    *i,
                    request.into().queries().first().expect("no query!").clone()
                );

                *i += 1;

                Ok(DnsResponse::from_message(message).unwrap())
            };

            Box::pin(stream::once(future))
        }
    }

    #[test]
    fn test_memoized() {
        use futures::executor::block_on;

        subscribe();

        let client = MemoizeClientHandle::new(TestClient {
            i: Arc::new(Mutex::new(0)),
        });

        let mut test1 = Message::new();
        test1.add_query(Query::new().set_query_type(RecordType::A).clone());

        let mut test2 = Message::new();
        test2.add_query(Query::new().set_query_type(RecordType::AAAA).clone());

        let result = block_on(client.send(test1.clone()).first_answer())
            .ok()
            .unwrap();
        assert_eq!(result.id(), 0);

        let result = block_on(client.send(test2.clone()).first_answer())
            .ok()
            .unwrap();
        assert_eq!(result.id(), 1);

        // should get the same result for each...
        let result = block_on(client.send(test1).first_answer()).ok().unwrap();
        assert_eq!(result.id(), 0);

        let result = block_on(client.send(test2).first_answer()).ok().unwrap();
        assert_eq!(result.id(), 1);
    }
}
