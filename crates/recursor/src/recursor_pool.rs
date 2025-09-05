// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{
    collections::HashMap,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::{
    Future, FutureExt, StreamExt,
    future::{BoxFuture, Shared},
};
use hickory_resolver::name_server::NameServerPool;
#[cfg(feature = "metrics")]
use metrics::{Counter, Unit, counter, describe_counter};
use parking_lot::Mutex;
use tracing::info;

use crate::proto::{
    DnsHandle, ProtoError,
    op::{DnsRequestOptions, DnsResponse, Query},
};
use crate::resolver::{Name, name_server::ConnectionProvider};

#[derive(Clone)]
pub(crate) struct SharedLookup(Shared<BoxFuture<'static, Option<Result<DnsResponse, ProtoError>>>>);

impl Future for SharedLookup {
    type Output = Result<DnsResponse, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_unpin(cx).map(|o| match o {
            Some(r) => r,
            None => Err("no response from nameserver".into()),
        })
    }
}

#[derive(Clone)]
pub(crate) struct RecursorPool<P: ConnectionProvider> {
    zone: Name,
    case_randomization: bool,
    ns: NameServerPool<P>,
    active_requests: Arc<Mutex<HashMap<Query, SharedLookup>>>,
    #[cfg(feature = "metrics")]
    outgoing_query_counter: Counter,
}

impl<P: ConnectionProvider> RecursorPool<P> {
    pub(crate) fn from(zone: Name, case_randomization: bool, ns: NameServerPool<P>) -> Self {
        #[cfg(feature = "metrics")]
        let outgoing_query_counter = counter!("hickory_recursor_outgoing_queries_total");
        #[cfg(feature = "metrics")]
        describe_counter!(
            "hickory_recursor_outgoing_queries_total",
            Unit::Count,
            "Number of outgoing queries made during resolution."
        );

        Self {
            zone,
            case_randomization,
            ns,
            active_requests: Arc::new(Mutex::new(HashMap::default())),
            #[cfg(feature = "metrics")]
            outgoing_query_counter,
        }
    }

    pub(crate) fn zone(&self) -> &Name {
        &self.zone
    }

    pub(crate) async fn lookup(
        &self,
        query: Query,
        security_aware: bool,
    ) -> Result<DnsResponse, ProtoError> {
        let ns = self.ns.clone();

        let query_cpy = query.clone();
        let case_randomization = self.case_randomization;

        // block concurrent requests
        let lookup = self
            .active_requests
            .lock()
            .entry(query.clone())
            .or_insert_with(move || {
                info!("querying {} for {}", self.zone, query_cpy);

                let mut options = DnsRequestOptions::default();
                options.use_edns = security_aware;
                options.edns_set_dnssec_ok = security_aware;
                options.case_randomization = case_randomization;

                // Set RD=0 in queries made by the recursive resolver. See the last figure in
                // section 2.2 of RFC 1035, for example. Failure to do so may allow for loops
                // between recursive resolvers following referrals to each other.
                options.recursion_desired = false;

                // convert the lookup into a shared future
                let lookup = ns
                    .lookup(query_cpy, options)
                    .into_future()
                    .map(|(next, _)| next)
                    .boxed()
                    .shared();

                #[cfg(feature = "metrics")]
                self.outgoing_query_counter.increment(1);

                SharedLookup(lookup)
            })
            .clone();

        let result = lookup.await;

        // remove the concurrent request marker
        self.active_requests.lock().remove(&query);

        result
    }
}
