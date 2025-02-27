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

use futures_util::{Future, FutureExt, StreamExt, future::Shared};
use hickory_proto::{
    DnsHandle,
    op::Query,
    runtime::{RuntimeProvider, TokioRuntimeProvider},
    xfer::{DnsRequestOptions, DnsResponse},
};
use hickory_resolver::{Name, ResolveError, ResolveErrorKind, name_server::GenericNameServerPool};
use parking_lot::Mutex;
use tracing::info;

#[allow(clippy::type_complexity)]
#[derive(Clone)]
pub(crate) struct SharedLookup(
    Shared<
        Pin<Box<dyn Future<Output = Option<Result<DnsResponse, ResolveError>>> + Send + 'static>>,
    >,
);

impl Future for SharedLookup {
    type Output = Result<DnsResponse, ResolveError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_unpin(cx).map(|o| match o {
            Some(r) => r,
            None => Err(ResolveErrorKind::Message("no response from nameserver").into()),
        })
    }
}

#[derive(Clone)]
pub(crate) struct RecursorPool<P: RuntimeProvider + Send + 'static> {
    zone: Name,
    ns: GenericNameServerPool<P>,
    active_requests: Arc<Mutex<HashMap<Query, SharedLookup>>>,
}

impl RecursorPool<TokioRuntimeProvider> {
    pub(crate) fn from(zone: Name, ns: GenericNameServerPool<TokioRuntimeProvider>) -> Self {
        let active_requests = Arc::new(Mutex::new(HashMap::default()));

        Self {
            zone,
            ns,
            active_requests,
        }
    }
}

impl<P> RecursorPool<P>
where
    P: RuntimeProvider + Send + 'static,
{
    pub(crate) fn zone(&self) -> &Name {
        &self.zone
    }

    pub(crate) async fn lookup(
        &self,
        query: Query,
        security_aware: bool,
    ) -> Result<DnsResponse, ResolveError> {
        let ns = self.ns.clone();

        let query_cpy = query.clone();
        let case_randomization = self.ns.options().case_randomization;

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
                    .map(|(next, _)| next.map(|r| r.map_err(ResolveError::from)))
                    .boxed()
                    .shared();

                SharedLookup(lookup)
            })
            .clone();

        let result = lookup.await;

        // remove the concurrent request marker
        self.active_requests.lock().remove(&query);

        result
    }
}
