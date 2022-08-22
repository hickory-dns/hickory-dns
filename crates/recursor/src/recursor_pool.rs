// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{
    collections::HashMap,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::{future::Shared, Future, FutureExt, StreamExt};
use parking_lot::Mutex;
use tracing::info;
use trust_dns_proto::{
    op::Query,
    xfer::{DnsRequestOptions, DnsResponse},
    DnsHandle,
};
use trust_dns_resolver::{
    error::{ResolveError, ResolveErrorKind},
    name_server::NameServerPool,
    ConnectionProvider, Name, TokioConnection, TokioConnectionProvider,
};

/// Active request cache
///
/// The futures are Shared so any waiting on these results will resolve to the same result
type ActiveRequests = HashMap<Query, SharedLookup>;

type DnsResponseFuture =
    Box<dyn Future<Output = Option<Result<DnsResponse, ResolveError>>> + Send + 'static>;

#[derive(Clone)]
pub(crate) struct SharedLookup(Shared<Pin<DnsResponseFuture>>);

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
pub(crate) struct RecursorPool<
    C: DnsHandle<Error = ResolveError> + Send + Sync + 'static,
    P: ConnectionProvider<Conn = C> + Send + 'static,
> {
    zone: Name,
    ns: NameServerPool<C, P>,
    active_requests: Arc<Mutex<ActiveRequests>>,
}

impl RecursorPool<TokioConnection, TokioConnectionProvider> {
    pub(crate) fn from(
        zone: Name,
        ns: NameServerPool<TokioConnection, TokioConnectionProvider>,
    ) -> Self {
        let active_requests = Arc::new(Mutex::new(ActiveRequests::default()));

        Self {
            zone,
            ns,
            active_requests,
        }
    }
}

impl<C, P> RecursorPool<C, P>
where
    C: DnsHandle<Error = ResolveError> + Send + Sync + 'static,
    P: ConnectionProvider<Conn = C> + Send + 'static,
{
    pub(crate) fn zone(&self) -> &Name {
        &self.zone
    }

    pub(crate) async fn lookup(&self, query: Query) -> Result<DnsResponse, ResolveError> {
        let mut ns = self.ns.clone();

        let query_cpy = query.clone();

        // block concurrent requests
        let lookup = self
            .active_requests
            .lock()
            .entry(query.clone())
            .or_insert_with(move || {
                info!("querying {} for {}", self.zone, query_cpy);

                let mut options = DnsRequestOptions::default();
                options.use_edns = false; // TODO: this should be configurable
                options.recursion_desired = false;

                // convert the lookup into a shared future
                let lookup = ns
                    .lookup(query_cpy, options)
                    .into_future()
                    .map(|(next, _)| next)
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
