// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::sync::Arc;
use std::pin::Pin;
use std::task::Context;

use futures::{future, ready, channel::mpsc, Future, FutureExt, Poll, StreamExt};
use futures::lock::Mutex;
#[cfg(feature = "dnssec")]
use proto::SecureDnsHandle;
use proto::{
    error::ProtoResult,
    rr::{Name, RData, RecordType, Record},
    xfer::{DnsRequestOptions, RetryDnsHandle},
};

use crate::config::{ResolverConfig, ResolverOpts};
use crate::dns_lru::{self, DnsLru};
use crate::hosts::Hosts;
use crate::lookup::{Lookup, LookupEither, LookupFuture};
use crate::lookup_ip::LookupIpFuture;
use crate::lookup_state::CachingClient;
use crate::name_server::{ConnectionHandle, NameServerPool, StandardConnection};
use crate::proto::op::Query;

use super::Request;

/// Returns a new future that will drive the background task.
///
/// This background task manages the [`NameServerPool`] and other state used
/// to drive lookups. When this future is spawned on an executor, it will
/// first construct the [`NameServerPool`] and configure the client state,
/// before yielding. When polled again, it will check for any incoming lookup
/// requests, handle them, and then yield again, as long as there are still any
/// [`AsyncResolver`] handles linked to that background task. When all of its
/// [`AsyncResolver`]s have been dropped, the background future will finish.
pub(super) fn task(
    config: ResolverConfig,
    options: ResolverOpts,
    lru: Arc<Mutex<DnsLru>>,
    request_rx: mpsc::UnboundedReceiver<Request>,
) -> impl Future<Output = ()> + Send {
    future::lazy(move |_| {
        debug!("trust-dns resolver running");

        let pool =
            NameServerPool::<ConnectionHandle, StandardConnection>::from_config(&config, &options);
        let either;
        let client = RetryDnsHandle::new(pool.clone(), options.attempts);
        if options.validate {
            #[cfg(feature = "dnssec")]
            {
                either = LookupEither::Secure(SecureDnsHandle::new(client));
            }

            #[cfg(not(feature = "dnssec"))]
            {
                // TODO: should this just be a panic, or a pinned error?
                warn!("validate option is only available with 'dnssec' feature");
                either = LookupEither::Retry(client);
            }
        } else {
            either = LookupEither::Retry(client);
        }

        let hosts = if options.use_hosts_file {
            Some(Arc::new(Hosts::new()))
        } else {
            None
        };

        trace!("handle passed back");
        Task {
            config,
            options,
            client_cache: CachingClient::with_cache(lru, either),
            hosts,
            request_rx,
        }
    }).flatten()
}

type ClientCache = CachingClient<LookupEither<ConnectionHandle, StandardConnection>>;

/// Background task that resolves DNS queries.
struct Task {
    config: ResolverConfig,
    options: ResolverOpts,
    client_cache: ClientCache,
    hosts: Option<Arc<Hosts>>,
    request_rx: mpsc::UnboundedReceiver<Request>,
}

impl Task {
    fn lookup(
        &self,
        name: Name,
        record_type: RecordType,
        options: DnsRequestOptions,
    ) -> LookupFuture {
        let names = self.build_names(name);
        LookupFuture::lookup(names, record_type, options, self.client_cache.clone())
    }

    fn lookup_ip(&self, maybe_name: ProtoResult<Name>, maybe_ip: Option<RData>) -> LookupIpFuture {
        let mut finally_ip_addr: Option<Record> = None;

        // if host is a ip address, return directly.
        if let Some(ip_addr) = maybe_ip {
            let name = maybe_name.clone().unwrap_or_default();
            let record = Record::from_rdata(name.clone(), dns_lru::MAX_TTL, ip_addr.clone());

            // if ndots are greater than 4, then we can't assume the name is an IpAddr
            //   this accepts IPv6 as well, b/c IPv6 can take the form: 2001:db8::198.51.100.35
            //   but `:` is not a valid DNS character, so technically this will fail parsing.
            //   TODO: should we always do search before returning this?
            if self.options.ndots > 4 {
                finally_ip_addr = Some(record);
            } else {
                let query = Query::query(name, ip_addr.to_record_type());
                let lookup = Lookup::new_with_max_ttl(query, Arc::new(vec![record]));
                return LookupIpFuture::ok(self.client_cache.clone(), lookup);
            }
        }

        let name = match (maybe_name, finally_ip_addr.as_ref()) {
            (Ok(name), _) => name,
            (Err(_), Some(ip_addr)) => {
                // it was a valid IP, return that...
                let query = Query::query(ip_addr.name().clone(), ip_addr.record_type());
                let lookup = Lookup::new_with_max_ttl(query, Arc::new(vec![ip_addr.clone()]));
                return LookupIpFuture::ok(self.client_cache.clone(), lookup);
            }
            (Err(err), None) => {
                return LookupIpFuture::error(self.client_cache.clone(), err);
            }
        };

        let names = self.build_names(name);
        let hosts = self.hosts.as_ref().cloned();

        LookupIpFuture::lookup(
            names,
            self.options.ip_strategy,
            self.client_cache.clone(),
            DnsRequestOptions::default(),
            hosts,
            finally_ip_addr.map(Record::unwrap_rdata),
        )
    }

    fn push_name(name: Name, names: &mut Vec<Name>) {
        if !names.contains(&name) {
            names.push(name);
        }
    }

    fn build_names(&self, name: Name) -> Vec<Name> {
        // if it's fully qualified, we can short circuit the lookup logic
        if name.is_fqdn() {
            vec![name]
        } else {
            // Otherwise we have to build the search list
            // Note: the vec is built in reverse order of precedence, for stack semantics
            let mut names =
                Vec::<Name>::with_capacity(1 /*FQDN*/ + 1 /*DOMAIN*/ + self.config.search().len());

            // if not meeting ndots, we always do the raw name in the final lookup, or it's a localhost...
            let raw_name_first: bool =
                name.num_labels() as usize > self.options.ndots || name.is_localhost();

            // if not meeting ndots, we always do the raw name in the final lookup
            if !raw_name_first {
                names.push(name.clone());
            }

            for search in self.config.search().iter().rev() {
                let name_search = name.clone().append_domain(search);
                Self::push_name(name_search, &mut names);
            }

            if let Some(domain) = self.config.domain() {
                let name_search = name.clone().append_domain(domain);
                Self::push_name(name_search, &mut names);
            }

            // this is the direct name lookup
            if raw_name_first {
                // adding the name as though it's an FQDN for lookup
                names.push(name.clone());
            }

            names
        }
    }
}

impl Future for Task {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            let poll = self.request_rx.poll_next_unpin(cx);
            match ready!(poll) {
                None => {
                    // mpsc::UnboundedReceiver::poll(cx) returns `None` when the sender
                    // has been dropped.
                    trace!("AsyncResolver dropped, shutting down background task.");
                    // Return `Ready` so the background future finishes, as no handles
                    // are using it any longer.
                    return Poll::Ready(());
                }
                Some(Request::Lookup {
                    name,
                    record_type,
                    options,
                    tx,
                }) => {
                    trace!("AsyncResolver performing lookup");
                    let future = self.lookup(name, record_type, options);
                    // tx.send() will return an error if the oneshot was canceled, but
                    // we don't actually care, so just drop the future.
                    let _ = tx.send(future);
                }
                Some(Request::Ip {
                    maybe_name,
                    maybe_ip,
                    tx,
                }) => {
                    trace!("AsyncResolver performing lookup_ip");
                    let future = self.lookup_ip(maybe_name, maybe_ip);
                    // tx.send() will return an error if the oneshot was canceled, but
                    // we don't actually care, so just drop the future.
                    let _ = tx.send(future);
                }
            }
        }
    }
}
