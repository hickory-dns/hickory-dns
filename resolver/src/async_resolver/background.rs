use std::sync::{Arc, Mutex};

use futures::{
    future,
    sync::mpsc,
    Async, Future, Poll, Stream
};
use trust_dns_proto::{
    error::ProtoResult,
    rr::{Name, RData, RecordType},
    xfer::{ DnsRequestOptions, RetryDnsHandle,},
};
#[cfg(feature = "dnssec")]
use trust_dns_proto::SecureDnsHandle;

use config::{ResolverConfig, ResolverOpts};
use dns_lru::DnsLru;
use hosts::Hosts;
use lookup::{Lookup, LookupEither, LookupFuture};
use lookup_ip::LookupIpFuture;
use lookup_state::CachingClient;
use name_server_pool::{NameServerPool, StandardConnection};

use super::{BasicAsyncResolver, Request};

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
) -> impl Future<Item = (), Error = ()> {
    future::lazy(move || {
        let pool = NameServerPool::<BasicAsyncResolver, StandardConnection>::from_config(
            &config, &options,
        );
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

        Task {
            config,
            options,
            client_cache: CachingClient::with_cache(lru, either),
            hosts: hosts,
            request_rx,
        }
    })
}

type ClientCache =
    CachingClient<LookupEither<BasicAsyncResolver, StandardConnection>>;

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

    fn lookup_ip(
        &self,
        maybe_name: ProtoResult<Name>,
        maybe_ip: Option<RData>
    ) -> LookupIpFuture {
        let mut finally_ip_addr = None;

        // if host is a ip address, return directly.
        if let Some(ip_addr) = maybe_ip {
            // if ndots are greater than 4, then we can't assume the name is an IpAddr
            //   this accepts IPv6 as well, b/c IPv6 can take the form: 2001:db8::198.51.100.35
            //   but `:` is not a valid DNS character, so techinically this will fail parsing.
            //   TODO: should we always do search before returning this?
            if self.options.ndots > 4 {
                finally_ip_addr = Some(ip_addr);
            } else {
                return LookupIpFuture::ok(
                    self.client_cache.clone(),
                    Lookup::new_with_max_ttl(Arc::new(vec![ip_addr])),
                );
            }
        }

        let name = match (maybe_name, finally_ip_addr.as_ref()) {
            (Ok(name), _) => name,
            (Err(_), Some(ip_addr)) => {
                // it was a valid IP, return that...
                return LookupIpFuture::ok(
                    self.client_cache.clone(),
                    Lookup::new_with_max_ttl(Arc::new(vec![ip_addr.clone()])),
                );
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
            finally_ip_addr,
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
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            let poll = self.request_rx.poll().map_err(|e| {
                error!("AsyncResolver poisoned: {:?}", e);
            });
            match try_ready!(poll) {
                None => {
                    // mpsc::UnboundedReceiver::poll() returns `None` when the sender
                    // has been dropped.
                    trace!("AsyncResolver dropped, shutting down background task.");
                    // Return `Ready` so the background future finishes, as no handles
                    // are using it any longer.
                    return Ok(Async::Ready(()))
                },
                Some(Request::Lookup { name, record_type, options, tx, }) => {
                    let future = self.lookup(name, record_type, options);
                    // tx.send() will return an error if the oneshot was canceled, but
                    // we don't actually care, so just drop the future.
                    let _ = tx.send(future);
                },
                Some(Request::Ip { maybe_name, maybe_ip, tx }) => {
                    let future = self.lookup_ip(maybe_name, maybe_ip);
                    // tx.send() will return an error if the oneshot was canceled, but
                    // we don't actually care, so just drop the future.
                    let _ = tx.send(future);
                },
            }
        }
    }
}
