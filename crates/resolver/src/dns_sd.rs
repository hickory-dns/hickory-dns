// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNS Service Discovery
#![cfg(feature = "mdns")]

use std::borrow::Cow;
use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::future::Future;

use proto::rr::rdata::TXT;
use proto::rr::{Name, RecordType};
use proto::xfer::DnsRequestOptions;
use proto::DnsHandle;

use crate::error::*;
use crate::lookup::{ReverseLookup, ReverseLookupIter, TxtLookup};
use crate::name_server::ConnectionProvider;
use crate::AsyncResolver;

/// An extension for the Resolver to perform DNS Service Discovery
pub trait DnsSdHandle {
    /// List all services available
    ///
    /// <https://tools.ietf.org/html/rfc6763#section-4.1>
    ///
    /// For registered service types, see: <https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml>
    fn list_services(&self, name: Name) -> ListServicesFuture;

    /// Retrieve service information
    ///
    /// <https://tools.ietf.org/html/rfc6763#section-6>
    fn service_info(&self, name: Name) -> ServiceInfoFuture;
}

impl<C: DnsHandle<Error = ResolveError>, P: ConnectionProvider<Conn = C>> DnsSdHandle
    for AsyncResolver<C, P>
{
    fn list_services(&self, name: Name) -> ListServicesFuture {
        let this = self.clone();

        let ptr_future = async move {
            let mut options = DnsRequestOptions::default();
            options.expects_multiple_responses = true;
            // TODO: This should use the AsyncResolver's options.edns0
            // setting, but options is private.
            options.use_edns = false;

            this.inner_lookup(name, RecordType::PTR, options).await
        };

        ListServicesFuture(Box::pin(ptr_future))
    }

    fn service_info(&self, name: Name) -> ServiceInfoFuture {
        let this = self.clone();

        let ptr_future = async move { this.txt_lookup(name).await };

        ServiceInfoFuture(Box::pin(ptr_future))
    }
}

/// A DNS Service Discovery future of Services discovered through the list operation
pub struct ListServicesFuture(
    Pin<Box<dyn Future<Output = Result<ReverseLookup, ResolveError>> + Send + 'static>>,
);

impl Future for ListServicesFuture {
    type Output = Result<ListServices, ResolveError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.0.as_mut().poll(cx) {
            Poll::Ready(Ok(lookup)) => Poll::Ready(Ok(ListServices(lookup))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

/// The list of Services discovered
pub struct ListServices(ReverseLookup);

impl ListServices {
    /// Returns an iterator over the list of returned names of services.
    ///
    /// Each name can be queried for additional information. To lookup service entries see [AsyncResolver::lookup_srv(..)]. To get parameters associated with the service, see `DnsSdFuture::service_info`.
    pub fn iter(&self) -> ListServicesIter<'_> {
        ListServicesIter(self.0.iter())
    }
}

/// An iterator over the Lookup type
pub struct ListServicesIter<'i>(ReverseLookupIter<'i>);

impl<'i> Iterator for ListServicesIter<'i> {
    type Item = &'i Name;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

/// A Future that resolves to the TXT information for a service
pub struct ServiceInfoFuture(
    Pin<Box<dyn Future<Output = Result<TxtLookup, ResolveError>> + Send + 'static>>,
);

impl Future for ServiceInfoFuture {
    type Output = Result<ServiceInfo, ResolveError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.0.as_mut().poll(cx) {
            Poll::Ready(Ok(lookup)) => Poll::Ready(Ok(ServiceInfo(lookup))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

/// The list of Services discovered
pub struct ServiceInfo(TxtLookup);

impl ServiceInfo {
    /// Returns this as a map, this allocates a new hashmap
    ///
    /// This converts the DNS-SD TXT record into a map following the rules specified in <https://tools.ietf.org/html/rfc6763#section-6.4>
    pub fn to_map(&self) -> HashMap<Cow<'_, str>, Option<Cow<'_, str>>> {
        self.0
            .iter()
            .flat_map(TXT::iter)
            .filter_map(|bytes| {
                let mut split = bytes.split(|byte| *byte == b'=');

                let key = split.next().map(String::from_utf8_lossy);
                let value = split.next().map(String::from_utf8_lossy);

                if let Some(key) = key {
                    Some((key, value))
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use std::str::FromStr;
    use tokio::runtime::Runtime;

    use crate::config::*;
    use crate::{TokioAsyncResolver, TokioHandle};

    use super::*;

    #[test]
    #[ignore]
    fn test_list_services() {
        let io_loop = Runtime::new().unwrap();
        let resolver = TokioAsyncResolver::new(
            ResolverConfig::default(),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv6thenIpv4,
                ..ResolverOpts::default()
            },
            TokioHandle,
        )
        .expect("failed to create resolver");

        let response = io_loop
            .block_on(resolver.list_services(Name::from_str("_http._tcp.local.").unwrap()))
            .expect("failed to run lookup");

        for name in response.iter() {
            println!("service: {}", name);
            let srvs = io_loop
                .block_on(resolver.srv_lookup(name.clone()))
                .expect("failed to lookup name");

            for srv in srvs.iter() {
                println!("service: {:#?}", srv);

                let info = io_loop
                    .block_on(resolver.service_info(name.clone()))
                    .expect("info failed");
                let info = info.to_map();
                println!("info: {:#?}", info);
            }

            for ip in srvs.ip_iter() {
                println!("ip: {}", ip);
            }
        }
    }
}
