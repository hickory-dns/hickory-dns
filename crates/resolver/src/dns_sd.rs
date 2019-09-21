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

use futures::{Async, Future, Poll};

use proto::rr::rdata::TXT;
use proto::rr::{IntoName, Name, RecordType};
use proto::xfer::DnsRequestOptions;

use async_resolver::{AsyncResolver, BackgroundLookup};
use error::*;
use lookup::{ReverseLookup, ReverseLookupFuture, ReverseLookupIter, TxtLookup, TxtLookupFuture};

/// An extension for the Resolver to perform DNS Service Discovery
pub trait DnsSdHandle {
    /// List all services available
    ///
    /// https://tools.ietf.org/html/rfc6763#section-4.1
    ///
    /// For registered service types, see: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
    fn list_services<N: IntoName>(&self, name: N) -> ListServicesFuture;

    /// Retrieve service information
    ///
    /// https://tools.ietf.org/html/rfc6763#section-6
    fn service_info<N: IntoName>(&self, name: N) -> ServiceInfoFuture;
}

impl DnsSdHandle for AsyncResolver {
    fn list_services<N: IntoName>(&self, name: N) -> ListServicesFuture {
        let options = DnsRequestOptions {
            expects_multiple_responses: true,
        };

        let name: Name = match name.into_name() {
            Ok(name) => name,
            Err(err) => return ListServicesFuture(err.into()),
        };

        let ptr_future: BackgroundLookup<ReverseLookupFuture> =
            self.inner_lookup(name, RecordType::PTR, options);

        ListServicesFuture(ptr_future)
    }

    fn service_info<N: IntoName>(&self, name: N) -> ServiceInfoFuture {
        let txt_future = self.txt_lookup(name);
        ServiceInfoFuture(txt_future)
    }
}

/// A DNS Service Discovery future of Services discovered through the list operation
pub struct ListServicesFuture(BackgroundLookup<ReverseLookupFuture>);

impl Future for ListServicesFuture {
    type Item = ListServices;
    type Error = ResolveError;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match self.0.poll(cx) {
            Poll::Ready(Ok(lookup)) => Poll::Ready(Ok(ListServices(lookup))),
            Poll::Pending => Poll::Pending,
            Err(e) => Err(e),
        }
    }
}

/// The list of Services discovered
pub struct ListServices(ReverseLookup);

impl ListServices {
    /// Returns an iterator over the list of returned names of services.
    ///
    /// Each name can be queried for additional information. To lookup service entries see [`AsyncResolver::lookup_srv`]. To get parameters associated with the service, see `DnsSdFuture::service_info`.
    pub fn iter(&self) -> ListServicesIter {
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
pub struct ServiceInfoFuture(BackgroundLookup<TxtLookupFuture>);

impl Future for ServiceInfoFuture {
    type Item = ServiceInfo;
    type Error = ResolveError;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match self.0.poll(cx) {
            Poll::Ready(Ok(lookup)) => Poll::Ready(Ok(ServiceInfo(lookup))),
            Poll::Pending => Poll::Pending,
            Err(e) => Err(e),
        }
    }
}

/// The list of Services discovered
pub struct ServiceInfo(TxtLookup);

impl ServiceInfo {
    /// Returns this as a map, this allocates a new hashmap
    ///
    /// This converts the DNS-SD TXT record into a map following the rules specified in https://tools.ietf.org/html/rfc6763#section-6.4
    pub fn to_map<'s>(&'s self) -> HashMap<Cow<'s, str>, Option<Cow<'s, str>>> {
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
    use tokio::runtime::current_thread::Runtime;

    use config::*;

    use super::*;

    #[test]
    #[ignore]
    fn test_list_services() {
        let mut io_loop = Runtime::new().unwrap();
        let (resolver, bg) = AsyncResolver::new(
            ResolverConfig::default(),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv6thenIpv4,
                ..ResolverOpts::default()
            },
        );

        io_loop.spawn(bg);

        let response = io_loop
            .block_on(resolver.list_services("_http._tcp.local."))
            .expect("failed to run lookup");

        for name in response.iter() {
            println!("service: {}", name);
            let srvs = io_loop
                .block_on(resolver.lookup_srv(name.clone()))
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
