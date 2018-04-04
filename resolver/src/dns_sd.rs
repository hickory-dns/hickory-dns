// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNS Service Discovery

#![cfg(feature = "mdns")]

use futures::{Async, Future, Poll};
use tokio_core::reactor::Core;

use trust_dns_proto::rr::{IntoName, Name, RecordType};
use trust_dns_proto::xfer::DnsRequestOptions;

use error::*;
use lookup::{InnerLookupFuture, LookupFuture, ReverseLookup, ReverseLookupFuture,
             ReverseLookupIter, TxtLookup, TxtLookupFuture, TxtLookupIter};
use resolver_future::ResolverFuture;

/// An extension for the Resolver to perform DNS Service Discovery
pub trait DnsSdFuture {
    /// List all services available
    ///
    /// https://tools.ietf.org/html/rfc6763#section-4.1
    ///
    /// For registered service types, see: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
    ///
    /// # Arguments
    ///
    /// * `service` - the type of service to be looked up, eg `http`
    /// * `protocol` - the protocol used for these services, eg `tcp`
    /// * `domain` - the domain in which the search will be done, eg `local.`
    fn list_services(&self, service: &str, protocol: &str, domain: &str) -> ListServicesFuture;

    /// Retrieve service information
    ///
    /// https://tools.ietf.org/html/rfc6763#section-6
    fn service_info<N: IntoName>(&self, name: N) -> ServiceInfoFuture;
}

impl DnsSdFuture for ResolverFuture {
    fn list_services(&self, service: &str, protocol: &str, domain: &str) -> ListServicesFuture {
        let name = format!("_{}._{}.{}", service, protocol, domain);
        let options = DnsRequestOptions {
            expects_multiple_responses: true,
            ..Default::default()
        };
        let name: Name = match name.into_name() {
            Ok(name) => name,
            Err(err) => {
                return ListServicesFuture(ReverseLookupFuture::from(InnerLookupFuture::error(
                    self.client_cache.clone(),
                    err,
                )));
            }
        };

        let ptr_future: LookupFuture = self.inner_lookup(name, RecordType::PTR, options);
        let ptr_future: ReverseLookupFuture = ptr_future.into();

        ListServicesFuture(ptr_future)
    }

    fn service_info<N: IntoName>(&self, name: N) -> ServiceInfoFuture {
        let txt_future: TxtLookupFuture = self.txt_lookup(name);
        panic!();
    }
}

/// A DNS Service Discovery future of Services discovered through the list operation
pub struct ListServicesFuture(ReverseLookupFuture);

impl Future for ListServicesFuture {
    type Item = ListServices;
    type Error = ResolveError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.0.poll() {
            Ok(Async::Ready(lookup)) => Ok(Async::Ready(ListServices(lookup))),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(e) => Err(e),
        }
    }
}

/// The list of Services discovered
pub struct ListServices(ReverseLookup);

impl ListServices {
    /// Returns an iterator over the list of returned names of services.
    ///
    /// Each name can be queried for additional information. To lookup service entries see `ResolverFuture::srv_lookup`. To get parameters associated with the service, see `DnsSdFuture::service_info`.
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
pub struct ServiceInfoFuture(TxtLookupFuture);

impl Future for ServiceInfoFuture {
    type Item = ServiceInfo;
    type Error = ResolveError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.0.poll() {
            Ok(Async::Ready(lookup)) => {
                panic!();

                //Ok(Async::Ready(ServiceInfo(lookup)))
            }
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(e) => Err(e),
        }
    }
}

/// The list of Services discovered
pub struct ServiceInfo(TxtLookup);

impl ServiceInfo {
    /// Returns an iterator over the list of returned names of services.
    ///
    /// Each name can be queried for additional information. To lookup service entries see `ResolverFuture::srv_lookup`. To get parameters associated with the service, see `DnsSdFuture::service_info`.
    pub fn iter(&self) -> ServiceInfoIter {
        ServiceInfoIter(self.0.iter())
    }
}

/// An iterator over the Lookup type
pub struct ServiceInfoIter<'i>(TxtLookupIter<'i>);

impl<'i> Iterator for ServiceInfoIter<'i> {
    type Item = &'i [u8];

    fn next(&mut self) -> Option<Self::Item> {
        panic!()
    }
}

#[cfg(test)]
mod tests {
    use config::*;

    use super::*;

    #[test]
    #[ignore]
    fn test_list_services() {
        let mut io_loop = Core::new().unwrap();
        let resolver = ResolverFuture::new(
            ResolverConfig::default(),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv6thenIpv4,
                ..ResolverOpts::default()
            },
            &io_loop.handle(),
        );

        let response = io_loop
            .run(resolver.list_services("http", "tcp", "local"))
            .expect("failed to run lookup");

        let mut iter = response.iter();
        for i in iter {
            println!("service: {}", i);
        }
    }
}
