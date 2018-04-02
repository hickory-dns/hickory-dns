// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! LookupIp result from a resolution of ipv4 and ipv6 records with a Resolver.
//!
//! At it's heart LookupIp uses Lookup for performing all lookups. It is unlike other standard lookups in that there are customizations around A and AAAA resolutions.

use std::error::Error;
use std::mem;
use std::net::IpAddr;
use std::sync::Arc;

use futures::{future, task, Async, Future, Poll};

use trust_dns_proto::op::Query;
use trust_dns_proto::rr::{Name, RData, RecordType};
use trust_dns_proto::xfer::{DnsHandle, DnsRequestOptions};

use config::LookupIpStrategy;
use error::*;
use hosts::Hosts;
use lookup::{Lookup, LookupEither, LookupIter};
use lookup_state::CachingClient;
use name_server_pool::StandardConnection;
use resolver_future::BasicResolverHandle;

/// Result of a DNS query when querying for A or AAAA records.
///
/// When resolving IP records, there can be many IPs that match a given name. A consumer of this should expect that there are more than a single address potentially returned. Generally there are multiple IPs stored for a given service in DNS so that there is a form of high availability offered for a given name. The service implementation is resposible for the seymantics around which IP should be used and when, but in general if a connection fails to one, the next in the list should be attempted.
#[derive(Debug, Clone)]
pub struct LookupIp(Lookup);

impl LookupIp {
    /// Returns a borrowed iterator of the returned IPs
    pub fn iter(&self) -> LookupIpIter {
        LookupIpIter(self.0.iter())
    }
}

impl From<Lookup> for LookupIp {
    fn from(lookup: Lookup) -> Self {
        LookupIp(lookup)
    }
}

/// Borrowed view of set of IPs returned from a LookupIp
pub struct LookupIpIter<'i>(LookupIter<'i>);

impl<'i> Iterator for LookupIpIter<'i> {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        let iter: &mut _ = &mut self.0;
        iter.filter_map(|rdata| match *rdata {
            RData::A(ip) => Some(IpAddr::from(ip)),
            RData::AAAA(ip) => Some(IpAddr::from(ip)),
            _ => None,
        }).next()
    }
}

/// The Future returned from ResolverFuture when performing an A or AAAA lookup.
pub type LookupIpFuture =
    InnerLookupIpFuture<LookupEither<BasicResolverHandle, StandardConnection>>;

#[doc(hidden)]
/// The Future returned from ResolverFuture when performing an A or AAAA lookup.
pub struct InnerLookupIpFuture<C: DnsHandle<Error = ResolveError> + 'static> {
    client_cache: CachingClient<C>,
    names: Vec<Name>,
    strategy: LookupIpStrategy,
    options: DnsRequestOptions,
    future: Box<Future<Item = Lookup, Error = ResolveError>>,
    hosts: Option<Arc<Hosts>>,
}

impl<C: DnsHandle<Error = ResolveError> + 'static> InnerLookupIpFuture<C> {
    /// Perform a lookup from a hostname to a set of IPs
    ///
    /// # Arguments
    ///
    /// * `names` - a set of DNS names to attempt to resolve, they will be attempted in queue order, i.e. the first is `names.pop()`. Upon each failure, the next will be attempted.
    /// * `strategy` - the lookup IP strategy to use
    /// * `client_cache` - cache with a connection to use for performing all lookups
    pub fn lookup(
        mut names: Vec<Name>,
        strategy: LookupIpStrategy,
        client_cache: CachingClient<C>,
        options: DnsRequestOptions,
        hosts: Option<Arc<Hosts>>,
    ) -> Self {
        let name = names.pop().ok_or_else(|| {
            ResolveError::from(ResolveErrorKind::Message("can not lookup IPs for no names"))
        });

        let query: Box<Future<Item = Lookup, Error = ResolveError>> = match name {
            Ok(name) => strategic_lookup(
                name,
                strategy,
                client_cache.clone(),
                options.clone(),
                hosts.clone(),
            ),
            Err(err) => Box::new(future::err(err)),
        };

        InnerLookupIpFuture {
            client_cache: client_cache,
            names,
            strategy,
            options,
            future: query,
            hosts: hosts,
        }
    }

    fn next_lookup<F: FnOnce() -> Poll<LookupIp, ResolveError>>(
        &mut self,
        otherwise: F,
    ) -> Poll<LookupIp, ResolveError> {
        let name = self.names.pop();
        if let Some(name) = name {
            let query = strategic_lookup(
                name,
                self.strategy,
                self.client_cache.clone(),
                self.options.clone(),
                self.hosts.clone(),
            );

            mem::replace(&mut self.future, Box::new(query));
            // guarantee that we get scheduled for the next turn...
            task::current().notify();
            Ok(Async::NotReady)
        } else {
            otherwise()
        }
    }

    pub(crate) fn error<E: Error>(client_cache: CachingClient<C>, error: E) -> Self {
        return InnerLookupIpFuture {
            // errors on names don't need to be cheap... i.e. this clone is unfortunate in this case.
            client_cache,
            names: vec![],
            strategy: LookupIpStrategy::default(),
            options: DnsRequestOptions::default(),
            future: Box::new(future::err(
                ResolveErrorKind::Msg(format!("{}", error)).into(),
            )),
            hosts: None,
        };
    }

    pub(crate) fn ok(client_cache: CachingClient<C>, lp: Lookup) -> Self {
        return InnerLookupIpFuture {
            client_cache,
            names: vec![],
            strategy: LookupIpStrategy::default(),
            options: DnsRequestOptions::default(),
            future: Box::new(future::ok(lp)),
            hosts: None,
        };
    }
}

impl<C: DnsHandle<Error = ResolveError> + 'static> Future for InnerLookupIpFuture<C> {
    type Item = LookupIp;
    type Error = ResolveError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.future.poll() {
            Ok(Async::Ready(lookup)) => if lookup.is_empty() {
                return self.next_lookup(|| Ok(Async::Ready(LookupIp::from(lookup))));
            } else {
                return Ok(Async::Ready(LookupIp::from(lookup)));
            },
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(e) => {
                return self.next_lookup(|| Err(e));
            }
        }
    }
}

/// returns a new future for lookup
fn strategic_lookup<C: DnsHandle<Error = ResolveError> + 'static>(
    name: Name,
    strategy: LookupIpStrategy,
    client: CachingClient<C>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Box<Future<Item = Lookup, Error = ResolveError>> {
    match strategy {
        LookupIpStrategy::Ipv4Only => ipv4_only(name, client, options, hosts),
        LookupIpStrategy::Ipv6Only => ipv6_only(name, client, options, hosts),
        LookupIpStrategy::Ipv4AndIpv6 => ipv4_and_ipv6(name, client, options, hosts),
        LookupIpStrategy::Ipv6thenIpv4 => ipv6_then_ipv4(name, client, options, hosts),
        LookupIpStrategy::Ipv4thenIpv6 => ipv4_then_ipv6(name, client, options, hosts),
    }
}

/// first lookups in hosts, then performs the query
fn hosts_lookup<C: DnsHandle<Error = ResolveError> + 'static>(
    query: Query,
    mut client: CachingClient<C>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Box<Future<Item = Lookup, Error = ResolveError>> {
    if let Some(hosts) = hosts {
        if let Some(lookup) = hosts.lookup_static_host(&query) {
            return Box::new(future::ok(lookup));
        };
    }

    // TODO: consider making the client.lookup lazily evaluated
    client.lookup(query, options)
}

/// queries only for A records
fn ipv4_only<C: DnsHandle<Error = ResolveError> + 'static>(
    name: Name,
    client: CachingClient<C>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Box<Future<Item = Lookup, Error = ResolveError>> {
    hosts_lookup(Query::query(name, RecordType::A), client, options, hosts)
}

/// queries only for AAAA records
fn ipv6_only<C: DnsHandle<Error = ResolveError> + 'static>(
    name: Name,
    client: CachingClient<C>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Box<Future<Item = Lookup, Error = ResolveError>> {
    hosts_lookup(Query::query(name, RecordType::AAAA), client, options, hosts)
}

/// queries only for A and AAAA in parallel
fn ipv4_and_ipv6<C: DnsHandle<Error = ResolveError> + 'static>(
    name: Name,
    client: CachingClient<C>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Box<Future<Item = Lookup, Error = ResolveError>> {
    Box::new(
        hosts_lookup(
            Query::query(name.clone(), RecordType::A),
            client.clone(),
            options.clone(),
            hosts.clone(),
        ).select(hosts_lookup(
            Query::query(name, RecordType::AAAA),
            client,
            options,
            hosts,
        ))
            .then(|sel_res| {
                match sel_res {
                    // Some ips returned, get the other record result, or else just return record
                    Ok((ips, remaining_query)) => {
                        Box::new(remaining_query.then(move |query_res| match query_res {
                            // join AAAA and A results
                            Ok(rem_ips) => {
                                // TODO: create a LookupIp enum with the ability to chain these together
                                let ips = ips.append(rem_ips);
                                future::ok(ips)
                            }
                            // One failed, just return the other
                            Err(_) => future::ok(ips),
                        })) as
                            // This cast is to resolve a comilation error, not sure of it's necessity
                            Box<Future<Item = Lookup, Error = ResolveError>>
                    }

                    // One failed, just return the other
                    Err((_, remaining_query)) => Box::new(remaining_query),
                }
            }),
    )
}

/// queries only for AAAA and on no results queries for A
fn ipv6_then_ipv4<C: DnsHandle<Error = ResolveError> + 'static>(
    name: Name,
    client: CachingClient<C>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Box<Future<Item = Lookup, Error = ResolveError>> {
    rt_then_swap(
        name,
        client,
        RecordType::AAAA,
        RecordType::A,
        options,
        hosts,
    )
}

/// queries only for A and on no results queries for AAAA
fn ipv4_then_ipv6<C: DnsHandle<Error = ResolveError> + 'static>(
    name: Name,
    client: CachingClient<C>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Box<Future<Item = Lookup, Error = ResolveError>> {
    rt_then_swap(
        name,
        client,
        RecordType::A,
        RecordType::AAAA,
        options,
        hosts,
    )
}

/// queries only for first_type and on no results queries for second_type
fn rt_then_swap<C: DnsHandle<Error = ResolveError> + 'static>(
    name: Name,
    client: CachingClient<C>,
    first_type: RecordType,
    second_type: RecordType,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Box<Future<Item = Lookup, Error = ResolveError>> {
    let or_client = client.clone();
    Box::new(
        hosts_lookup(
            Query::query(name.clone(), first_type),
            client,
            options.clone(),
            hosts.clone(),
        ).then(move |res| {
            match res {
                Ok(ips) => {
                    if ips.is_empty() {
                        // no ips returns, NXDomain or Otherwise, doesn't matter
                        Box::new(hosts_lookup(
                            Query::query(name.clone(), second_type),
                            or_client,
                            options,
                            hosts,
                        ))
                            as Box<Future<Item = Lookup, Error = ResolveError>>
                    } else {
                        Box::new(future::ok(ips))
                            as Box<Future<Item = Lookup, Error = ResolveError>>
                    }
                }
                Err(_) => Box::new(hosts_lookup(
                    Query::query(name.clone(), second_type),
                    or_client,
                    options,
                    hosts,
                )),
            }
        }),
    )
}

#[cfg(test)]
pub mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};

    use futures::{future, Future};

    //use trust_dns_proto::error::*;
    use trust_dns_proto::op::Message;
    use trust_dns_proto::rr::{Name, RData, Record, RecordType};
    use trust_dns_proto::xfer::{DnsHandle, DnsRequest};

    use super::*;

    #[derive(Clone)]
    pub struct MockDnsHandle {
        messages: Arc<Mutex<Vec<ResolveResult<Message>>>>,
    }

    impl DnsHandle for MockDnsHandle {
        type Error = ResolveError;

        fn send<R: Into<DnsRequest>>(
            &mut self,
            _: R,
        ) -> Box<Future<Item = Message, Error = Self::Error>> {
            Box::new(future::result(
                self.messages.lock().unwrap().pop().unwrap_or(empty()),
            ))
        }
    }

    pub fn v4_message() -> ResolveResult<Message> {
        let mut message = Message::new();
        message.insert_answers(vec![
            Record::from_rdata(
                Name::root(),
                86400,
                RecordType::A,
                RData::A(Ipv4Addr::new(127, 0, 0, 1)),
            ),
        ]);
        Ok(message)
    }

    pub fn v6_message() -> ResolveResult<Message> {
        let mut message = Message::new();
        message.insert_answers(vec![
            Record::from_rdata(
                Name::root(),
                86400,
                RecordType::AAAA,
                RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ),
        ]);
        Ok(message)
    }

    pub fn empty() -> ResolveResult<Message> {
        Ok(Message::new())
    }

    pub fn error() -> ResolveResult<Message> {
        Err(ResolveErrorKind::Message("forced test failure").into())
    }

    pub fn mock(messages: Vec<ResolveResult<Message>>) -> MockDnsHandle {
        MockDnsHandle {
            messages: Arc::new(Mutex::new(messages)),
        }
    }

    #[test]
    fn test_ipv4_only_strategy() {
        assert_eq!(
            ipv4_only(
                Name::root(),
                CachingClient::new(0, mock(vec![v4_message()])),
                Default::default(),
                None,
            ).wait()
                .unwrap()
                .iter()
                .map(|r| r.to_ip_addr().unwrap())
                .collect::<Vec<IpAddr>>(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );
    }

    #[test]
    fn test_ipv6_only_strategy() {
        assert_eq!(
            ipv6_only(
                Name::root(),
                CachingClient::new(0, mock(vec![v6_message()])),
                Default::default(),
                None,
            ).wait()
                .unwrap()
                .iter()
                .map(|r| r.to_ip_addr().unwrap())
                .collect::<Vec<IpAddr>>(),
            vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)]
        );
    }

    #[test]
    fn test_ipv4_and_ipv6_strategy() {
        // ipv6 is consistently queried first (even though the select has it second)
        // both succeed
        assert_eq!(
            ipv4_and_ipv6(
                Name::root(),
                CachingClient::new(0, mock(vec![v6_message(), v4_message()])),
                Default::default(),
                None,
            ).wait()
                .unwrap()
                .iter()
                .map(|r| r.to_ip_addr().unwrap())
                .collect::<Vec<IpAddr>>(),
            vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ]
        );

        // only ipv4 available
        assert_eq!(
            ipv4_and_ipv6(
                Name::root(),
                CachingClient::new(0, mock(vec![empty(), v4_message()])),
                Default::default(),
                None,
            ).wait()
                .unwrap()
                .iter()
                .map(|r| r.to_ip_addr().unwrap())
                .collect::<Vec<IpAddr>>(),
            vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]
        );

        // error then ipv4
        assert_eq!(
            ipv4_and_ipv6(
                Name::root(),
                CachingClient::new(0, mock(vec![error(), v4_message()])),
                Default::default(),
                None,
            ).wait()
                .unwrap()
                .iter()
                .map(|r| r.to_ip_addr().unwrap())
                .collect::<Vec<IpAddr>>(),
            vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]
        );

        // only ipv6 available
        assert_eq!(
            ipv4_and_ipv6(
                Name::root(),
                CachingClient::new(0, mock(vec![v6_message(), empty()])),
                Default::default(),
                None,
            ).wait()
                .unwrap()
                .iter()
                .map(|r| r.to_ip_addr().unwrap())
                .collect::<Vec<IpAddr>>(),
            vec![IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]
        );

        // error, then only ipv6 available
        assert_eq!(
            ipv4_and_ipv6(
                Name::root(),
                CachingClient::new(0, mock(vec![v6_message(), error()])),
                Default::default(),
                None,
            ).wait()
                .unwrap()
                .iter()
                .map(|r| r.to_ip_addr().unwrap())
                .collect::<Vec<IpAddr>>(),
            vec![IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]
        );
    }

    #[test]
    fn test_ipv6_then_ipv4_strategy() {
        // ipv6 first
        assert_eq!(
            ipv6_then_ipv4(
                Name::root(),
                CachingClient::new(0, mock(vec![v6_message()])),
                Default::default(),
                None,
            ).wait()
                .unwrap()
                .iter()
                .map(|r| r.to_ip_addr().unwrap())
                .collect::<Vec<IpAddr>>(),
            vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)]
        );

        // nothing then ipv4
        assert_eq!(
            ipv6_then_ipv4(
                Name::root(),
                CachingClient::new(0, mock(vec![v4_message(), empty()])),
                Default::default(),
                None,
            ).wait()
                .unwrap()
                .iter()
                .map(|r| r.to_ip_addr().unwrap())
                .collect::<Vec<IpAddr>>(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );

        // ipv4 and error
        assert_eq!(
            ipv6_then_ipv4(
                Name::root(),
                CachingClient::new(0, mock(vec![v4_message(), error()])),
                Default::default(),
                None,
            ).wait()
                .unwrap()
                .iter()
                .map(|r| r.to_ip_addr().unwrap())
                .collect::<Vec<IpAddr>>(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );
    }

    #[test]
    fn test_ipv4_then_ipv6_strategy() {
        // ipv6 first
        assert_eq!(
            ipv4_then_ipv6(
                Name::root(),
                CachingClient::new(0, mock(vec![v4_message()])),
                Default::default(),
                None,
            ).wait()
                .unwrap()
                .iter()
                .map(|r| r.to_ip_addr().unwrap())
                .collect::<Vec<IpAddr>>(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );

        // nothing then ipv6
        assert_eq!(
            ipv4_then_ipv6(
                Name::root(),
                CachingClient::new(0, mock(vec![v6_message(), empty()])),
                Default::default(),
                None,
            ).wait()
                .unwrap()
                .iter()
                .map(|r| r.to_ip_addr().unwrap())
                .collect::<Vec<IpAddr>>(),
            vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)]
        );

        // error then ipv6
        assert_eq!(
            ipv4_then_ipv6(
                Name::root(),
                CachingClient::new(0, mock(vec![v6_message(), error()])),
                Default::default(),
                None,
            ).wait()
                .unwrap()
                .iter()
                .map(|r| r.to_ip_addr().unwrap())
                .collect::<Vec<IpAddr>>(),
            vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)]
        );
    }
}
