// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! LookupIp result from a resolution of ipv4 and ipv6 records with a Resolver.
//!
//! At it's heart LookupIp uses Lookup for performing all lookups. It is unlike other standard lookups in that there are customizations around A and AAAA resolutions.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use failure::Fail;

use futures::{future, Async, Future, Poll};

use proto::op::Query;
use proto::rr::{Name, RData, Record, RecordType};
use proto::xfer::{DnsHandle, DnsRequestOptions};

use config::LookupIpStrategy;
use dns_lru::MAX_TTL;
use error::*;
use hosts::Hosts;
use lookup::{Lookup, LookupEither, LookupIntoIter, LookupIter};
use lookup_state::CachingClient;
use name_server::{ConnectionHandle, StandardConnection};

/// Result of a DNS query when querying for A or AAAA records.
///
/// When resolving IP records, there can be many IPs that match a given name. A consumer of this should expect that there are more than a single address potentially returned. Generally there are multiple IPs stored for a given service in DNS so that there is a form of high availability offered for a given name. The service implementation is resposible for the semantics around which IP should be used and when, but in general if a connection fails to one, the next in the list should be attempted.
#[derive(Debug, Clone)]
pub struct LookupIp(Lookup);

impl LookupIp {
    /// Returns a borrowed iterator of the returned IPs
    pub fn iter(&self) -> LookupIpIter {
        LookupIpIter(self.0.iter())
    }

    /// Returns a reference to the Query that was used to produce this result.
    pub fn query(&self) -> &Query {
        self.0.query()
    }

    /// Returns the `Instant` at which this lookup is no longer valid.
    pub fn valid_until(&self) -> Instant {
        self.0.valid_until()
    }
}

impl From<Lookup> for LookupIp {
    fn from(lookup: Lookup) -> Self {
        LookupIp(lookup)
    }
}

/// Borrowed view of set of IPs returned from a LookupIp
pub struct LookupIpIter<'i>(pub(crate) LookupIter<'i>);

impl<'i> Iterator for LookupIpIter<'i> {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        let iter: &mut _ = &mut self.0;
        iter.filter_map(|rdata| match *rdata {
            RData::A(ip) => Some(IpAddr::from(ip)),
            RData::AAAA(ip) => Some(IpAddr::from(ip)),
            _ => None,
        })
        .next()
    }
}

impl IntoIterator for LookupIp {
    type Item = IpAddr;
    type IntoIter = LookupIpIntoIter;

    /// This is most likely not a free conversion, the RDatas will be cloned if data is
    ///  held behind an Arc with more than one reference (which is most likely the case coming from cache)
    fn into_iter(self) -> Self::IntoIter {
        LookupIpIntoIter(self.0.into_iter())
    }
}

/// Borrowed view of set of RDatas returned from a Lookup
pub struct LookupIpIntoIter(LookupIntoIter);

impl Iterator for LookupIpIntoIter {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        let iter: &mut _ = &mut self.0;
        iter.filter_map(|rdata| match rdata {
            RData::A(ip) => Some(IpAddr::from(ip)),
            RData::AAAA(ip) => Some(IpAddr::from(ip)),
            _ => None,
        })
        .next()
    }
}

/// The Future returned from ResolverFuture when performing an A or AAAA lookup.
///
/// This type isn't necessarily something that should be used by users, see the default TypeParameters are generally correct
pub struct LookupIpFuture<C = LookupEither<ConnectionHandle, StandardConnection>>
where
    C: DnsHandle + 'static,
{
    client_cache: CachingClient<C>,
    names: Vec<Name>,
    strategy: LookupIpStrategy,
    options: DnsRequestOptions,
    query: Box<Future<Item = Lookup, Error = ResolveError> + Send>,
    hosts: Option<Arc<Hosts>>,
    finally_ip_addr: Option<RData>,
}

impl<C: DnsHandle + 'static> Future for LookupIpFuture<C> {
    type Item = LookupIp;
    type Error = ResolveError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            // Try polling the underlying DNS query.
            let query = self.query.poll();

            // Determine whether or not we will attempt to retry the query.
            let should_retry = match query {
                // If the query is NotReady, yield immediately.
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                // If the query returned a successful lookup, we will attempt
                // to retry if the lookup is empty. Otherwise, we will return
                // that lookup.
                Ok(Async::Ready(ref lookup)) => lookup.is_empty(),
                // If the query failed, we will attempt to retry.
                Err(_) => true,
            };

            if should_retry {
                if let Some(name) = self.names.pop() {
                    // If there's another name left to try, build a new query
                    // for that next name and continue looping.
                    self.query = strategic_lookup(
                        name,
                        self.strategy,
                        self.client_cache.clone(),
                        self.options.clone(),
                        self.hosts.clone(),
                    );
                    // Continue looping with the new query. It will be polled
                    // on the next iteration of the loop.
                    continue;
                } else if let Some(ip_addr) = self.finally_ip_addr.take() {
                    // Otherwise, if there's an IP address to fall back to,
                    // we'll return it.
                    let record = Record::from_rdata(Name::new(), MAX_TTL, ip_addr);
                    let lookup = Lookup::new_with_max_ttl(Query::new(), Arc::new(vec![record]));
                    return Ok(Async::Ready(lookup.into()));
                }
            };

            // If we didn't have to retry the query, or we weren't able to
            // retry because we've exhausted the names to search and have no
            // fallback IP address, return the current query.
            return query.map(|async| async.map(LookupIp::from));
            // If we skipped retrying the  query, this will return the
            // successful lookup, otherwise, if the retry failed, this will
            // return the last  query result --- either an empty lookup or the
            // last error we saw.
        }
    }
}

impl<C> LookupIpFuture<C>
where
    C: DnsHandle + 'static,
{
    /// Perform a lookup from a hostname to a set of IPs
    ///
    /// # Arguments
    ///
    /// * `names` - a set of DNS names to attempt to resolve, they will be attempted in queue order, i.e. the first is `names.pop()`. Upon each failure, the next will be attempted.
    /// * `strategy` - the lookup IP strategy to use
    /// * `client_cache` - cache with a connection to use for performing all lookups
    pub fn lookup(
        names: Vec<Name>,
        strategy: LookupIpStrategy,
        client_cache: CachingClient<C>,
        options: DnsRequestOptions,
        hosts: Option<Arc<Hosts>>,
        finally_ip_addr: Option<RData>,
    ) -> Self {
        let empty =
            ResolveError::from(ResolveErrorKind::Message("can not lookup IPs for no names"));
        LookupIpFuture {
            names,
            strategy,
            client_cache,
            // If there are no names remaining, this will be returned immediately,
            // otherwise, it will be retried.
            query: Box::new(future::err(empty)),
            options,
            hosts,
            finally_ip_addr,
        }
    }

    pub(crate) fn error<E: Fail>(client_cache: CachingClient<C>, error: E) -> Self {
        LookupIpFuture {
            // errors on names don't need to be cheap... i.e. this clone is unfortunate in this case.
            client_cache,
            names: vec![],
            strategy: LookupIpStrategy::default(),
            options: DnsRequestOptions::default(),
            query: Box::new(future::err(
                ResolveErrorKind::Msg(format!("{}", error)).into(),
            )),
            hosts: None,
            finally_ip_addr: None,
        }
    }

    pub(crate) fn ok(client_cache: CachingClient<C>, lp: Lookup) -> Self {
        LookupIpFuture {
            client_cache,
            names: vec![],
            strategy: LookupIpStrategy::default(),
            options: DnsRequestOptions::default(),
            query: Box::new(future::ok(lp)),
            hosts: None,
            finally_ip_addr: None,
        }
    }
}
/// returns a new future for lookup
fn strategic_lookup<C: DnsHandle + 'static>(
    name: Name,
    strategy: LookupIpStrategy,
    client: CachingClient<C>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Box<Future<Item = Lookup, Error = ResolveError> + Send> {
    match strategy {
        LookupIpStrategy::Ipv4Only => ipv4_only(name, client, options, hosts),
        LookupIpStrategy::Ipv6Only => ipv6_only(name, client, options, hosts),
        LookupIpStrategy::Ipv4AndIpv6 => ipv4_and_ipv6(name, client, options, hosts),
        LookupIpStrategy::Ipv6thenIpv4 => ipv6_then_ipv4(name, client, options, hosts),
        LookupIpStrategy::Ipv4thenIpv6 => ipv4_then_ipv6(name, client, options, hosts),
    }
}

/// first lookups in hosts, then performs the query
fn hosts_lookup<C: DnsHandle + 'static>(
    query: Query,
    mut client: CachingClient<C>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Box<Future<Item = Lookup, Error = ResolveError> + Send> {
    if let Some(hosts) = hosts {
        if let Some(lookup) = hosts.lookup_static_host(&query) {
            return Box::new(future::ok(lookup));
        };
    }

    // TODO: consider making the client.lookup lazily evaluated
    client.lookup(query, options)
}

/// queries only for A records
fn ipv4_only<C: DnsHandle + 'static>(
    name: Name,
    client: CachingClient<C>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Box<Future<Item = Lookup, Error = ResolveError> + Send> {
    hosts_lookup(Query::query(name, RecordType::A), client, options, hosts)
}

/// queries only for AAAA records
fn ipv6_only<C: DnsHandle + 'static>(
    name: Name,
    client: CachingClient<C>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Box<Future<Item = Lookup, Error = ResolveError> + Send> {
    hosts_lookup(Query::query(name, RecordType::AAAA), client, options, hosts)
}

/// queries only for A and AAAA in parallel
fn ipv4_and_ipv6<C: DnsHandle + 'static>(
    name: Name,
    client: CachingClient<C>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Box<Future<Item = Lookup, Error = ResolveError> + Send> {
    Box::new(
        hosts_lookup(
            Query::query(name.clone(), RecordType::A),
            client.clone(),
            options.clone(),
            hosts.clone(),
        )
        .select(hosts_lookup(
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
                            Box<Future<Item = Lookup, Error = ResolveError> + Send>
                }

                // One failed, just return the other
                Err((_, remaining_query)) => Box::new(remaining_query),
            }
        }),
    )
}

/// queries only for AAAA and on no results queries for A
fn ipv6_then_ipv4<C: DnsHandle + 'static>(
    name: Name,
    client: CachingClient<C>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Box<Future<Item = Lookup, Error = ResolveError> + Send> {
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
fn ipv4_then_ipv6<C: DnsHandle + 'static>(
    name: Name,
    client: CachingClient<C>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Box<Future<Item = Lookup, Error = ResolveError> + Send> {
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
fn rt_then_swap<C: DnsHandle + 'static>(
    name: Name,
    client: CachingClient<C>,
    first_type: RecordType,
    second_type: RecordType,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Box<Future<Item = Lookup, Error = ResolveError> + Send> {
    let or_client = client.clone();
    Box::new(
        hosts_lookup(
            Query::query(name.clone(), first_type),
            client,
            options.clone(),
            hosts.clone(),
        )
        .then(move |res| {
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
                            as Box<Future<Item = Lookup, Error = ResolveError> + Send>
                    } else {
                        Box::new(future::ok(ips))
                            as Box<Future<Item = Lookup, Error = ResolveError> + Send>
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

    use proto::error::{ProtoError, ProtoResult};
    use proto::op::Message;
    use proto::rr::{Name, RData, Record};
    use proto::xfer::{DnsHandle, DnsRequest, DnsResponse};

    use super::*;

    #[derive(Clone)]
    pub struct MockDnsHandle {
        messages: Arc<Mutex<Vec<ProtoResult<DnsResponse>>>>,
    }

    impl DnsHandle for MockDnsHandle {
        type Response = Box<Future<Item = DnsResponse, Error = ProtoError> + Send>;

        fn send<R: Into<DnsRequest>>(&mut self, _: R) -> Self::Response {
            Box::new(future::result(
                self.messages.lock().unwrap().pop().unwrap_or_else(empty),
            ))
        }
    }

    pub fn v4_message() -> ProtoResult<DnsResponse> {
        let mut message = Message::new();
        message.insert_answers(vec![Record::from_rdata(
            Name::root(),
            86400,
            RData::A(Ipv4Addr::new(127, 0, 0, 1)),
        )]);
        Ok(message.into())
    }

    pub fn v6_message() -> ProtoResult<DnsResponse> {
        let mut message = Message::new();
        message.insert_answers(vec![Record::from_rdata(
            Name::root(),
            86400,
            RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        )]);
        Ok(message.into())
    }

    pub fn empty() -> ProtoResult<DnsResponse> {
        Ok(Message::new().into())
    }

    pub fn error() -> ProtoResult<DnsResponse> {
        Err(ProtoError::from("forced test failure"))
    }

    pub fn mock(messages: Vec<ProtoResult<DnsResponse>>) -> MockDnsHandle {
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
            )
            .wait()
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
            )
            .wait()
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
            )
            .wait()
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
            )
            .wait()
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
            )
            .wait()
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
            )
            .wait()
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
            )
            .wait()
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
            )
            .wait()
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
            )
            .wait()
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
            )
            .wait()
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
            )
            .wait()
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
            )
            .wait()
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
            )
            .wait()
            .unwrap()
            .iter()
            .map(|r| r.to_ip_addr().unwrap())
            .collect::<Vec<IpAddr>>(),
            vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)]
        );
    }
}
