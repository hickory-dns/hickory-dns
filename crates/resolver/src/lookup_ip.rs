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
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use futures_util::{future, future::Either, future::Future, FutureExt};

use proto::error::ProtoError;
use proto::op::Query;
use proto::rr::{Name, RData, Record, RecordType};
use proto::xfer::{DnsHandle, DnsRequestOptions};

use crate::caching_client::CachingClient;
use crate::config::LookupIpStrategy;
use crate::dns_lru::MAX_TTL;
use crate::error::*;
use crate::hosts::Hosts;
use crate::lookup::{Lookup, LookupIntoIter, LookupIter};

/// Result of a DNS query when querying for A or AAAA records.
///
/// When resolving IP records, there can be many IPs that match a given name. A consumer of this should expect that there are more than a single address potentially returned. Generally there are multiple IPs stored for a given service in DNS so that there is a form of high availability offered for a given name. The service implementation is responsible for the semantics around which IP should be used and when, but in general if a connection fails to one, the next in the list should be attempted.
#[derive(Debug, Clone)]
pub struct LookupIp(Lookup);

impl LookupIp {
    /// Returns a borrowed iterator of the returned IPs
    pub fn iter(&self) -> LookupIpIter<'_> {
        LookupIpIter(self.0.iter())
    }

    /// Returns a reference to the `Query` that was used to produce this result.
    pub fn query(&self) -> &Query {
        self.0.query()
    }

    /// Returns the `Instant` at which this lookup is no longer valid.
    pub fn valid_until(&self) -> Instant {
        self.0.valid_until()
    }

    /// Return a reference to the inner lookup
    ///
    /// This can be useful for getting all records from the request
    pub fn as_lookup(&self) -> &Lookup {
        &self.0
    }
}

impl From<Lookup> for LookupIp {
    fn from(lookup: Lookup) -> Self {
        Self(lookup)
    }
}

impl From<LookupIp> for Lookup {
    fn from(lookup: LookupIp) -> Self {
        lookup.0
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

/// The Future returned from [crate::AsyncResolver] when performing an A or AAAA lookup.
///
/// This type isn't necessarily something that should be used by users, see the default TypeParameters are generally correct
pub struct LookupIpFuture<C, E>
where
    C: DnsHandle<Error = E> + 'static,
    E: Into<ResolveError> + From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    client_cache: CachingClient<C, E>,
    names: Vec<Name>,
    strategy: LookupIpStrategy,
    options: DnsRequestOptions,
    query: Pin<Box<dyn Future<Output = Result<Lookup, ResolveError>> + Send>>,
    hosts: Option<Arc<Hosts>>,
    finally_ip_addr: Option<RData>,
}

impl<C, E> Future for LookupIpFuture<C, E>
where
    C: DnsHandle<Error = E> + 'static,
    E: Into<ResolveError> + From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    type Output = Result<LookupIp, ResolveError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            // Try polling the underlying DNS query.
            let query = self.query.as_mut().poll(cx);

            // Determine whether or not we will attempt to retry the query.
            let should_retry = match query {
                // If the query is NotReady, yield immediately.
                Poll::Pending => return Poll::Pending,
                // If the query returned a successful lookup, we will attempt
                // to retry if the lookup is empty. Otherwise, we will return
                // that lookup.
                Poll::Ready(Ok(ref lookup)) => lookup.is_empty(),
                // If the query failed, we will attempt to retry.
                Poll::Ready(Err(_)) => true,
            };

            if should_retry {
                if let Some(name) = self.names.pop() {
                    // If there's another name left to try, build a new query
                    // for that next name and continue looping.
                    self.query = strategic_lookup(
                        name,
                        self.strategy,
                        self.client_cache.clone(),
                        self.options,
                        self.hosts.clone(),
                    )
                    .boxed();
                    // Continue looping with the new query. It will be polled
                    // on the next iteration of the loop.
                    continue;
                } else if let Some(ip_addr) = self.finally_ip_addr.take() {
                    // Otherwise, if there's an IP address to fall back to,
                    // we'll return it.
                    let record = Record::from_rdata(Name::new(), MAX_TTL, ip_addr);
                    let lookup = Lookup::new_with_max_ttl(Query::new(), Arc::from([record]));
                    return Poll::Ready(Ok(lookup.into()));
                }
            };

            // If we didn't have to retry the query, or we weren't able to
            // retry because we've exhausted the names to search and have no
            // fallback IP address, return the current query.
            return query.map(|f| f.map(LookupIp::from));
            // If we skipped retrying the  query, this will return the
            // successful lookup, otherwise, if the retry failed, this will
            // return the last  query result --- either an empty lookup or the
            // last error we saw.
        }
    }
}

impl<C, E> LookupIpFuture<C, E>
where
    C: DnsHandle<Error = E> + 'static,
    E: Into<ResolveError> + From<ProtoError> + Error + Clone + Send + Unpin + 'static,
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
        client_cache: CachingClient<C, E>,
        options: DnsRequestOptions,
        hosts: Option<Arc<Hosts>>,
        finally_ip_addr: Option<RData>,
    ) -> Self {
        let empty =
            ResolveError::from(ResolveErrorKind::Message("can not lookup IPs for no names"));
        Self {
            names,
            strategy,
            client_cache,
            // If there are no names remaining, this will be returned immediately,
            // otherwise, it will be retried.
            query: future::err(empty).boxed(),
            options,
            hosts,
            finally_ip_addr,
        }
    }
}

/// returns a new future for lookup
async fn strategic_lookup<C, E>(
    name: Name,
    strategy: LookupIpStrategy,
    client: CachingClient<C, E>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Result<Lookup, ResolveError>
where
    C: DnsHandle<Error = E> + 'static,
    E: Into<ResolveError> + From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    match strategy {
        LookupIpStrategy::Ipv4Only => ipv4_only(name, client, options, hosts).await,
        LookupIpStrategy::Ipv6Only => ipv6_only(name, client, options, hosts).await,
        LookupIpStrategy::Ipv4AndIpv6 => ipv4_and_ipv6(name, client, options, hosts).await,
        LookupIpStrategy::Ipv6thenIpv4 => ipv6_then_ipv4(name, client, options, hosts).await,
        LookupIpStrategy::Ipv4thenIpv6 => ipv4_then_ipv6(name, client, options, hosts).await,
    }
}

/// first lookups in hosts, then performs the query
async fn hosts_lookup<C, E>(
    query: Query,
    mut client: CachingClient<C, E>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Result<Lookup, ResolveError>
where
    C: DnsHandle<Error = E> + 'static,
    E: Into<ResolveError> + From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    if let Some(hosts) = hosts {
        if let Some(lookup) = hosts.lookup_static_host(&query) {
            return Ok(lookup);
        };
    }

    client.lookup(query, options).await
}

/// queries only for A records
async fn ipv4_only<C, E>(
    name: Name,
    client: CachingClient<C, E>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Result<Lookup, ResolveError>
where
    C: DnsHandle<Error = E> + 'static,
    E: Into<ResolveError> + From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    hosts_lookup(Query::query(name, RecordType::A), client, options, hosts).await
}

/// queries only for AAAA records
async fn ipv6_only<C, E>(
    name: Name,
    client: CachingClient<C, E>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Result<Lookup, ResolveError>
where
    C: DnsHandle<Error = E> + 'static,
    E: Into<ResolveError> + From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    hosts_lookup(Query::query(name, RecordType::AAAA), client, options, hosts).await
}

// TODO: this really needs to have a stream interface
/// queries only for A and AAAA in parallel
async fn ipv4_and_ipv6<C, E>(
    name: Name,
    client: CachingClient<C, E>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Result<Lookup, ResolveError>
where
    C: DnsHandle<Error = E> + 'static,
    E: Into<ResolveError> + From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    let sel_res = future::select(
        hosts_lookup(
            Query::query(name.clone(), RecordType::A),
            client.clone(),
            options,
            hosts.clone(),
        )
        .boxed(),
        hosts_lookup(Query::query(name, RecordType::AAAA), client, options, hosts).boxed(),
    )
    .await;

    let (ips, remaining_query) = match sel_res {
        Either::Left(ips_and_remaining) => ips_and_remaining,
        Either::Right(ips_and_remaining) => ips_and_remaining,
    };

    let next_ips = remaining_query.await;

    match (ips, next_ips) {
        (Ok(ips), Ok(next_ips)) => {
            // TODO: create a LookupIp enum with the ability to chain these together
            let ips = ips.append(next_ips);
            Ok(ips)
        }
        (Ok(ips), Err(e)) | (Err(e), Ok(ips)) => {
            debug!(
                "one of ipv4 or ipv6 lookup failed in ipv4_and_ipv6 strategy: {}",
                e
            );
            Ok(ips)
        }
        (Err(e1), Err(e2)) => {
            debug!(
                "both of ipv4 or ipv6 lookup failed in ipv4_and_ipv6 strategy e1: {}, e2: {}",
                e1, e2
            );
            Err(e1)
        }
    }
}

/// queries only for AAAA and on no results queries for A
async fn ipv6_then_ipv4<C, E>(
    name: Name,
    client: CachingClient<C, E>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Result<Lookup, ResolveError>
where
    C: DnsHandle<Error = E> + 'static,
    E: Into<ResolveError> + From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    rt_then_swap(
        name,
        client,
        RecordType::AAAA,
        RecordType::A,
        options,
        hosts,
    )
    .await
}

/// queries only for A and on no results queries for AAAA
async fn ipv4_then_ipv6<C, E>(
    name: Name,
    client: CachingClient<C, E>,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Result<Lookup, ResolveError>
where
    C: DnsHandle<Error = E> + 'static,
    E: Into<ResolveError> + From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    rt_then_swap(
        name,
        client,
        RecordType::A,
        RecordType::AAAA,
        options,
        hosts,
    )
    .await
}

/// queries only for first_type and on no results queries for second_type
async fn rt_then_swap<C, E>(
    name: Name,
    client: CachingClient<C, E>,
    first_type: RecordType,
    second_type: RecordType,
    options: DnsRequestOptions,
    hosts: Option<Arc<Hosts>>,
) -> Result<Lookup, ResolveError>
where
    C: DnsHandle<Error = E> + 'static,
    E: Into<ResolveError> + From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    let or_client = client.clone();
    let res = hosts_lookup(
        Query::query(name.clone(), first_type),
        client,
        options,
        hosts.clone(),
    )
    .await;

    match res {
        Ok(ips) => {
            if ips.is_empty() {
                // no ips returns, NXDomain or Otherwise, doesn't matter
                hosts_lookup(
                    Query::query(name.clone(), second_type),
                    or_client,
                    options,
                    hosts,
                )
                .await
            } else {
                Ok(ips)
            }
        }
        Err(_) => {
            hosts_lookup(
                Query::query(name.clone(), second_type),
                or_client,
                options,
                hosts,
            )
            .await
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};

    use futures_executor::block_on;
    use futures_util::future;

    use proto::op::Message;
    use proto::rr::{Name, RData, Record};
    use proto::xfer::{DnsHandle, DnsRequest, DnsResponse};

    use futures_util::stream::{once, Stream};

    use super::*;
    use crate::error::ResolveError;

    #[derive(Clone)]
    pub struct MockDnsHandle {
        messages: Arc<Mutex<Vec<Result<DnsResponse, ResolveError>>>>,
    }

    impl DnsHandle for MockDnsHandle {
        type Response =
            Pin<Box<dyn Stream<Item = Result<DnsResponse, ResolveError>> + Send + Unpin>>;
        type Error = ResolveError;

        fn send<R: Into<DnsRequest>>(&mut self, _: R) -> Self::Response {
            Box::pin(once(future::ready(
                self.messages.lock().unwrap().pop().unwrap_or_else(empty),
            )))
        }
    }

    pub fn v4_message() -> Result<DnsResponse, ResolveError> {
        let mut message = Message::new();
        message.add_query(Query::query(Name::root(), RecordType::A));
        message.insert_answers(vec![Record::from_rdata(
            Name::root(),
            86400,
            RData::A(Ipv4Addr::new(127, 0, 0, 1)),
        )]);

        let resp: DnsResponse = message.into();
        assert!(resp.contains_answer());
        Ok(resp)
    }

    pub fn v6_message() -> Result<DnsResponse, ResolveError> {
        let mut message = Message::new();
        message.add_query(Query::query(Name::root(), RecordType::AAAA));
        message.insert_answers(vec![Record::from_rdata(
            Name::root(),
            86400,
            RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        )]);

        let resp: DnsResponse = message.into();
        assert!(resp.contains_answer());
        Ok(resp)
    }

    pub fn empty() -> Result<DnsResponse, ResolveError> {
        Ok(Message::new().into())
    }

    pub fn error() -> Result<DnsResponse, ResolveError> {
        Err(ResolveError::from("forced test failure"))
    }

    pub fn mock(messages: Vec<Result<DnsResponse, ResolveError>>) -> MockDnsHandle {
        MockDnsHandle {
            messages: Arc::new(Mutex::new(messages)),
        }
    }

    #[test]
    fn test_ipv4_only_strategy() {
        assert_eq!(
            block_on(ipv4_only(
                Name::root(),
                CachingClient::new(0, mock(vec![v4_message()]), false),
                DnsRequestOptions::default(),
                None,
            ))
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
            block_on(ipv6_only(
                Name::root(),
                CachingClient::new(0, mock(vec![v6_message()]), false),
                DnsRequestOptions::default(),
                None,
            ))
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
            block_on(ipv4_and_ipv6(
                Name::root(),
                CachingClient::new(0, mock(vec![v6_message(), v4_message()]), false),
                DnsRequestOptions::default(),
                None,
            ))
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
            block_on(ipv4_and_ipv6(
                Name::root(),
                CachingClient::new(0, mock(vec![empty(), v4_message()]), false),
                DnsRequestOptions::default(),
                None,
            ))
            .unwrap()
            .iter()
            .map(|r| r.to_ip_addr().unwrap())
            .collect::<Vec<IpAddr>>(),
            vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]
        );

        // error then ipv4
        assert_eq!(
            block_on(ipv4_and_ipv6(
                Name::root(),
                CachingClient::new(0, mock(vec![error(), v4_message()]), false),
                DnsRequestOptions::default(),
                None,
            ))
            .unwrap()
            .iter()
            .map(|r| r.to_ip_addr().unwrap())
            .collect::<Vec<IpAddr>>(),
            vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]
        );

        // only ipv6 available
        assert_eq!(
            block_on(ipv4_and_ipv6(
                Name::root(),
                CachingClient::new(0, mock(vec![v6_message(), empty()]), false),
                DnsRequestOptions::default(),
                None,
            ))
            .unwrap()
            .iter()
            .map(|r| r.to_ip_addr().unwrap())
            .collect::<Vec<IpAddr>>(),
            vec![IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]
        );

        // error, then only ipv6 available
        assert_eq!(
            block_on(ipv4_and_ipv6(
                Name::root(),
                CachingClient::new(0, mock(vec![v6_message(), error()]), false),
                DnsRequestOptions::default(),
                None,
            ))
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
            block_on(ipv6_then_ipv4(
                Name::root(),
                CachingClient::new(0, mock(vec![v6_message()]), false),
                DnsRequestOptions::default(),
                None,
            ))
            .unwrap()
            .iter()
            .map(|r| r.to_ip_addr().unwrap())
            .collect::<Vec<IpAddr>>(),
            vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)]
        );

        // nothing then ipv4
        assert_eq!(
            block_on(ipv6_then_ipv4(
                Name::root(),
                CachingClient::new(0, mock(vec![v4_message(), empty()]), false),
                DnsRequestOptions::default(),
                None,
            ))
            .unwrap()
            .iter()
            .map(|r| r.to_ip_addr().unwrap())
            .collect::<Vec<IpAddr>>(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );

        // ipv4 and error
        assert_eq!(
            block_on(ipv6_then_ipv4(
                Name::root(),
                CachingClient::new(0, mock(vec![v4_message(), error()]), false),
                DnsRequestOptions::default(),
                None,
            ))
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
            block_on(ipv4_then_ipv6(
                Name::root(),
                CachingClient::new(0, mock(vec![v4_message()]), false),
                DnsRequestOptions::default(),
                None,
            ))
            .unwrap()
            .iter()
            .map(|r| r.to_ip_addr().unwrap())
            .collect::<Vec<IpAddr>>(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );

        // nothing then ipv6
        assert_eq!(
            block_on(ipv4_then_ipv6(
                Name::root(),
                CachingClient::new(0, mock(vec![v6_message(), empty()]), false),
                DnsRequestOptions::default(),
                None,
            ))
            .unwrap()
            .iter()
            .map(|r| r.to_ip_addr().unwrap())
            .collect::<Vec<IpAddr>>(),
            vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)]
        );

        // error then ipv6
        assert_eq!(
            block_on(ipv4_then_ipv6(
                Name::root(),
                CachingClient::new(0, mock(vec![v6_message(), error()]), false),
                DnsRequestOptions::default(),
                None,
            ))
            .unwrap()
            .iter()
            .map(|r| r.to_ip_addr().unwrap())
            .collect::<Vec<IpAddr>>(),
            vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)]
        );
    }
}
