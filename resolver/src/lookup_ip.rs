
// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! LookupHost result from a resolution with a Resolver

use std::error::Error;
use std::io;
use std::mem;
use std::net::IpAddr;
use std::slice::Iter;
use std::sync::{Arc, Mutex, TryLockError};
use std::time::Instant;

use futures::{Async, future, Future, Poll, task};

use trust_dns::client::{ClientHandle, RetryClientHandle, SecureClientHandle};
use trust_dns::error::ClientError;
use trust_dns::op::Message;
use trust_dns::rr::{DNSClass, Name, RData, RecordType};

use config::LookupIpStrategy;
use lru::DnsLru;
use name_server_pool::NameServerPool;

/// Result of a DNS query when querying for A or AAAA records.
///
/// When resolving IP records, there can be many IPs that match a given name. A consumer of this should expect that there are more than a single address potentially returned. Generally there are multiple IPs stored for a given service in DNS so that there is a form of high availability offered for a given name. The service implementation is resposible for the seymantics around which IP should be used and when, but in general if a connection fails to one, the next in the list should be attempted.
#[derive(Debug, Clone)]
pub struct LookupIp {
    ips: Arc<Vec<IpAddr>>,
}

impl LookupIp {
    pub(crate) fn new(ips: Arc<Vec<IpAddr>>) -> Self {
        LookupIp { ips }
    }

    /// Returns a borrowed iterator of the returned IPs
    pub fn iter(&self) -> LookupIpIter {
        LookupIpIter(self.ips.iter())
    }
}

/// Borrowed view of set of IPs returned from a LookupIp
pub struct LookupIpIter<'a>(Iter<'a, IpAddr>);

impl<'a> Iterator for LookupIpIter<'a> {
    type Item = &'a IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

/// Different lookup options for the lookup strategy
#[derive(Clone)]
#[doc(hidden)]
pub enum LookupIpEither {
    Retry(RetryClientHandle<NameServerPool>),
    Secure(SecureClientHandle<RetryClientHandle<NameServerPool>>),
}

impl ClientHandle for LookupIpEither {
    fn send(&mut self, message: Message) -> Box<Future<Item = Message, Error = ClientError>> {
        match *self {
            LookupIpEither::Retry(ref mut c) => c.send(message),
            LookupIpEither::Secure(ref mut c) => c.send(message),
        }
    }
}

/// The Future returned from ResolverFuture when performing an A or AAAA lookup.
pub type LookupIpFuture = InnerLookupIpFuture<LookupIpEither>;

#[doc(hidden)]
/// The Future returned from ResolverFuture when performing an A or AAAA lookup.
pub struct InnerLookupIpFuture<C: ClientHandle + 'static> {
    client: C,
    names: Vec<Name>,
    strategy: LookupIpStrategy,
    future: Box<Future<Item = LookupIp, Error = io::Error>>,
    // TODO: zero lock datastructure instead?
    cache: Arc<Mutex<DnsLru>>,
}

impl<C: ClientHandle + 'static> InnerLookupIpFuture<C> {
    /// Perform a lookup from a hostname to a set of IPs
    ///
    /// # Arguments
    ///
    /// * `names` - a set of DNS names to attempt to resolve, they will be attempted in queue order, i.e. the first is `names.pop()`. Upon each failure, the next will be attempted.
    /// * `strategy` - the lookup IP strategy to use
    /// * `client` - connection to use for performing all lookups
    /// * `cache` - an optional cache from which to attempt to load records prior to lookup
    pub(crate) fn lookup(
        mut names: Vec<Name>,
        strategy: LookupIpStrategy,
        client: &mut C,
        cache: Arc<Mutex<DnsLru>>,
    ) -> Self {
        let name = names.pop().expect("can not lookup IPs for no names");

        let query = LookupIpState::lookup(name, strategy, client, cache.clone());
        InnerLookupIpFuture {
            client: client.clone(),
            names,
            strategy,
            future: Box::new(query),
            cache,
        }
    }

    fn next_lookup<F: FnOnce() -> Poll<LookupIp, io::Error>>(
        &mut self,
        otherwise: F,
    ) -> Poll<LookupIp, io::Error> {
        let name = self.names.pop();
        if let Some(name) = name {
            let query =
                LookupIpState::lookup(name, self.strategy, &mut self.client, self.cache.clone());

            mem::replace(&mut self.future, Box::new(query));
            // guarantee that we get scheduled for the next turn...
            task::current().notify();
            Ok(Async::NotReady)
        } else {
            otherwise()
        }
    }

    pub(crate) fn error<E: Error>(client: C, error: E) -> Self {
        return InnerLookupIpFuture {
            // errors on names don't need to be cheap... i.e. this clone is unfortunate in this case.
            client,
            names: vec![],
            strategy: LookupIpStrategy::default(),
            future: Box::new(future::err(
                io::Error::new(io::ErrorKind::Other, format!("{}", error)),
            )),
            cache: Arc::new(Mutex::new(DnsLru::new(0))),
        };
    }
}

impl<C: ClientHandle + 'static> Future for InnerLookupIpFuture<C> {
    type Item = LookupIp;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.future.poll() {
            Ok(Async::Ready(lookup_ip)) => {
                if lookup_ip.ips.len() == 0 {
                    return self.next_lookup(|| Ok(Async::Ready(lookup_ip)));
                } else {
                    return Ok(Async::Ready(lookup_ip));
                }
            }
            p @ Ok(Async::NotReady) => p,
            e @ Err(_) => {
                return self.next_lookup(|| e);
            }
        }
    }
}

// TODO: maximum recursion on CNAME, etc, chains...
// struct LookupStack(Vec<Query>);

// impl LookupStack {
//     // pushes the Query onto the stack, and returns a reference. An error will be returned
//     fn push(&mut self, query: Query) -> io::Result<&Query> {
//         if self.0.contains(&query) {
//             return Err(io::Error::new(io::ErrorKind::Other, "circular CNAME or other recursion"));
//         }

//         self.0.push(query);
//         Ok(self.0.last().unwrap())
//     }
// }

struct FromCache {
    name: Name,
    strategy: LookupIpStrategy,
    cache: Arc<Mutex<DnsLru>>,
}

impl Future for FromCache {
    type Item = Option<LookupIp>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // first transition any polling that is needed (mutable refs...)
        match self.cache.try_lock() {
            Err(TryLockError::WouldBlock) => {
                task::current().notify(); // yield
                return Ok(Async::NotReady);
            }
            // TODO: need to figure out a way to recover from this.
            // It requires unwrapping the poisoned error and recreating the Mutex at a higher layer...
            Err(TryLockError::Poisoned(poison)) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("poisoned: {}", poison),
            )),
            Ok(mut lru) => {
                return Ok(Async::Ready(lru.get(&self.name, Instant::now())));
            }
        }
    }
}

struct InsertCache {
    ips: Vec<(IpAddr, u32)>,
    name: Name,
    cache: Arc<Mutex<DnsLru>>,
}

impl Future for InsertCache {
    type Item = LookupIp;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // first transition any polling that is needed (mutable refs...)
        match self.cache.try_lock() {
            Err(TryLockError::WouldBlock) => {
                task::current().notify(); // yield
                return Ok(Async::NotReady);
            }
            // TODO: need to figure out a way to recover from this.
            // It requires unwrapping the poisoned error and recreating the Mutex at a higher layer...
            Err(TryLockError::Poisoned(poison)) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("poisoned: {}", poison),
            )),
            Ok(mut lru) => {
                // this will put this object into an inconsistent state, but no one should call poll again...
                let name = mem::replace(&mut self.name, Name::root());
                let ips = mem::replace(&mut self.ips, vec![]);

                return Ok(Async::Ready(lru.insert(name, ips, Instant::now())));
            }
        }
    }
}

enum LookupIpState<C: ClientHandle + 'static> {
    /// In the FromCache state we evaluate cache entries for any results
    FromCache(FromCache, C),
    /// In the query state there is an active query that's been started, see Self::lookup()
    Query(Box<Future<Item = Vec<(IpAddr, u32)>, Error = ClientError>>, Name, Arc<Mutex<DnsLru>>),
    /// State of adding the item to the cache
    InsertCache(InsertCache),
    /// A state which should not occur
    Error,
}

impl<C: ClientHandle + 'static> LookupIpState<C> {
    pub(crate) fn lookup(
        name: Name,
        strategy: LookupIpStrategy,
        client: &mut C,
        cache: Arc<Mutex<DnsLru>>,
    ) -> LookupIpState<C> {
        LookupIpState::FromCache(
            FromCache {
                name,
                strategy,
                cache,
            },
            client.clone(),
        )
    }

    /// Query after a failed cache lookup
    ///
    /// # Panics
    ///
    /// This will panic if the current state is not FromCache.
    fn query_after_cache(&mut self) {
        let from_cache_state = mem::replace(self, LookupIpState::Error);

        // TODO: with specialization, could we define a custom query only on the FromCache type?
        match from_cache_state {
            LookupIpState::FromCache(from_cache, mut client) => {
                let query_future =
                    strategic_lookup(from_cache.name.clone(), from_cache.strategy, &mut client);
                mem::replace(
                    self,
                    LookupIpState::Query(query_future, from_cache.name, from_cache.cache),
                );
            }
            _ => panic!("bad state, expected FromCache"),
        }
    }

    fn cache(&mut self, ips: Vec<(IpAddr, u32)>) {
        // The error state, this query is complete...
        let query_state = mem::replace(self, LookupIpState::Error);

        match query_state {
            LookupIpState::Query(_, name, cache) => {
                mem::replace(
                    self,
                    LookupIpState::InsertCache(InsertCache { ips, name, cache }),
                );
            }
            _ => panic!("bad state, expected Query"),
        }
    }
}

impl<C: ClientHandle + 'static> Future for LookupIpState<C> {
    type Item = LookupIp;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // first transition any polling that is needed (mutable refs...)
        let poll;
        match *self {
            LookupIpState::FromCache(ref mut from_cache, ..) => {
                match from_cache.poll() {
                    // need to query since it wasn't in the cache
                    Ok(Async::Ready(None)) => (), // handled below
                    Ok(Async::Ready(Some(ips))) => return Ok(Async::Ready(ips)),
                    Ok(Async::NotReady) => return Ok(Async::NotReady),
                    Err(error) => return Err(error),
                };

                poll = Ok(Async::NotReady);
            }
            LookupIpState::Query(ref mut query, ..) => {
                poll = query.poll().map_err(|e| e.into());
                match poll {
                    Ok(Async::NotReady) => {
                        return Ok(Async::NotReady);
                    }
                    Ok(Async::Ready(_)) => (), // handled in next match
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            LookupIpState::InsertCache(ref mut insert_cache) => {
                return insert_cache.poll();
                // match insert_cache.poll() {
                //     // need to query since it wasn't in the cache
                //     Ok(Async::Ready(ips)) => return Ok(Async::Ready(ips)),
                //     Ok(Async::NotReady) => return Ok(Async::NotReady),
                //     Err(error) => return Err(error),
                // }
            }
            LookupIpState::Error => panic!("invalid error state"),
        }

        // getting here means there are Aync::Ready available.
        match *self {
            LookupIpState::FromCache(..) => self.query_after_cache(),
            LookupIpState::Query(..) => {
                match poll {
                    Ok(Async::Ready(ips)) => {
                        self.cache(ips.clone());
                    }
                    _ => panic!("should have returned earlier"),
                }
            }
            _ => panic!("should have returned earlier"),            
        }

        task::current().notify(); // yield
        return Ok(Async::NotReady);
    }
}

/// returns a new future for lookup
fn strategic_lookup<C: ClientHandle + 'static>(
    name: Name,
    strategy: LookupIpStrategy,
    client: &mut C,
) -> Box<Future<Item = Vec<(IpAddr, u32)>, Error = ClientError>> {
    match strategy {
        LookupIpStrategy::Ipv4Only => ipv4_only(name, client),
        LookupIpStrategy::Ipv6Only => ipv6_only(name, client),
        LookupIpStrategy::Ipv4AndIpv6 => ipv4_and_ipv6(name, client),
        LookupIpStrategy::Ipv6thenIpv4 => ipv6_then_ipv4(name, client),
        LookupIpStrategy::Ipv4thenIpv6 => ipv4_then_ipv6(name, client),
    }
}

fn map_message_to_ipaddr(mut message: Message) -> Vec<(IpAddr, u32)> {
    message
        .take_answers()
        .iter()
        .filter_map(|r| {
            let ttl = r.ttl();
            match *r.rdata() {
                RData::A(ipaddr) => Some((IpAddr::V4(ipaddr), ttl)),
                RData::AAAA(ipaddr) => Some((IpAddr::V6(ipaddr), ttl)),
                _ => None,
            }
        })
        .collect()
}

/// queries only for A records
fn ipv4_only<C: ClientHandle>(
    name: Name,
    client: &mut C,
) -> Box<Future<Item = Vec<(IpAddr, u32)>, Error = ClientError>> {
    Box::new(client.query(name, DNSClass::IN, RecordType::A).map(
        map_message_to_ipaddr,
    ))
}

/// queries only for AAAA records
fn ipv6_only<C: ClientHandle>(
    name: Name,
    client: &mut C,
) -> Box<Future<Item = Vec<(IpAddr, u32)>, Error = ClientError>> {
    Box::new(client.query(name, DNSClass::IN, RecordType::AAAA).map(
        map_message_to_ipaddr,
    ))
}

/// queries only for A and AAAA in parallel
fn ipv4_and_ipv6<C: ClientHandle>(
    name: Name,
    client: &mut C,
) -> Box<Future<Item = Vec<(IpAddr, u32)>, Error = ClientError>> {
    Box::new(
        client
            .query(name.clone(), DNSClass::IN, RecordType::A)
            .map(map_message_to_ipaddr)
            .select(client.query(name, DNSClass::IN, RecordType::AAAA).map(
                map_message_to_ipaddr,
            ))
            .then(|sel_res| {
                match sel_res {
                    // Some ips returned, get the other record result, or else just return record
                    Ok((mut ips, remaining_query)) => {
                        Box::new(remaining_query.then(move |query_res| match query_res {
                            /// join AAAA and A results
                            Ok(mut rem_ips) => {
                                rem_ips.append(&mut ips);
                                future::ok(rem_ips)
                            }
                            // One failed, just return the other
                            Err(_) => future::ok(ips),
                        })) as
                            // This cast is to resolve a comilation error, not sure of it's necessity
                            Box<Future<Item = Vec<(IpAddr, u32)>, Error = ClientError>>
                    }

                    // One failed, just return the other
                    Err((_, remaining_query)) => Box::new(remaining_query),
                }
            }),
    )
}

/// queries only for AAAA and on no results queries for A
fn ipv6_then_ipv4<C: ClientHandle + 'static>(
    name: Name,
    client: &mut C,
) -> Box<Future<Item = Vec<(IpAddr, u32)>, Error = ClientError>> {
    rt_then_swap(name, client, RecordType::AAAA, RecordType::A)
}

/// queries only for A and on no results queries for AAAA
fn ipv4_then_ipv6<C: ClientHandle + 'static>(
    name: Name,
    client: &mut C,
) -> Box<Future<Item = Vec<(IpAddr, u32)>, Error = ClientError>> {
    rt_then_swap(name, client, RecordType::A, RecordType::AAAA)
}

/// queries only for first_type and on no results queries for second_type
fn rt_then_swap<C: ClientHandle + 'static>(
    name: Name,
    client: &mut C,
    first_type: RecordType,
    second_type: RecordType,
) -> Box<Future<Item = Vec<(IpAddr, u32)>, Error = ClientError>> {
    let mut or_client = client.clone();
    Box::new(
        client
            .query(name.clone(), DNSClass::IN, first_type)
            .map(map_message_to_ipaddr)
            .then(move |res| {
                match res {
                    Ok(ips) => {
                        println!("ips");
                        if ips.is_empty() {
                            println!("ips, are empty");

                            // no ips returns, NXDomain or Otherwise, doesn't matter
                            Box::new(
                                or_client
                                    .query(name.clone(), DNSClass::IN, second_type)
                                    .map(map_message_to_ipaddr),
                            ) as
                                Box<Future<Item = Vec<(IpAddr, u32)>, Error = ClientError>>
                        } else {
                            Box::new(future::ok(ips)) as
                                Box<Future<Item = Vec<(IpAddr, u32)>, Error = ClientError>>
                        }
                    }
                    Err(_) => {
                        Box::new(
                            or_client
                                .query(name.clone(), DNSClass::IN, second_type)
                                .map(map_message_to_ipaddr),
                        )
                    }
                }
            }),
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};

    use futures::{future, Future};

    use trust_dns::client::ClientHandle;
    use trust_dns::error::*;
    use trust_dns::op::Message;
    use trust_dns::rr::{Name, Record, RData, RecordType};

    use super::*;

    #[derive(Clone)]
    struct MockClientHandle {
        messages: Arc<Mutex<Vec<ClientResult<Message>>>>,
    }

    impl ClientHandle for MockClientHandle {
        fn send(&mut self, _: Message) -> Box<Future<Item = Message, Error = ClientError>> {
            Box::new(future::result(
                self.messages.lock().unwrap().pop().unwrap_or(empty()),
            ))
        }
    }

    fn v4_message() -> ClientResult<Message> {
        let mut message = Message::new();
        message.insert_answers(vec![
            Record::from_rdata(
                Name::root(),
                86400,
                RecordType::A,
                RData::A(Ipv4Addr::new(127, 0, 0, 1))
            ),
        ]);
        Ok(message)
    }

    fn v6_message() -> ClientResult<Message> {
        let mut message = Message::new();
        message.insert_answers(vec![
            Record::from_rdata(
                Name::root(),
                86400,
                RecordType::AAAA,
                RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
            ),
        ]);
        Ok(message)
    }

    fn empty() -> ClientResult<Message> {
        Ok(Message::new())
    }

    fn error() -> ClientResult<Message> {
        Err(ClientErrorKind::Io.into())
    }

    fn mock(messages: Vec<ClientResult<Message>>) -> MockClientHandle {
        MockClientHandle { messages: Arc::new(Mutex::new(messages)) }
    }

    #[test]
    fn test_ipv4_only_strategy() {
        assert_eq!(
            ipv4_only(Name::root(), &mut mock(vec![v4_message()]))
                .wait()
                .unwrap()
                .into_iter()
                .map(|(ip, _)| ip)
                .collect::<Vec<IpAddr>>(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );
    }

    #[test]
    fn test_ipv6_only_strategy() {
        assert_eq!(
            ipv6_only(Name::root(), &mut mock(vec![v6_message()]))
                .wait()
                .unwrap()
                .into_iter()
                .map(|(ip, _)| ip)
                .collect::<Vec<IpAddr>>(),
            vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)]
        );
    }

    #[test]
    fn test_ipv4_and_ipv6_strategy() {
        // both succeed
        assert_eq!(
            ipv4_and_ipv6(Name::root(), &mut mock(vec![v4_message(), v6_message()]))
                .wait()
                .unwrap()
                .into_iter()
                .map(|(ip, _)| ip)
                .collect::<Vec<IpAddr>>(),
            vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ]
        );

        // only ipv4 available
        assert_eq!(
            ipv4_and_ipv6(Name::root(), &mut mock(vec![v4_message()]))
                .wait()
                .unwrap()
                .into_iter()
                .map(|(ip, _)| ip)
                .collect::<Vec<IpAddr>>(),
            vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]
        );

        // only ipv6 available
        assert_eq!(
            ipv4_and_ipv6(Name::root(), &mut mock(vec![v6_message()]))
                .wait()
                .unwrap()
                .into_iter()
                .map(|(ip, _)| ip)
                .collect::<Vec<IpAddr>>(),
            vec![IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]
        );

        // error, then only ipv6 available
        assert_eq!(
            ipv4_and_ipv6(Name::root(), &mut mock(vec![error(), v6_message()]))
                .wait()
                .unwrap()
                .into_iter()
                .map(|(ip, _)| ip)
                .collect::<Vec<IpAddr>>(),
            vec![IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]
        );
    }

    #[test]
    fn test_ipv6_then_ipv4_strategy() {
        // ipv6 first
        assert_eq!(
            ipv6_then_ipv4(Name::root(), &mut mock(vec![v6_message()]))
                .wait()
                .unwrap()
                .into_iter()
                .map(|(ip, _)| ip)
                .collect::<Vec<IpAddr>>(),
            vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)]
        );

        // nothing then ipv4
        assert_eq!(
            ipv6_then_ipv4(Name::root(), &mut mock(vec![v4_message(), empty()]))
                .wait()
                .unwrap()
                .into_iter()
                .map(|(ip, _)| ip)
                .collect::<Vec<IpAddr>>(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );

        // ipv4 and error
        assert_eq!(
            ipv6_then_ipv4(Name::root(), &mut mock(vec![v4_message(), error()]))
                .wait()
                .unwrap()
                .into_iter()
                .map(|(ip, _)| ip)
                .collect::<Vec<IpAddr>>(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );
    }

    #[test]
    fn test_ipv4_then_ipv6_strategy() {
        // ipv6 first
        assert_eq!(
            ipv4_then_ipv6(Name::root(), &mut mock(vec![v4_message()]))
                .wait()
                .unwrap()
                .into_iter()
                .map(|(ip, _)| ip)
                .collect::<Vec<IpAddr>>(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );

        // nothing then ipv6
        assert_eq!(
            ipv4_then_ipv6(Name::root(), &mut mock(vec![v6_message(), empty()]))
                .wait()
                .unwrap()
                .into_iter()
                .map(|(ip, _)| ip)
                .collect::<Vec<IpAddr>>(),
            vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)]
        );

        // error then ipv6
        assert_eq!(
            ipv4_then_ipv6(Name::root(), &mut mock(vec![v6_message(), error()]))
                .wait()
                .unwrap()
                .into_iter()
                .map(|(ip, _)| ip)
                .collect::<Vec<IpAddr>>(),
            vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)]
        );
    }

    #[test]
    fn test_empty_cache() {
        let cache = Arc::new(Mutex::new(DnsLru::new(1)));
        let mut client = mock(vec![empty()]);

        let ips =
            LookupIpState::lookup(Name::root(), LookupIpStrategy::Ipv4Only, &mut client, cache)
                .wait()
                .unwrap();

        assert!(ips.iter().next().is_none());
    }

    #[test]
    fn test_from_cache() {
        let cache = Arc::new(Mutex::new(DnsLru::new(1)));
        cache.lock().unwrap().insert(
            Name::root(),
            vec![
                (IpAddr::from(Ipv4Addr::new(127, 0, 0, 1)), u32::max_value()),
            ],
            Instant::now(),
        );

        let mut client = mock(vec![empty()]);

        let ips =
            LookupIpState::lookup(Name::root(), LookupIpStrategy::Ipv4Only, &mut client, cache)
                .wait()
                .unwrap();

        assert_eq!(
            ips.iter().cloned().collect::<Vec<IpAddr>>(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );
    }

    #[test]
    fn test_no_cache_insert() {
        let cache = Arc::new(Mutex::new(DnsLru::new(1)));
        // first should come from client...
        let mut client = mock(vec![v4_message()]);

        let ips = LookupIpState::lookup(
            Name::root(),
            LookupIpStrategy::Ipv4Only,
            &mut client,
            cache.clone(),
        ).wait()
            .unwrap();

        assert_eq!(
            ips.iter().cloned().collect::<Vec<IpAddr>>(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );

        // next should come from cache...
        let mut client = mock(vec![empty()]);

        let ips =
            LookupIpState::lookup(Name::root(), LookupIpStrategy::Ipv4Only, &mut client, cache)
                .wait()
                .unwrap();

        assert_eq!(
            ips.iter().cloned().collect::<Vec<IpAddr>>(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );
    }
}