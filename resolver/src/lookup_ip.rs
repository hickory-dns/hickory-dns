
// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! LookupHost result from a resolution with a Resolver

use std::io;
use std::mem;
use std::net::IpAddr;
use std::slice::Iter;

use futures::{Async, future, Future, Poll, task};

use trust_dns::client::ClientHandle;
use trust_dns::error::ClientError;
use trust_dns::op::Message;
use trust_dns::rr::{DNSClass, Name, RData, RecordType};

use config::LookupIpStrategy;

/// Result of a DNS query when querying for A or AAAA records.
#[derive(Debug)]
pub struct LookupIp {
    ips: Vec<IpAddr>,
}

impl LookupIp {
    fn new(ips: Vec<IpAddr>) -> Self {
        LookupIp { ips }
    }

    /// Returns a borrowed iterator of the returned IPs
    pub fn iter(&self) -> LookupIpIter {
        LookupIpIter(self.ips.iter())
    }
}

impl Iterator for LookupIp {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.ips.pop()
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


/// The Future returned from ResolverFuture when performing an A or AAAA lookup.
pub struct LookupIpFuture {
    future: Box<Future<Item = LookupIp, Error = io::Error>>,
}

impl LookupIpFuture {
    pub(crate) fn lookup<C: ClientHandle + 'static>(
        host: &str,
        strategy: LookupIpStrategy,
        client: &mut C,
    ) -> Self {
        let name = match Name::parse(host, None) {
            Ok(name) => name,
            Err(err) => {
                return LookupIpFuture { future: Box::new(future::err(io::Error::from(err))) }
            }
        };

        let query = LookupIpState::lookup(name, strategy, client);
        LookupIpFuture { future: Box::new(query) }
    }
}

impl Future for LookupIpFuture {
    type Item = LookupIp;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.future.poll()
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

enum LookupIpState {
    Query(Box<Future<Item = Vec<IpAddr>, Error = ClientError>>),
    Fin(Vec<IpAddr>),
}

impl LookupIpState {
    pub fn lookup<C: ClientHandle + 'static>(
        name: Name,
        strategy: LookupIpStrategy,
        client: &mut C,
    ) -> Self {
        let query_future = lookup(name, strategy, client);

        LookupIpState::Query(query_future)
    }

    fn transition_query(&mut self, ips: Vec<IpAddr>) {
        assert!(if let LookupIpState::Query(_) = *self {
            true
        } else {
            false
        });

        // transition
        mem::replace(self, LookupIpState::Fin(ips));
    }
}

impl Future for LookupIpState {
    type Item = LookupIp;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // first transition any polling that is needed (mutable refs...)
        let poll;
        match *self {
            LookupIpState::Query(ref mut query) => {
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
            LookupIpState::Fin(ref mut ips) => {
                let ips = mem::replace(ips, Vec::<IpAddr>::new());
                let ips = LookupIp::new(ips);
                return Ok(Async::Ready(ips));
            }
        }

        // getting here means there are Aync::Ready available.
        match *self {
            LookupIpState::Query(_) => {
                match poll {
                    Ok(Async::Ready(ips)) => self.transition_query(ips),
                    _ => panic!("should have returned earlier"),
                }
            }
            LookupIpState::Fin(_) => panic!("should have returned earlier"),
        }

        task::current().notify(); // yield
        Ok(Async::NotReady)
    }
}

fn lookup<C: ClientHandle + 'static>(
    name: Name,
    strategy: LookupIpStrategy,
    client: &mut C,
) -> Box<Future<Item = Vec<IpAddr>, Error = ClientError>> {
    match strategy {
        LookupIpStrategy::Ipv4Only => ipv4_only(name, client),
        LookupIpStrategy::Ipv6Only => ipv6_only(name, client),
        LookupIpStrategy::Ipv4AndIpv6 => ipv4_and_ipv6(name, client),
        LookupIpStrategy::Ipv6thenIpv4 => ipv6_then_ipv4(name, client),
        LookupIpStrategy::Ipv4thenIpv6 => ipv4_then_ipv6(name, client),
    }
}

fn map_message_to_ipaddr(mut message: Message) -> Vec<IpAddr> {
    message
        .take_answers()
        .iter()
        .filter_map(|r| match *r.rdata() {
            RData::A(ipaddr) => Some(IpAddr::V4(ipaddr)),
            RData::AAAA(ipaddr) => Some(IpAddr::V6(ipaddr)),
            _ => None,
        })
        .collect()
}

/// queries only for A records
fn ipv4_only<C: ClientHandle>(
    name: Name,
    client: &mut C,
) -> Box<Future<Item = Vec<IpAddr>, Error = ClientError>> {
    Box::new(client.query(name, DNSClass::IN, RecordType::A).map(
        map_message_to_ipaddr,
    ))
}

/// queries only for AAAA records
fn ipv6_only<C: ClientHandle>(
    name: Name,
    client: &mut C,
) -> Box<Future<Item = Vec<IpAddr>, Error = ClientError>> {
    Box::new(client.query(name, DNSClass::IN, RecordType::AAAA).map(
        map_message_to_ipaddr,
    ))
}

/// queries only for A and AAAA in parallel
fn ipv4_and_ipv6<C: ClientHandle>(
    name: Name,
    client: &mut C,
) -> Box<Future<Item = Vec<IpAddr>, Error = ClientError>> {
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
                            Box<Future<Item = Vec<IpAddr>, Error = ClientError>>
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
) -> Box<Future<Item = Vec<IpAddr>, Error = ClientError>> {
    rt_then_swap(name, client, RecordType::AAAA, RecordType::A)
}

/// queries only for A and on no results queries for AAAA
fn ipv4_then_ipv6<C: ClientHandle + 'static>(
    name: Name,
    client: &mut C,
) -> Box<Future<Item = Vec<IpAddr>, Error = ClientError>> {
    rt_then_swap(name, client, RecordType::A, RecordType::AAAA)
}

/// queries only for first_type and on no results queries for second_type
fn rt_then_swap<C: ClientHandle + 'static>(
    name: Name,
    client: &mut C,
    first_type: RecordType,
    second_type: RecordType,
) -> Box<Future<Item = Vec<IpAddr>, Error = ClientError>> {
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
                                Box<Future<Item = Vec<IpAddr>, Error = ClientError>>
                        } else {
                            Box::new(future::ok(ips)) as
                                Box<Future<Item = Vec<IpAddr>, Error = ClientError>>
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

// TODO: need to add some Err(result) tests...
#[cfg(test)]
mod tests {
    use std::io;
    use std::mem;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::slice::Iter;
    use std::sync::{Arc, Mutex};

    use futures::{Async, future, Future, Poll, task};

    use trust_dns::client::ClientHandle;
    use trust_dns::error::ClientError;
    use trust_dns::op::Message;
    use trust_dns::rr::{DNSClass, Name, Record, RData, RecordType};

    use config::LookupIpStrategy;

    use super::*;

    #[derive(Clone)]
    struct MockClientHandle {
        messages: Arc<Mutex<Vec<Message>>>,
    }

    impl ClientHandle for MockClientHandle {
        fn send(&mut self, message: Message) -> Box<Future<Item = Message, Error = ClientError>> {
            Box::new(future::ok(self.messages.lock().unwrap().pop().unwrap_or(
                Message::new(),
            )))
        }
    }

    fn v4_message() -> Message {
        let mut message = Message::new();
        message.insert_answers(vec![
            Record::from_rdata(
                Name::root(),
                0,
                RecordType::A,
                RData::A(Ipv4Addr::new(127, 0, 0, 1))
            ),
        ]);
        message
    }

    fn v6_message() -> Message {
        let mut message = Message::new();
        message.insert_answers(vec![
            Record::from_rdata(
                Name::root(),
                0,
                RecordType::AAAA,
                RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
            ),
        ]);
        message
    }

    fn mock(messages: Vec<Message>) -> MockClientHandle {
        MockClientHandle { messages: Arc::new(Mutex::new(messages)) }
    }

    #[test]
    fn test_ipv4_only_strategy() {
        assert_eq!(
            ipv4_only(Name::root(), &mut mock(vec![v4_message()]))
                .wait()
                .unwrap(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );
    }

    #[test]
    fn test_ipv6_only_strategy() {
        assert_eq!(
            ipv6_only(Name::root(), &mut mock(vec![v6_message()]))
                .wait()
                .unwrap(),
            vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)]
        );
    }

    #[test]
    fn test_ipv4_and_ipv6_strategy() {
        // both succeed
        assert_eq!(
            ipv4_and_ipv6(Name::root(), &mut mock(vec![v4_message(), v6_message()]))
                .wait()
                .unwrap(),
            vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ]
        );

        // only ipv4 available
        assert_eq!(
            ipv4_and_ipv6(Name::root(), &mut mock(vec![v4_message()]))
                .wait()
                .unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]
        );

        // only ipv6 available
        assert_eq!(
            ipv4_and_ipv6(Name::root(), &mut mock(vec![v6_message()]))
                .wait()
                .unwrap(),
            vec![IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]
        );
    }

    #[test]
    fn test_ipv6_then_ipv4_strategy() {
        // ipv6 first
        assert_eq!(
            ipv6_then_ipv4(Name::root(), &mut mock(vec![v6_message()]))
                .wait()
                .unwrap(),
            vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)]
        );

        // nothing then ipv4
        assert_eq!(
            ipv6_then_ipv4(Name::root(), &mut mock(vec![v4_message(), Message::new()]))
                .wait()
                .unwrap(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );
    }

    #[test]
    fn test_ipv4_then_ipv6_strategy() {
        // ipv6 first
        assert_eq!(
            ipv4_then_ipv6(Name::root(), &mut mock(vec![v4_message()]))
                .wait()
                .unwrap(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );

        // nothing then ipv6
        assert_eq!(
            ipv4_then_ipv6(Name::root(), &mut mock(vec![v6_message(), Message::new()]))
                .wait()
                .unwrap(),
            vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)]
        );
    }
}