
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
    pub(crate) fn lookup<C: ClientHandle>(
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
    pub fn lookup<C: ClientHandle>(name: Name, strategy: LookupIpStrategy, client: &mut C) -> Self {
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

fn lookup<C: ClientHandle>(
    name: Name,
    strategy: LookupIpStrategy,
    client: &mut C,
) -> Box<Future<Item = Vec<IpAddr>, Error = ClientError>> {
    match strategy {
        LookupIpStrategy::Ipv4Only => ipv4_only(name, client),
        LookupIpStrategy::Ipv6Only => ipv6_only(name, client),
        LookupIpStrategy::Ipv4AndIpv6 => ipv4_and_ipv6(name, client),
        LookupIpStrategy::Ipv6thenIpv4 => unimplemented!(),
        LookupIpStrategy::Ipv4thenIpv6 => unimplemented!(),
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

fn ipv6_only<C: ClientHandle>(
    name: Name,
    client: &mut C,
) -> Box<Future<Item = Vec<IpAddr>, Error = ClientError>> {
    Box::new(client.query(name, DNSClass::IN, RecordType::AAAA).map(
        map_message_to_ipaddr,
    ))
}

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
                    // A record returned, get the other record result, or else just return record
                    Ok((mut ips, remaining_query)) => {
                        Box::new(remaining_query.then(move |query_res| match query_res {
                            /// join AAAA and A results
                            Ok(mut rem_ips) => {
                                rem_ips.append(&mut ips);
                                future::ok(rem_ips)
                            }
                            // AAAA failed, just return A
                            Err(_) => future::ok(ips),
                        })) as
                            // This cast is to resolve a comilation error, not sure of it's necessity
                            Box<Future<Item = Vec<IpAddr>, Error = ClientError>>
                    }

                    // A failed, just return the AAAA result
                    Err((_, remaining_query)) => Box::new(remaining_query),
                }
            }),
    )
}

// TODO: build some non-network tests which test all variants of the Strategies...