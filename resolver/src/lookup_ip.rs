
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

use futures::{Async, future, Future, Poll, task};

use trust_dns::client::ClientHandle;
use trust_dns::error::ClientError;
use trust_dns::op::Message;
use trust_dns::rr::{DNSClass, Name, RData, RecordType};

/// Result of a DNS query when querying for A or AAAA records.
#[derive(Debug)]
pub struct LookupIp {
    ips: Vec<IpAddr>,
}

impl LookupIp {
    fn new(ips: Vec<IpAddr>) -> Self {
        LookupIp { ips }
    }
}

impl Iterator for LookupIp {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.ips.pop()
    }
}

/// The Future returned from ResolverFuture when performing an A or AAAA lookup.
pub struct LookupIpFuture {
    future: Box<Future<Item = LookupIp, Error = io::Error>>,
}

impl LookupIpFuture {
    pub(crate) fn lookup<C: ClientHandle>(
        host: &str,
        query_type: RecordType,
        client: &mut C,
    ) -> Self {
        let name = match Name::parse(host, None) {
            Ok(name) => name,
            Err(err) => {
                return LookupIpFuture { future: Box::new(future::err(io::Error::from(err))) }
            }
        };

        let query = LookupIpState::lookup(name, query_type, client);
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
    Query(RecordType, Box<Future<Item = Message, Error = ClientError>>),
    Fin(Vec<IpAddr>),
}

impl LookupIpState {
    pub fn lookup<C: ClientHandle>(name: Name, query_type: RecordType, client: &mut C) -> Self {
        let query_future = client.query(name, DNSClass::IN, query_type);
        LookupIpState::Query(query_type, query_future)
    }

    fn transition_query(&mut self, message: &Message) {
        assert!(if let LookupIpState::Query(_, _) = *self {
            true
        } else {
            false
        });

        // TODO: evaluate all response settings, like truncation, etc.
        let answers = message
            .answers()
            .iter()
            .filter_map(|r| match *r.rdata() {
                RData::A(ipaddr) => Some(IpAddr::V4(ipaddr)),
                RData::AAAA(ipaddr) => Some(IpAddr::V6(ipaddr)),
                _ => None,
            })
            .collect();

        // transition 
        mem::replace(self, LookupIpState::Fin(answers));
    }
}

impl Future for LookupIpState {
    type Item = LookupIp;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // first transition any polling that is needed (mutable refs...)
        let poll;
        match *self {
            LookupIpState::Query(_, ref mut query) => {
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
            LookupIpState::Query(_, _) => {
                match poll {
                    Ok(Async::Ready(ref message)) => self.transition_query(message),
                    _ => panic!("should have returned earlier"),
                }
            }
            LookupIpState::Fin(_) => panic!("should have returned earlier"),
        }

        task::current().notify(); // yield
        Ok(Async::NotReady)
    }
}

mod tests {
    pub use super::*;


}