
// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Lookup result from a resolution of ipv4 and ipv6 records with a Resolver.

use std::error::Error as StdError;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::mem;
use std::slice::Iter;
use std::sync::Arc;

use futures::{Async, future, Future, Poll, task};

use trust_dns::client::{BasicClientHandle, ClientHandle, RetryClientHandle, SecureClientHandle};
use trust_dns::error::ClientError;
use trust_dns::op::{Message, Query};
use trust_dns::rr::{Name, RecordType, RData};
use trust_dns::rr::rdata;
use trust_dns_proto::DnsHandle;

use lookup_state::CachingClient;
use name_server_pool::{ConnectionProvider, NameServerPool, StandardConnection};

/// Result of a DNS query when querying for any record type supported by the TRust-DNS Client library.
///
/// For IP resolution see LookIp, as it has more features for A and AAAA lookups.
#[derive(Debug, Clone)]
pub struct Lookup {
    rdatas: Arc<Vec<RData>>,
}

impl Lookup {
    /// Return new instance with given rdatas
    pub fn new(rdatas: Arc<Vec<RData>>) -> Self {
        Lookup { rdatas }
    }

    /// Returns a borrowed iterator of the returned IPs
    pub fn iter(&self) -> LookupIter {
        LookupIter(self.rdatas.iter())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rdatas.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.rdatas.len()
    }

    /// Clones the inner vec, appends the other vec
    pub(crate) fn append(&self, other: Lookup) -> Self {
        let mut rdatas = Vec::with_capacity(self.len() + other.len());
        rdatas.extend_from_slice(&*self.rdatas);
        rdatas.extend_from_slice(&*other.rdatas);

        Self::new(Arc::new(rdatas))
    }
}

/// Borrowed view of set of RDatas returned from a Lookup
pub struct LookupIter<'a>(Iter<'a, RData>);

impl<'a> Iterator for LookupIter<'a> {
    type Item = &'a RData;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

/// Different lookup options for the lookup attempts and validation
#[derive(Clone)]
#[doc(hidden)]
pub enum LookupEither<C: ClientHandle + 'static, P: ConnectionProvider<ConnHandle = C> + 'static> {
    Retry(RetryClientHandle<NameServerPool<C, P>>),
    Secure(SecureClientHandle<RetryClientHandle<NameServerPool<C, P>>>),
}

impl<C: ClientHandle, P: ConnectionProvider<ConnHandle = C>> DnsHandle for LookupEither<C, P> {
    // TODO: this should be a ResolverError.
    type Error = ClientError;

    fn send(&mut self, message: Message) -> Box<Future<Item = Message, Error = Self::Error>> {
        match *self {
            LookupEither::Retry(ref mut c) => c.send(message),
            LookupEither::Secure(ref mut c) => c.send(message),
        }
    }
}

impl<C: ClientHandle, P: ConnectionProvider<ConnHandle = C>> ClientHandle for LookupEither<C, P> {
    fn is_verifying_dnssec(&self) -> bool {
        match *self {
            LookupEither::Retry(ref c) => c.is_verifying_dnssec(),
            LookupEither::Secure(ref c) => c.is_verifying_dnssec(),
        }
    }
}

/// The Future returned from ResolverFuture when performing a lookup.
pub type LookupFuture = InnerLookupFuture<LookupEither<BasicClientHandle, StandardConnection>>;

/// The Future returned from ResolverFuture when performing a lookup.
#[doc(hidden)]
pub struct InnerLookupFuture<C: ClientHandle + 'static> {
    client_cache: CachingClient<C>,
    names: Vec<Name>,
    record_type: RecordType,
    future: Box<Future<Item = Lookup, Error = io::Error>>,
}

impl<C: ClientHandle + 'static> InnerLookupFuture<C> {
    /// Perform a lookup from a name and type to a set of RDatas
    ///
    /// # Arguments
    ///
    /// * `names` - a set of DNS names to attempt to resolve, they will be attempted in queue order, i.e. the first is `names.pop()`. Upon each failure, the next will be attempted.
    /// * `record_type` - type of record being sought
    /// * `client_cache` - cache with a connection to use for performing all lookups
    #[doc(hidden)]
    pub fn lookup(
        mut names: Vec<Name>,
        record_type: RecordType,
        mut client_cache: CachingClient<C>,
    ) -> Self {
        let name = names.pop().expect("can not lookup IPs for no names");

        let query = client_cache.lookup(Query::query(name, record_type));

        //        let query = lookup(name, record_type, client_cache.clone());
        InnerLookupFuture {
            client_cache: client_cache,
            names,
            record_type,
            future: Box::new(query),
        }
    }

    fn next_lookup<F: FnOnce() -> Poll<Lookup, io::Error>>(
        &mut self,
        otherwise: F,
    ) -> Poll<Lookup, io::Error> {
        let name = self.names.pop();
        if let Some(name) = name {
            let query = self.client_cache.lookup(
                Query::query(name, self.record_type),
            );

            mem::replace(&mut self.future, Box::new(query));
            // guarantee that we get scheduled for the next turn...
            task::current().notify();
            Ok(Async::NotReady)
        } else {
            otherwise()
        }
    }

    pub(crate) fn error<E: StdError>(client_cache: CachingClient<C>, error: E) -> Self {
        return InnerLookupFuture {
            // errors on names don't need to be cheap... i.e. this clone is unfortunate in this case.
            client_cache,
            names: vec![],
            record_type: RecordType::NULL,
            future: Box::new(future::err(
                io::Error::new(io::ErrorKind::Other, format!("{}", error)),
            )),
        };
    }
}

impl<C: ClientHandle + 'static> Future for InnerLookupFuture<C> {
    type Item = Lookup;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.future.poll() {
            Ok(Async::Ready(lookup_ip)) => {
                if lookup_ip.rdatas.len() == 0 {
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

/// Creates a Lookup result type from the specified components
macro_rules! lookup_type {
    ($l:ident, $i:ident, $f:ident, $r:path, $t:path) => {
/// Contains the results of a lookup for the associated RecordType
#[derive(Debug, Clone)]
pub struct $l(Lookup);

impl $l {
    /// Returns an iterator over the RData
    pub fn iter(&self) -> $i {
        $i(self.0.iter())
    }
}

impl From<Lookup> for $l {
    fn from(lookup: Lookup) -> Self {
        $l(lookup)
    }
}

/// An iterator over the Lookup type
pub struct $i<'i>(LookupIter<'i>);

impl<'i> Iterator for $i<'i> {
    type Item = &'i $t;

    fn next(&mut self) -> Option<Self::Item> {
        let iter: &mut _ = &mut self.0;
        iter.filter_map(|rdata| match *rdata {
            $r(ref data) => Some(data),
            _ => None,
        }).next()
    }
}

/// A Future while resolves to the Lookup type
pub struct $f(LookupFuture);

impl From<LookupFuture> for $f {
    fn from(lookup_future: LookupFuture) -> Self {
        $f(lookup_future)
    }
}

impl Future for $f {
    type Item = $l;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.0.poll() {
            Ok(Async::Ready(lookup)) => Ok(Async::Ready($l(lookup))),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(e) => Err(e),
        }
    }
}
    }
}

// Generate all Lookup record types
lookup_type!(
    ReverseLookup,
    ReverseLookupIter,
    ReverseLookupFuture,
    RData::PTR,
    Name
);
lookup_type!(
    Ipv4Lookup,
    Ipv4LookupIter,
    Ipv4LookupFuture,
    RData::A,
    Ipv4Addr
);
lookup_type!(
    Ipv6Lookup,
    Ipv6LookupIter,
    Ipv6LookupFuture,
    RData::AAAA,
    Ipv6Addr
);
lookup_type!(MxLookup, MxLookupIter, MxLookupFuture, RData::MX, rdata::MX);
lookup_type!(
    SrvLookup,
    SrvLookupIter,
    SrvLookupFuture,
    RData::SRV,
    rdata::SRV
);
lookup_type!(
    TxtLookup,
    TxtLookupIter,
    TxtLookupFuture,
    RData::TXT,
    rdata::TXT
);

#[cfg(test)]
pub mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};

    use futures::{future, Future};

    use trust_dns::client::ClientHandle;
    use trust_dns::error::*;
    use trust_dns::op::Message;
    use trust_dns::rr::{Name, Record, RData, RecordType};

    use super::*;

    #[derive(Clone)]
    pub struct MockClientHandle {
        messages: Arc<Mutex<Vec<ClientResult<Message>>>>,
    }

    impl DnsHandle for MockClientHandle {
        type Error = ClientError;

        fn send(&mut self, _: Message) -> Box<Future<Item = Message, Error = Self::Error>> {
            Box::new(future::result(
                self.messages.lock().unwrap().pop().unwrap_or(empty()),
            ))
        }
    }

    impl ClientHandle for MockClientHandle {
        fn is_verifying_dnssec(&self) -> bool {
            false
        }
    }

    pub fn v4_message() -> ClientResult<Message> {
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

    pub fn empty() -> ClientResult<Message> {
        Ok(Message::new())
    }

    pub fn error() -> ClientResult<Message> {
        Err(ClientErrorKind::Io.into())
    }

    pub fn mock(messages: Vec<ClientResult<Message>>) -> MockClientHandle {
        MockClientHandle { messages: Arc::new(Mutex::new(messages)) }
    }

    #[test]
    fn test_lookup() {
        assert_eq!(
            InnerLookupFuture::lookup(
                vec![Name::root()],
                RecordType::A,
                CachingClient::new(0, mock(vec![v4_message()])),
            ).wait()
                .unwrap()
                .iter()
                .map(|r| r.to_ip_addr().unwrap())
                .collect::<Vec<IpAddr>>(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );
    }

    #[test]
    fn test_error() {
        assert!(
            InnerLookupFuture::lookup(
                vec![Name::root()],
                RecordType::A,
                CachingClient::new(0, mock(vec![error()])),
            ).wait()
                .is_err()
        );
    }

    #[test]
    fn test_empty_no_response() {
        assert_eq!(
            InnerLookupFuture::lookup(
                vec![Name::root()],
                RecordType::A,
                CachingClient::new(0, mock(vec![empty()])),
            ).wait()
                .unwrap_err()
                .kind(),
            io::ErrorKind::AddrNotAvailable
        );
    }
}
