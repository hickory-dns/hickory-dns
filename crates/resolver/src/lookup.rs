// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Lookup result from a resolution of ipv4 and ipv6 records with a Resolver.

use std::cmp::min;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::slice::Iter;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{future, Async, Future, Poll};

use proto::error::ProtoError;
use proto::op::Query;
use proto::rr::rdata;
use proto::rr::{Name, RData, RecordType, Record};
use proto::xfer::{DnsRequest, DnsRequestOptions, DnsResponse};
#[cfg(feature = "dnssec")]
use proto::SecureDnsHandle;
use proto::{DnsHandle, RetryDnsHandle};

use dns_lru::MAX_TTL;
use error::*;
use lookup_ip::LookupIpIter;
use lookup_state::CachingClient;
use name_server::{ConnectionHandle, ConnectionProvider, NameServerPool, StandardConnection};

/// Result of a DNS query when querying for any record type supported by the Trust-DNS Proto library.
///
/// For IP resolution see LookupIp, as it has more features for A and AAAA lookups.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lookup {
    query: Query,
    records: Arc<Vec<Record>>,
    valid_until: Instant,
}

impl Lookup {
    /// Return new instance with given rdata and the maximum TTL.
    pub fn from_rdata(query: Query, rdata: RData) -> Self {
        let record = Record::from_rdata(query.name().clone(), MAX_TTL, rdata);
        Self::new_with_max_ttl(query, Arc::new(vec![record]))
    }

    /// Return new instance with given records and the maximum TTL.
    pub fn new_with_max_ttl(query: Query, records: Arc<Vec<Record>>) -> Self {
        let valid_until = Instant::now() + Duration::from_secs(u64::from(MAX_TTL));
        Lookup {
            query,
            records,
            valid_until,
        }
    }

    /// Return a new instance with the given records and deadline.
    pub fn new_with_deadline(query: Query, records: Arc<Vec<Record>>, valid_until: Instant) -> Self {
        Lookup {
            query,
            records,
            valid_until,
        }
    }

    /// Returns a reference to the Query that was used to produce this result.
    pub fn query(&self) -> &Query {
        &self.query
    }

    /// Returns a borrowed iterator of the returned IPs
    pub fn iter(&self) -> LookupIter {
        LookupIter(self.records.iter())
    }

    /// Returns the `Instant` at which this `Lookup` is no longer valid.
    pub fn valid_until(&self) -> Instant {
        self.valid_until
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.records.len()
    }

    #[cfg(test)]
    pub fn records(&self) -> &[Record] {
        self.records.as_ref()
    }

    /// Clones the inner vec, appends the other vec
    pub(crate) fn append(&self, other: Lookup) -> Self {
        let mut records = Vec::with_capacity(self.len() + other.len());
        records.extend_from_slice(&*self.records);
        records.extend_from_slice(&*other.records);

        // Choose the sooner deadline of the two lookups.
        let valid_until = min(self.valid_until(), other.valid_until());
        Self::new_with_deadline(self.query.clone(), Arc::new(records), valid_until)
    }
}

/// Borrowed view of set of RDatas returned from a Lookup
pub struct LookupIter<'a>(Iter<'a, Record>);

impl<'a> Iterator for LookupIter<'a> {
    type Item = &'a RData;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|r| r.rdata())
    }
}

/// Different lookup options for the lookup attempts and validation
#[derive(Clone)]
#[doc(hidden)]
pub enum LookupEither<C: DnsHandle + 'static, P: ConnectionProvider<ConnHandle = C> + 'static> {
    Retry(RetryDnsHandle<NameServerPool<C, P>>),
    #[cfg(feature = "dnssec")]
    Secure(SecureDnsHandle<RetryDnsHandle<NameServerPool<C, P>>>),
}

impl<C: DnsHandle, P: ConnectionProvider<ConnHandle = C>> DnsHandle for LookupEither<C, P> {
    type Response = Box<Future<Item = DnsResponse, Error = ProtoError> + Send>;

    fn is_verifying_dnssec(&self) -> bool {
        match *self {
            LookupEither::Retry(ref c) => c.is_verifying_dnssec(),
            #[cfg(feature = "dnssec")]
            LookupEither::Secure(ref c) => c.is_verifying_dnssec(),
        }
    }

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> Self::Response {
        match *self {
            LookupEither::Retry(ref mut c) => c.send(request),
            #[cfg(feature = "dnssec")]
            LookupEither::Secure(ref mut c) => c.send(request),
        }
    }
}

/// The Future returned from ResolverFuture when performing a lookup.
#[doc(hidden)]
pub struct LookupFuture<C = LookupEither<ConnectionHandle, StandardConnection>>
where
    C: DnsHandle + 'static,
{
    client_cache: CachingClient<C>,
    names: Vec<Name>,
    record_type: RecordType,
    options: DnsRequestOptions,
    query: Box<Future<Item = Lookup, Error = ResolveError> + Send>,
}

impl<C: DnsHandle + 'static> LookupFuture<C> {
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
        options: DnsRequestOptions,
        mut client_cache: CachingClient<C>,
    ) -> Self {
        let name = names.pop().ok_or_else(|| {
            ResolveError::from(ResolveErrorKind::Message("can not lookup for no names"))
        });

        let query: Box<Future<Item = Lookup, Error = ResolveError> + Send> = match name {
            Ok(name) => {
                Box::new(client_cache.lookup(Query::query(name, record_type), options.clone()))
            }
            Err(err) => Box::new(future::err(err)),
        };

        LookupFuture {
            client_cache,
            names,
            record_type,
            options,
            query,
        }
    }
}

impl<C: DnsHandle + 'static> Future for LookupFuture<C> {
    type Item = Lookup;
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
                Ok(Async::Ready(ref lookup)) => lookup.records.len() == 0,
                // If the query failed, we will attempt to retry.
                Err(_) => true,
            };

            if should_retry {
                if let Some(name) = self.names.pop() {
                    // If there's another name left to try, build a new query
                    // for that next name and continue looping.
                    self.query = self
                        .client_cache
                        .lookup(Query::query(name, self.record_type), self.options.clone());
                    // Continue looping with the new query. It will be polled
                    // on the next iteration of the loop.
                    continue;
                }
            }
            // If we didn't have to retry the query, or we weren't able to
            // retry because we've exhausted the names to search, return the
            // current query.
            return query;
            // If we skipped retrying the  query, this will return the
            // successful lookup, otherwise, if the retry failed, this will
            // return the last  query result --- either an empty lookup or the
            // last error we saw.
        }
    }
}

/// The result of an SRV lookup
#[derive(Debug, Clone)]
pub struct SrvLookup(Lookup);

impl SrvLookup {
    /// Returns an iterator over the SRV RData
    pub fn iter(&self) -> SrvLookupIter {
        SrvLookupIter(self.0.iter())
    }

    /// Returns a reference to the Query that was used to produce this result.
    pub fn query(&self) -> &Query {
        self.0.query()
    }

    /// Returns the list of IPs associated with the SRV record.
    ///
    /// *Note*: the lack of any IPs does not necessarily meant that there are no IPs available for the service, only that they were not included in the original request. A subsequent query for the IPs via the `srv.target()` should resolve to the IPs.
    pub fn ip_iter(&self) -> LookupIpIter {
        LookupIpIter(self.0.iter())
    }
}

impl From<Lookup> for SrvLookup {
    fn from(lookup: Lookup) -> Self {
        SrvLookup(lookup)
    }
}

/// An iterator over the Lookup type
pub struct SrvLookupIter<'i>(LookupIter<'i>);

impl<'i> Iterator for SrvLookupIter<'i> {
    type Item = &'i rdata::SRV;

    fn next(&mut self) -> Option<Self::Item> {
        let iter: &mut _ = &mut self.0;
        iter.filter_map(|rdata| match *rdata {
            RData::SRV(ref data) => Some(data),
            _ => None,
        }).next()
    }
}

/// A Future while resolves to the Lookup type
pub struct SrvLookupFuture(LookupFuture);

impl From<LookupFuture> for SrvLookupFuture {
    fn from(lookup_future: LookupFuture) -> Self {
        SrvLookupFuture(lookup_future)
    }
}

impl Future for SrvLookupFuture {
    type Item = SrvLookup;
    type Error = ResolveError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.0.poll() {
            Ok(Async::Ready(lookup)) => Ok(Async::Ready(SrvLookup(lookup))),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(e) => Err(e),
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

            /// Returns a reference to the Query that was used to produce this result.
            pub fn query(&self) -> &Query {
                self.0.query()
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
            type Error = ResolveError;

            fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
                match self.0.poll() {
                    Ok(Async::Ready(lookup)) => Ok(Async::Ready($l(lookup))),
                    Ok(Async::NotReady) => Ok(Async::NotReady),
                    Err(e) => Err(e),
                }
            }
        }
    };
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

    use proto::error::{ProtoErrorKind, ProtoResult};
    use proto::op::Message;
    use proto::rr::{Name, RData, Record, RecordType};
    use proto::xfer::{DnsRequest, DnsRequestOptions};

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

    pub fn empty() -> ProtoResult<DnsResponse> {
        Ok(Message::new().into())
    }

    pub fn error() -> ProtoResult<DnsResponse> {
        Err(ProtoErrorKind::Io.into())
    }

    pub fn mock(messages: Vec<ProtoResult<DnsResponse>>) -> MockDnsHandle {
        MockDnsHandle {
            messages: Arc::new(Mutex::new(messages)),
        }
    }

    #[test]
    fn test_lookup() {
        assert_eq!(
            LookupFuture::lookup(
                vec![Name::root()],
                RecordType::A,
                DnsRequestOptions::default(),
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
            LookupFuture::lookup(
                vec![Name::root()],
                RecordType::A,
                DnsRequestOptions::default(),
                CachingClient::new(0, mock(vec![error()])),
            ).wait()
            .is_err()
        );
    }

    #[test]
    fn test_empty_no_response() {
        assert_eq!(
            *LookupFuture::lookup(
                vec![Name::root()],
                RecordType::A,
                DnsRequestOptions::default(),
                CachingClient::new(0, mock(vec![empty()])),
            ).wait()
            .unwrap_err()
            .kind(),
            ResolveErrorKind::NoRecordsFound {
                query: Query::query(Name::root(), RecordType::A),
                valid_until: None,
            }
        );
    }
}
