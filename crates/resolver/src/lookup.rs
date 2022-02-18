// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Lookup result from a resolution of ipv4 and ipv6 records with a Resolver.

use std::cmp::min;
use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::slice::Iter;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_util::stream::Stream;
use futures_util::{future, future::Future, FutureExt};

use proto::error::ProtoError;
use proto::op::Query;
use proto::rr::rdata;
use proto::rr::{Name, RData, Record, RecordType};
use proto::xfer::{DnsRequest, DnsRequestOptions, DnsResponse};
#[cfg(feature = "dnssec")]
use proto::DnssecDnsHandle;
use proto::{DnsHandle, RetryDnsHandle};

use crate::caching_client::CachingClient;
use crate::dns_lru::MAX_TTL;
use crate::error::*;
use crate::lookup_ip::LookupIpIter;
use crate::name_server::{ConnectionProvider, NameServerPool};

/// Result of a DNS query when querying for any record type supported by the Trust-DNS Proto library.
///
/// For IP resolution see LookupIp, as it has more features for A and AAAA lookups.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lookup {
    query: Query,
    records: Arc<[Record]>,
    valid_until: Instant,
}

impl Lookup {
    /// Return new instance with given rdata and the maximum TTL.
    pub fn from_rdata(query: Query, rdata: RData) -> Self {
        let record = Record::from_rdata(query.name().clone(), MAX_TTL, rdata);
        Self::new_with_max_ttl(query, Arc::from([record]))
    }

    /// Return new instance with given records and the maximum TTL.
    pub fn new_with_max_ttl(query: Query, records: Arc<[Record]>) -> Self {
        let valid_until = Instant::now() + Duration::from_secs(u64::from(MAX_TTL));
        Self {
            query,
            records,
            valid_until,
        }
    }

    /// Return a new instance with the given records and deadline.
    pub fn new_with_deadline(query: Query, records: Arc<[Record]>, valid_until: Instant) -> Self {
        Self {
            query,
            records,
            valid_until,
        }
    }

    /// Returns a reference to the `Query` that was used to produce this result.
    pub fn query(&self) -> &Query {
        &self.query
    }

    /// Returns a borrowed iterator of the returned IPs
    pub fn iter(&self) -> LookupIter<'_> {
        LookupIter(self.records.iter())
    }

    /// Returns a borrowed iterator of the returned IPs
    pub fn record_iter(&self) -> LookupRecordIter<'_> {
        LookupRecordIter(self.records.iter())
    }

    /// Returns the `Instant` at which this `Lookup` is no longer valid.
    pub fn valid_until(&self) -> Instant {
        self.valid_until
    }

    #[doc(hidden)]
    pub fn is_empty(&self) -> bool {
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
    pub(crate) fn append(&self, other: Self) -> Self {
        let mut records = Vec::with_capacity(self.len() + other.len());
        records.extend_from_slice(&*self.records);
        records.extend_from_slice(&*other.records);

        // Choose the sooner deadline of the two lookups.
        let valid_until = min(self.valid_until(), other.valid_until());
        Self::new_with_deadline(self.query.clone(), Arc::from(records), valid_until)
    }
}

/// Borrowed view of set of [`RData`]s returned from a Lookup
pub struct LookupIter<'a>(Iter<'a, Record>);

impl<'a> Iterator for LookupIter<'a> {
    type Item = &'a RData;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().and_then(Record::data)
    }
}

/// Borrowed view of set of [`Record`]s returned from a Lookup
pub struct LookupRecordIter<'a>(Iter<'a, Record>);

impl<'a> Iterator for LookupRecordIter<'a> {
    type Item = &'a Record;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

// TODO: consider removing this as it's not a zero-cost abstraction
impl IntoIterator for Lookup {
    type Item = RData;
    type IntoIter = LookupIntoIter;

    /// This is most likely not a free conversion, the `RData`s will be cloned if data is
    ///  held behind an Arc with more than one reference (which is most likely the case coming from cache)
    fn into_iter(self) -> Self::IntoIter {
        LookupIntoIter {
            records: Arc::clone(&self.records),
            index: 0,
        }
    }
}

/// Borrowed view of set of [`RData`]s returned from a [`Lookup`].
///
/// This is not usually a zero overhead `Iterator`, it may result in clones of the [`RData`].
pub struct LookupIntoIter {
    // the result of the try_unwrap on Arc
    records: Arc<[Record]>,
    index: usize,
}

impl Iterator for LookupIntoIter {
    type Item = RData;

    fn next(&mut self) -> Option<Self::Item> {
        let rdata = self.records.get(self.index).and_then(Record::data);
        self.index += 1;
        rdata.cloned()
    }
}

/// Different lookup options for the lookup attempts and validation
#[derive(Clone)]
#[doc(hidden)]
pub enum LookupEither<
    C: DnsHandle<Error = ResolveError> + 'static,
    P: ConnectionProvider<Conn = C> + 'static,
> {
    Retry(RetryDnsHandle<NameServerPool<C, P>>),
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    Secure(DnssecDnsHandle<RetryDnsHandle<NameServerPool<C, P>>>),
}

impl<C: DnsHandle<Error = ResolveError> + Sync, P: ConnectionProvider<Conn = C>> DnsHandle
    for LookupEither<C, P>
{
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ResolveError>> + Send>>;
    type Error = ResolveError;

    fn is_verifying_dnssec(&self) -> bool {
        match *self {
            LookupEither::Retry(ref c) => c.is_verifying_dnssec(),
            #[cfg(feature = "dnssec")]
            LookupEither::Secure(ref c) => c.is_verifying_dnssec(),
        }
    }

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&mut self, request: R) -> Self::Response {
        match *self {
            LookupEither::Retry(ref mut c) => c.send(request),
            #[cfg(feature = "dnssec")]
            LookupEither::Secure(ref mut c) => c.send(request),
        }
    }
}

/// The Future returned from [`AsyncResolver`] when performing a lookup.
#[doc(hidden)]
pub struct LookupFuture<C, E>
where
    C: DnsHandle<Error = E> + 'static,
    E: Into<ResolveError> + From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    client_cache: CachingClient<C, E>,
    names: Vec<Name>,
    record_type: RecordType,
    options: DnsRequestOptions,
    query: Pin<Box<dyn Future<Output = Result<Lookup, ResolveError>> + Send>>,
}

impl<C, E> LookupFuture<C, E>
where
    C: DnsHandle<Error = E> + 'static,
    E: Into<ResolveError> + From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
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
        mut client_cache: CachingClient<C, E>,
    ) -> Self {
        let name = names.pop().ok_or_else(|| {
            ResolveError::from(ResolveErrorKind::Message("can not lookup for no names"))
        });

        let query: Pin<Box<dyn Future<Output = Result<Lookup, ResolveError>> + Send>> = match name {
            Ok(name) => client_cache
                .lookup(Query::query(name, record_type), options)
                .boxed(),
            Err(err) => future::err(err).boxed(),
        };

        Self {
            client_cache,
            names,
            record_type,
            options,
            query,
        }
    }
}

impl<C, E> Future for LookupFuture<C, E>
where
    C: DnsHandle<Error = E> + 'static,
    E: Into<ResolveError> + From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    type Output = Result<Lookup, ResolveError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            // Try polling the underlying DNS query.
            let query = self.query.as_mut().poll_unpin(cx);

            // Determine whether or not we will attempt to retry the query.
            let should_retry = match query {
                // If the query is NotReady, yield immediately.
                Poll::Pending => return Poll::Pending,
                // If the query returned a successful lookup, we will attempt
                // to retry if the lookup is empty. Otherwise, we will return
                // that lookup.
                Poll::Ready(Ok(ref lookup)) => lookup.records.len() == 0,
                // If the query failed, we will attempt to retry.
                Poll::Ready(Err(_)) => true,
            };

            if should_retry {
                if let Some(name) = self.names.pop() {
                    let record_type = self.record_type;
                    let options = self.options;

                    // If there's another name left to try, build a new query
                    // for that next name and continue looping.
                    self.query = self
                        .client_cache
                        .lookup(Query::query(name, record_type), options);
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
    pub fn iter(&self) -> SrvLookupIter<'_> {
        SrvLookupIter(self.0.iter())
    }

    /// Returns a reference to the Query that was used to produce this result.
    pub fn query(&self) -> &Query {
        self.0.query()
    }

    /// Returns the list of IPs associated with the SRV record.
    ///
    /// *Note*: That Trust-DNS performs a recursive lookup on SRV records for IPs if they were not included in the original request. If there are no IPs associated to the result, a subsequent query for the IPs via the `srv.target()` should not resolve to the IPs.
    pub fn ip_iter(&self) -> LookupIpIter<'_> {
        LookupIpIter(self.0.iter())
    }

    /// Return a reference to the inner lookup
    ///
    /// This can be useful for getting all records from the request
    pub fn as_lookup(&self) -> &Lookup {
        &self.0
    }
}

impl From<Lookup> for SrvLookup {
    fn from(lookup: Lookup) -> Self {
        Self(lookup)
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
        })
        .next()
    }
}

impl IntoIterator for SrvLookup {
    type Item = rdata::SRV;
    type IntoIter = SrvLookupIntoIter;

    /// This is most likely not a free conversion, the RDatas will be cloned if data is
    ///  held behind an Arc with more than one reference (which is most likely the case coming from cache)
    fn into_iter(self) -> Self::IntoIter {
        SrvLookupIntoIter(self.0.into_iter())
    }
}

/// Borrowed view of set of RDatas returned from a Lookup
pub struct SrvLookupIntoIter(LookupIntoIter);

impl Iterator for SrvLookupIntoIter {
    type Item = rdata::SRV;

    fn next(&mut self) -> Option<Self::Item> {
        let iter: &mut _ = &mut self.0;
        iter.filter_map(|rdata| match rdata {
            RData::SRV(data) => Some(data),
            _ => None,
        })
        .next()
    }
}

/// Creates a Lookup result type from the specified components
macro_rules! lookup_type {
    ($l:ident, $i:ident, $ii:ident, $r:path, $t:path) => {
        /// Contains the results of a lookup for the associated RecordType
        #[derive(Debug, Clone)]
        pub struct $l(Lookup);

        impl $l {
            /// Returns an iterator over the RData
            pub fn iter(&self) -> $i<'_> {
                $i(self.0.iter())
            }

            /// Returns a reference to the Query that was used to produce this result.
            pub fn query(&self) -> &Query {
                self.0.query()
            }

            /// Returns the `Instant` at which this result is no longer valid.
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
                })
                .next()
            }
        }

        impl IntoIterator for $l {
            type Item = $t;
            type IntoIter = $ii;

            /// This is most likely not a free conversion, the RDatas will be cloned if data is
            ///  held behind an Arc with more than one reference (which is most likely the case coming from cache)
            fn into_iter(self) -> Self::IntoIter {
                $ii(self.0.into_iter())
            }
        }

        /// Borrowed view of set of RDatas returned from a Lookup
        pub struct $ii(LookupIntoIter);

        impl Iterator for $ii {
            type Item = $t;

            fn next(&mut self) -> Option<Self::Item> {
                let iter: &mut _ = &mut self.0;
                iter.filter_map(|rdata| match rdata {
                    $r(data) => Some(data),
                    _ => None,
                })
                .next()
            }
        }
    };
}

// Generate all Lookup record types
lookup_type!(
    ReverseLookup,
    ReverseLookupIter,
    ReverseLookupIntoIter,
    RData::PTR,
    Name
);
lookup_type!(
    Ipv4Lookup,
    Ipv4LookupIter,
    Ipv4LookupIntoIter,
    RData::A,
    Ipv4Addr
);
lookup_type!(
    Ipv6Lookup,
    Ipv6LookupIter,
    Ipv6LookupIntoIter,
    RData::AAAA,
    Ipv6Addr
);
lookup_type!(
    MxLookup,
    MxLookupIter,
    MxLookupIntoIter,
    RData::MX,
    rdata::MX
);
lookup_type!(
    TlsaLookup,
    TlsaLookupIter,
    TlsaLookupIntoIter,
    RData::TLSA,
    rdata::TLSA
);
lookup_type!(
    TxtLookup,
    TxtLookupIter,
    TxtLookupIntoIter,
    RData::TXT,
    rdata::TXT
);
lookup_type!(
    SoaLookup,
    SoaLookupIter,
    SoaLookupIntoIter,
    RData::SOA,
    rdata::SOA
);
lookup_type!(NsLookup, NsLookupIter, NsLookupIntoIter, RData::NS, Name);

#[cfg(test)]
pub mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    use futures_executor::block_on;
    use futures_util::future;
    use futures_util::stream::once;

    use proto::op::{Message, Query};
    use proto::rr::{Name, RData, Record, RecordType};
    use proto::xfer::{DnsRequest, DnsRequestOptions};

    use super::*;
    use crate::error::ResolveError;

    #[derive(Clone)]
    pub struct MockDnsHandle {
        messages: Arc<Mutex<Vec<Result<DnsResponse, ResolveError>>>>,
    }

    impl DnsHandle for MockDnsHandle {
        type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ResolveError>> + Send>>;
        type Error = ResolveError;

        fn send<R: Into<DnsRequest>>(&mut self, _: R) -> Self::Response {
            Box::pin(once(
                future::ready(self.messages.lock().unwrap().pop().unwrap_or_else(empty)).boxed(),
            ))
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

    pub fn empty() -> Result<DnsResponse, ResolveError> {
        Ok(Message::new().into())
    }

    pub fn error() -> Result<DnsResponse, ResolveError> {
        Err(ResolveError::from(ProtoError::from(std::io::Error::from(
            std::io::ErrorKind::Other,
        ))))
    }

    pub fn mock(messages: Vec<Result<DnsResponse, ResolveError>>) -> MockDnsHandle {
        MockDnsHandle {
            messages: Arc::new(Mutex::new(messages)),
        }
    }

    #[test]
    fn test_lookup() {
        assert_eq!(
            block_on(LookupFuture::lookup(
                vec![Name::root()],
                RecordType::A,
                DnsRequestOptions::default(),
                CachingClient::new(0, mock(vec![v4_message()]), false),
            ))
            .unwrap()
            .iter()
            .map(|r| r.to_ip_addr().unwrap())
            .collect::<Vec<IpAddr>>(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );
    }

    #[test]
    fn test_lookup_into_iter() {
        assert_eq!(
            block_on(LookupFuture::lookup(
                vec![Name::root()],
                RecordType::A,
                DnsRequestOptions::default(),
                CachingClient::new(0, mock(vec![v4_message()]), false),
            ))
            .unwrap()
            .into_iter()
            .map(|r| r.to_ip_addr().unwrap())
            .collect::<Vec<IpAddr>>(),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );
    }

    #[test]
    fn test_error() {
        assert!(block_on(LookupFuture::lookup(
            vec![Name::root()],
            RecordType::A,
            DnsRequestOptions::default(),
            CachingClient::new(0, mock(vec![error()]), false),
        ))
        .is_err());
    }

    #[test]
    fn test_empty_no_response() {
        if let ResolveErrorKind::NoRecordsFound {
            query,
            negative_ttl,
            ..
        } = block_on(LookupFuture::lookup(
            vec![Name::root()],
            RecordType::A,
            DnsRequestOptions::default(),
            CachingClient::new(0, mock(vec![empty()]), false),
        ))
        .unwrap_err()
        .kind()
        {
            assert_eq!(**query, Query::query(Name::root(), RecordType::A));
            assert_eq!(*negative_ttl, None);
        } else {
            panic!("wrong error recieved");
        }
    }

    #[test]
    fn test_lookup_into_iter_arc() {
        let mut lookup = LookupIntoIter {
            records: Arc::from([
                Record::from_rdata(
                    Name::from_str("www.example.com.").unwrap(),
                    80,
                    RData::A(Ipv4Addr::new(127, 0, 0, 1)),
                ),
                Record::from_rdata(
                    Name::from_str("www.example.com.").unwrap(),
                    80,
                    RData::A(Ipv4Addr::new(127, 0, 0, 2)),
                ),
            ]),
            index: 0,
        };

        assert_eq!(
            lookup.next().unwrap(),
            RData::A(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(
            lookup.next().unwrap(),
            RData::A(Ipv4Addr::new(127, 0, 0, 2))
        );
        assert_eq!(lookup.next(), None);
    }
}
