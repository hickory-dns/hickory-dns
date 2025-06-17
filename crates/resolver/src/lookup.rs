// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Lookup result from a resolution of ipv4 and ipv6 records with a Resolver.

use std::{
    cmp::min,
    marker::PhantomData,
    slice::Iter,
    sync::Arc,
    time::{Duration, Instant},
};

use hickory_proto::rr::RecordData;

use crate::{
    cache::MAX_TTL,
    lookup_ip::LookupIpIter,
    proto::{
        op::Query,
        rr::{RData, Record, rdata},
    },
};

#[cfg(feature = "__dnssec")]
use crate::proto::dnssec::Proven;

/// Result of a DNS query when querying for any record type supported by the Hickory DNS Proto library.
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

    /// Returns an iterator over the data of all records returned during the query.
    ///
    /// It may include additional record types beyond the queried type, e.g. CNAME.
    pub fn iter(&self) -> LookupIter<'_> {
        LookupIter(self.records.iter())
    }

    /// Returns a borrowed iterator of the returned data wrapped in a dnssec Proven type
    #[cfg(feature = "__dnssec")]
    pub fn dnssec_iter(&self) -> DnssecIter<'_> {
        DnssecIter(self.dnssec_record_iter())
    }

    /// Returns an iterator over all records returned during the query.
    ///
    /// It may include additional record types beyond the queried type, e.g. CNAME.
    pub fn record_iter(&self) -> LookupRecordIter<'_> {
        LookupRecordIter(self.records.iter())
    }

    /// Returns a borrowed iterator of the returned records wrapped in a dnssec Proven type
    #[cfg(feature = "__dnssec")]
    pub fn dnssec_record_iter(&self) -> DnssecLookupRecordIter<'_> {
        DnssecLookupRecordIter(self.records.iter())
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

    /// Returns an slice over all records that were returned during the query, this can include
    ///   additional record types beyond the queried type, e.g. CNAME.
    pub fn records(&self) -> &[Record] {
        self.records.as_ref()
    }

    /// Clones the inner vec, appends the other vec
    pub(crate) fn append(&self, other: Self) -> Self {
        let mut records = Vec::with_capacity(self.len() + other.len());
        records.extend_from_slice(&self.records);
        records.extend_from_slice(&other.records);

        // Choose the sooner deadline of the two lookups.
        let valid_until = min(self.valid_until(), other.valid_until());
        Self::new_with_deadline(self.query.clone(), Arc::from(records), valid_until)
    }

    /// Add new records to this lookup, without creating a new Lookup
    pub fn extend_records(&mut self, other: Vec<Record>) {
        let mut records = Vec::with_capacity(self.len() + other.len());
        records.extend_from_slice(&self.records);
        records.extend(other);
        self.records = Arc::from(records);
    }
}

/// Borrowed view of set of [`RData`]s returned from a Lookup
pub struct LookupIter<'a>(Iter<'a, Record>);

impl<'a> Iterator for LookupIter<'a> {
    type Item = &'a RData;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(Record::data)
    }
}

/// An iterator over record data with all data wrapped in a Proven type for dnssec validation
#[cfg(feature = "__dnssec")]
pub struct DnssecIter<'a>(DnssecLookupRecordIter<'a>);

#[cfg(feature = "__dnssec")]
impl<'a> Iterator for DnssecIter<'a> {
    type Item = Proven<&'a RData>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|r| r.map(Record::data))
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

/// An iterator over record data with all data wrapped in a Proven type for dnssec validation
#[cfg(feature = "__dnssec")]
pub struct DnssecLookupRecordIter<'a>(Iter<'a, Record>);

#[cfg(feature = "__dnssec")]
impl<'a> Iterator for DnssecLookupRecordIter<'a> {
    type Item = Proven<&'a Record>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(Proven::from)
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
    /// *Note*: That Hickory DNS performs a recursive lookup on SRV records for IPs if they were not included in the original request. If there are no IPs associated to the result, a subsequent query for the IPs via the `srv.target()` should not resolve to the IPs.
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
        iter.find_map(|rdata| match rdata {
            RData::SRV(data) => Some(data),
            _ => None,
        })
    }
}

/// Contains the results of a lookup for the associated RecordType
#[derive(Debug, Clone)]
pub struct TypedLookup<T> {
    inner: Lookup,
    _marker: PhantomData<T>,
}

impl<T> TypedLookup<T> {
    /// Returns an iterator over the matching records
    pub fn iter(&self) -> TypedLookupIter<'_, T> {
        TypedLookupIter {
            inner: self.inner.iter(),
            _marker: PhantomData,
        }
    }

    /// Returns a reference to the Query that was used to produce this result.
    pub fn query(&self) -> &Query {
        self.inner.query()
    }

    /// Returns the `Instant` at which this result is no longer valid.
    pub fn valid_until(&self) -> Instant {
        self.inner.valid_until()
    }

    /// Return a reference to the inner lookup
    ///
    /// This can be useful for getting all records from the request
    pub fn as_lookup(&self) -> &Lookup {
        &self.inner
    }
}

impl<T> From<Lookup> for TypedLookup<T> {
    fn from(inner: Lookup) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }
}

impl<T> From<TypedLookup<T>> for Lookup {
    fn from(typed_lookup: TypedLookup<T>) -> Self {
        typed_lookup.inner
    }
}

/// An iterator over the Lookup type
pub struct TypedLookupIter<'i, T> {
    inner: LookupIter<'i>,
    _marker: PhantomData<T>,
}

impl<'i, T: RecordData + 'i> Iterator for TypedLookupIter<'i, T> {
    type Item = &'i T;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.find_map(T::try_borrow)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    #[cfg(feature = "__dnssec")]
    use crate::proto::op::Query;
    use crate::proto::rr::rdata::A;
    use crate::proto::rr::{Name, RData, Record};

    use super::*;

    #[test]
    fn test_lookup_into_iter_arc() {
        let records = &[
            Record::from_rdata(
                Name::from_str("www.example.com.").unwrap(),
                80,
                RData::A(A::new(127, 0, 0, 1)),
            ),
            Record::from_rdata(
                Name::from_str("www.example.com.").unwrap(),
                80,
                RData::A(A::new(127, 0, 0, 2)),
            ),
        ];

        let mut lookup = LookupIter(records.iter());
        assert_eq!(lookup.next().unwrap(), &RData::A(A::new(127, 0, 0, 1)));
        assert_eq!(lookup.next().unwrap(), &RData::A(A::new(127, 0, 0, 2)));
        assert_eq!(lookup.next(), None);
    }

    #[test]
    #[cfg(feature = "__dnssec")]
    fn test_dnssec_lookup() {
        use hickory_proto::dnssec::Proof;

        let mut a1 = Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            80,
            RData::A(A::new(127, 0, 0, 1)),
        );
        a1.set_proof(Proof::Secure);

        let mut a2 = Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            80,
            RData::A(A::new(127, 0, 0, 2)),
        );
        a2.set_proof(Proof::Insecure);

        let lookup = Lookup {
            query: Query::default(),
            records: Arc::from([a1.clone(), a2.clone()]),
            valid_until: Instant::now(),
        };

        let mut lookup = lookup.dnssec_iter();

        assert_eq!(
            *lookup.next().unwrap().require(Proof::Secure).unwrap(),
            *a1.data()
        );
        assert_eq!(
            *lookup.next().unwrap().require(Proof::Insecure).unwrap(),
            *a2.data()
        );
        assert_eq!(lookup.next(), None);
    }
}
