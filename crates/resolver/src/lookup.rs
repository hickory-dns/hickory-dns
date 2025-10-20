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
    sync::Arc,
    time::{Duration, Instant},
};

use hickory_proto::rr::RecordData;

use crate::{
    cache::MAX_TTL,
    lookup_ip::LookupIpIter,
    proto::{
        op::{Message, Query},
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
    message: Message,
    valid_until: Instant,
}

impl Lookup {
    /// Create a new Lookup from a complete DNS Message.
    pub fn new(query: Query, message: Message, valid_until: Instant) -> Self {
        Self {
            query,
            message,
            valid_until,
        }
    }

    /// Return new instance with given rdata and the maximum TTL.
    pub fn from_rdata(query: Query, rdata: RData) -> Self {
        let record = Record::from_rdata(query.name().clone(), MAX_TTL, rdata);
        Self::new_with_max_ttl(query, Arc::from([record]))
    }

    /// Return new instance with given records and the maximum TTL.
    pub fn new_with_max_ttl(query: Query, records: Arc<[Record]>) -> Self {
        let valid_until = Instant::now() + Duration::from_secs(u64::from(MAX_TTL));
        Self::new_with_deadline(query, records, valid_until)
    }

    /// Return a new instance with the given records and deadline.
    pub fn new_with_deadline(query: Query, records: Arc<[Record]>, valid_until: Instant) -> Self {
        // Build a response Message with the records in the answers section
        let mut message = Message::response(0, crate::proto::op::OpCode::Query);
        message.add_query(query.clone());
        message.add_answers(records.iter().cloned());

        Self {
            query,
            message,
            valid_until,
        }
    }

    /// Returns a reference to the `Query` that was used to produce this result.
    pub fn query(&self) -> &Query {
        &self.query
    }

    /// Returns a reference to the underlying DNS Message.
    pub fn message(&self) -> &Message {
        &self.message
    }

    /// Returns a borrowed iterator of the answer records wrapped in a dnssec Proven type
    #[cfg(feature = "__dnssec")]
    pub fn dnssec_answers(&self) -> DnssecIter<'_> {
        DnssecIter(DnssecLookupRecordIter::new(self.message.answers().iter()))
    }

    /// Returns the `Instant` at which this `Lookup` is no longer valid.
    pub fn valid_until(&self) -> Instant {
        self.valid_until
    }

    /// Combine two lookup results, preserving section structure
    ///
    /// Appends records from each section of `other` to the corresponding section of `self`.
    pub(crate) fn append(&self, other: Self) -> Self {
        // Clone self to get a mutable copy
        let mut result = self.clone();

        // Append each section separately to preserve structure
        result
            .message
            .add_answers(other.message.answers().iter().cloned());
        for authority in other.message.authorities() {
            result.message.add_authority(authority.clone());
        }
        result
            .message
            .add_additionals(other.message.additionals().iter().cloned());

        // Choose the sooner deadline of the two lookups
        result.valid_until = min(self.valid_until(), other.valid_until());

        result
    }

    /// Add new records to this lookup, without creating a new Lookup
    ///
    /// Records are added to the ANSWERS section while preserving existing section structure
    pub fn extend_records(&mut self, other: Vec<Record>) {
        // Add new records to the answers section, preserving existing sections
        self.message.add_answers(other);
    }
}

/// Borrowed view of set of [`RData`]s returned from a Lookup
pub struct LookupIter<'a>(Box<dyn Iterator<Item = &'a Record> + 'a>);

impl<'a> LookupIter<'a> {
    /// Create a new LookupIter from an iterator over Records
    pub(crate) fn new(iter: impl Iterator<Item = &'a Record> + 'a) -> Self {
        Self(Box::new(iter))
    }
}

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

/// An iterator over record data with all data wrapped in a Proven type for dnssec validation
#[cfg(feature = "__dnssec")]
pub struct DnssecLookupRecordIter<'a>(Box<dyn Iterator<Item = &'a Record> + 'a>);

#[cfg(feature = "__dnssec")]
impl<'a> DnssecLookupRecordIter<'a> {
    fn new(iter: impl Iterator<Item = &'a Record> + 'a) -> Self {
        Self(Box::new(iter))
    }
}

#[cfg(feature = "__dnssec")]
impl<'a> Iterator for DnssecLookupRecordIter<'a> {
    type Item = Proven<&'a Record>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(Proven::from)
    }
}

// TODO: consider removing this as it's not a zero-cost abstraction
impl IntoIterator for Lookup {
    type Item = RData;
    type IntoIter = LookupIntoIter;

    /// This is not a free conversion, because the `RData`s are cloned.
    fn into_iter(self) -> Self::IntoIter {
        // Convert answers to Arc<[Record]> for iteration
        let answers: Arc<[Record]> = Arc::from(self.message.answers());
        LookupIntoIter {
            records: answers,
            index: 0,
        }
    }
}

/// Borrowed view of set of [`RData`]s returned from a [`Lookup`].
///
/// This is not a zero overhead `Iterator`, because it clones each [`RData`].
pub struct LookupIntoIter {
    records: Arc<[Record]>,
    index: usize,
}

impl Iterator for LookupIntoIter {
    type Item = RData;

    fn next(&mut self) -> Option<Self::Item> {
        let rdata = self.records.get(self.index).map(Record::data);
        self.index += 1;
        rdata.cloned()
    }
}

/// The result of an SRV lookup
#[derive(Debug, Clone)]
pub struct SrvLookup(Lookup);

impl SrvLookup {
    /// Returns an iterator over the SRV RData
    ///
    /// For backwards compatibility, this returns records from all sections (ANSWER, AUTHORITY, ADDITIONAL).
    pub fn iter(&self) -> SrvLookupIter<'_> {
        SrvLookupIter(LookupIter::new(self.0.message().all_sections()))
    }

    /// Returns a reference to the Query that was used to produce this result.
    pub fn query(&self) -> &Query {
        self.0.query()
    }

    /// Returns the list of IPs associated with the SRV record.
    ///
    /// *Note*: That Hickory DNS performs a recursive lookup on SRV records for IPs if they were not included in the original request. If there are no IPs associated to the result, a subsequent query for the IPs via the `srv.target()` should not resolve to the IPs.
    pub fn ip_iter(&self) -> LookupIpIter<'_> {
        // Use all_sections() to get IPs from ANSWER and ADDITIONAL sections
        // (ADDITIONAL may contain glue records for SRV targets)
        LookupIpIter(LookupIter::new(self.0.message().all_sections()))
    }

    /// Returns a reference to the underlying DNS Message
    pub fn as_message(&self) -> &Message {
        self.0.message()
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
    ///
    /// For backwards compatibility, this returns records from all sections (ANSWER, AUTHORITY, ADDITIONAL).
    pub fn iter(&self) -> TypedLookupIter<'_, T> {
        TypedLookupIter {
            inner: LookupIter::new(self.inner.message().all_sections()),
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

    /// Returns a reference to the underlying DNS Message
    pub fn as_message(&self) -> &Message {
        self.inner.message()
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

        let mut lookup = LookupIter::new(records.iter());
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

        // Build a response Message with the records
        let mut message = Message::response(0, crate::proto::op::OpCode::Query);
        message.add_query(Query::default());
        message.add_answers([a1.clone(), a2.clone()]);

        let lookup = Lookup {
            query: Query::default(),
            message,
            valid_until: Instant::now(),
        };

        let mut lookup = lookup.dnssec_answers();

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

    #[test]
    fn test_extend_records_preserves_sections() {
        use crate::proto::op::OpCode;
        use crate::proto::rr::rdata::NS;

        // Create a message with records in different sections
        let mut message = Message::response(0, OpCode::Query);
        let query = Query::query(
            Name::from_str("www.example.com.").unwrap(),
            crate::proto::rr::RecordType::A,
        );
        message.add_query(query.clone());

        // Add answer
        message.add_answers(vec![Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            80,
            RData::A(A::new(127, 0, 0, 1)),
        )]);

        // Add authority
        message.add_authority(Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            80,
            RData::NS(NS(Name::from_str("ns1.example.com.").unwrap())),
        ));

        // Add additional
        message.add_additionals(vec![Record::from_rdata(
            Name::from_str("ns1.example.com.").unwrap(),
            80,
            RData::A(A::new(192, 0, 2, 1)),
        )]);

        let mut lookup = Lookup {
            query,
            message,
            valid_until: Instant::now(),
        };

        // Extend with new answer record
        let new_record = Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            80,
            RData::A(A::new(127, 0, 0, 2)),
        );
        lookup.extend_records(vec![new_record.clone()]);

        // Verify that lookup.message was updated (not just a temporary reference)
        assert_eq!(lookup.message.answers().len(), 2);
        assert_eq!(lookup.message.answers()[1], new_record);

        // Verify sections were preserved
        assert_eq!(lookup.message.authorities().len(), 1);
        assert_eq!(lookup.message.additionals().len(), 1);

        // Verify the authority and additional records are intact
        if let RData::NS(ns) = lookup.message.authorities()[0].data() {
            assert_eq!(ns.0, Name::from_str("ns1.example.com.").unwrap());
        } else {
            panic!("Authority record should be NS");
        }

        if let RData::A(a) = lookup.message.additionals()[0].data() {
            assert_eq!(*a, A::new(192, 0, 2, 1));
        } else {
            panic!("Additional record should be A");
        }
    }

    #[test]
    fn test_append_preserves_sections() {
        use crate::proto::op::OpCode;
        use crate::proto::rr::rdata::NS;

        // Create first lookup with records in all sections
        let mut message1 = Message::response(0, OpCode::Query);
        let query = Query::query(
            Name::from_str("www.example.com.").unwrap(),
            crate::proto::rr::RecordType::A,
        );
        message1.add_query(query.clone());
        message1.add_answers(vec![Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            80,
            RData::A(A::new(127, 0, 0, 1)),
        )]);
        message1.add_authority(Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            80,
            RData::NS(NS(Name::from_str("ns1.example.com.").unwrap())),
        ));
        message1.add_additionals(vec![Record::from_rdata(
            Name::from_str("ns1.example.com.").unwrap(),
            80,
            RData::A(A::new(192, 0, 2, 1)),
        )]);

        let lookup1 = Lookup {
            query: query.clone(),
            message: message1,
            valid_until: Instant::now(),
        };

        // Create second lookup with different records in all sections
        let mut message2 = Message::response(0, OpCode::Query);
        message2.add_query(query.clone());
        message2.add_answers(vec![Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            80,
            RData::A(A::new(127, 0, 0, 2)),
        )]);
        message2.add_authority(Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            80,
            RData::NS(NS(Name::from_str("ns2.example.com.").unwrap())),
        ));
        message2.add_additionals(vec![Record::from_rdata(
            Name::from_str("ns2.example.com.").unwrap(),
            80,
            RData::A(A::new(192, 0, 2, 2)),
        )]);

        let lookup2 = Lookup {
            query,
            message: message2,
            valid_until: Instant::now(),
        };

        // Append lookup2 to lookup1
        let combined = lookup1.append(lookup2);

        // Verify that sections were preserved and combined
        assert_eq!(combined.message.answers().len(), 2);
        assert_eq!(combined.message.authorities().len(), 2);
        assert_eq!(combined.message.additionals().len(), 2);

        // Verify answer records
        if let RData::A(a) = combined.message.answers()[0].data() {
            assert_eq!(*a, A::new(127, 0, 0, 1));
        } else {
            panic!("First answer should be A");
        }
        if let RData::A(a) = combined.message.answers()[1].data() {
            assert_eq!(*a, A::new(127, 0, 0, 2));
        } else {
            panic!("Second answer should be A");
        }

        // Verify authority records
        if let RData::NS(ns) = combined.message.authorities()[0].data() {
            assert_eq!(ns.0, Name::from_str("ns1.example.com.").unwrap());
        } else {
            panic!("First authority should be NS");
        }
        if let RData::NS(ns) = combined.message.authorities()[1].data() {
            assert_eq!(ns.0, Name::from_str("ns2.example.com.").unwrap());
        } else {
            panic!("Second authority should be NS");
        }

        // Verify additional records
        if let RData::A(a) = combined.message.additionals()[0].data() {
            assert_eq!(*a, A::new(192, 0, 2, 1));
        } else {
            panic!("First additional should be A");
        }
        if let RData::A(a) = combined.message.additionals()[1].data() {
            assert_eq!(*a, A::new(192, 0, 2, 2));
        } else {
            panic!("Second additional should be A");
        }
    }
}
