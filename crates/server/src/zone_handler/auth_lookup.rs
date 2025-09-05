// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::slice::Iter;
use std::sync::Arc;

use crate::proto::{
    op::Message,
    rr::{Record, RecordSet, RecordType, RrsetRecords},
};
#[cfg(feature = "resolver")]
use crate::resolver::lookup::{Lookup, LookupRecordIter};
use crate::zone_handler::LookupOptions;

/// The result of a lookup on a ZoneHandler
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Default)]
#[non_exhaustive]
pub enum AuthLookup {
    /// No records
    #[default]
    Empty,
    // TODO: change the result of a lookup to a set of chained iterators...
    /// Records
    Records {
        /// Authoritative answers
        answers: LookupRecords,
        /// Optional set of LookupRecords
        additionals: Option<LookupRecords>,
    },
    /// Records resulting from a resolver lookup
    #[cfg(feature = "resolver")]
    Resolved(Lookup),
    /// A response message
    Response(Message),
}

impl AuthLookup {
    /// Construct an answer with additional section
    pub fn answers(answers: LookupRecords, additionals: Option<LookupRecords>) -> Self {
        Self::Records {
            answers,
            additionals,
        }
    }

    /// Returns true if either the associated Records are empty, or this is a NameExists or NxDomain
    pub fn is_empty(&self) -> bool {
        // TODO: this needs to be cheap
        self.was_empty()
    }

    /// This is an NxDomain or NameExists, and has no associated records
    ///
    /// this consumes the iterator, and verifies it is empty
    pub fn was_empty(&self) -> bool {
        self.iter().count() == 0
    }

    /// Conversion to an iterator
    pub fn iter(&self) -> AuthLookupIter<'_> {
        self.into_iter()
    }

    /// Does not panic, but will return no records if it is not of that type
    pub fn unwrap_records(self) -> LookupRecords {
        match self {
            // TODO: this is ugly, what about the additionals?
            Self::Records { answers, .. } => answers,
            _ => LookupRecords::default(),
        }
    }

    /// Iterates over the records from the Authority section, if present.
    pub fn authorities(&self) -> Option<LookupRecordsIter<'_>> {
        match self {
            Self::Response(message) => {
                Some(LookupRecordsIter::SliceIter(message.authorities().iter()))
            }
            _ => None,
        }
    }

    /// Iterates over the records from the Additional section, if present.
    pub fn additionals(&self) -> Option<LookupRecordsIter<'_>> {
        match self {
            Self::Records { additionals, .. } => additionals.as_ref().map(|l| l.iter()),
            Self::Response(message) => {
                Some(LookupRecordsIter::SliceIter(message.additionals().iter()))
            }
            _ => None,
        }
    }

    /// Takes the additional records, leaving behind None
    pub fn take_additionals(&mut self) -> Option<LookupRecords> {
        match self {
            Self::Records { additionals, .. } => additionals.take(),
            Self::Response(message) => Some(LookupRecords::Section(message.take_additionals())),
            _ => None,
        }
    }
}

#[cfg(feature = "resolver")]
impl From<Lookup> for AuthLookup {
    fn from(lookup: Lookup) -> Self {
        Self::Resolved(lookup)
    }
}

impl<'a> IntoIterator for &'a AuthLookup {
    type Item = &'a Record;
    type IntoIter = AuthLookupIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            AuthLookup::Empty => AuthLookupIter::Empty,
            // TODO: what about the additionals? is IntoIterator a bad idea?
            AuthLookup::Records { answers: r, .. } => AuthLookupIter::Records(r.into_iter()),
            #[cfg(feature = "resolver")]
            AuthLookup::Resolved(lookup) => AuthLookupIter::Resolved(lookup.record_iter()),
            AuthLookup::Response(message) => AuthLookupIter::Response(message.answers().iter()),
        }
    }
}

/// An iterator over a ZoneHandler lookup
#[derive(Default)]
pub enum AuthLookupIter<'r> {
    /// The empty set
    #[default]
    Empty,
    /// An iteration over a set of Records
    Records(LookupRecordsIter<'r>),
    /// An iteration over resolved records
    #[cfg(feature = "resolver")]
    Resolved(LookupRecordIter<'r>),
    /// An iterator over the answer section of a response message
    Response(Iter<'r, Record>),
}

impl<'r> Iterator for AuthLookupIter<'r> {
    type Item = &'r Record;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            AuthLookupIter::Empty => None,
            AuthLookupIter::Records(i) => i.next(),
            #[cfg(feature = "resolver")]
            AuthLookupIter::Resolved(i) => i.next(),
            AuthLookupIter::Response(i) => i.next(),
        }
    }
}

impl From<LookupRecords> for AuthLookup {
    fn from(lookup: LookupRecords) -> Self {
        Self::Records {
            answers: lookup,
            additionals: None,
        }
    }
}

/// A collection of [`RecordSet`]s for an AXFR.
///
/// This omits the SOA record during iteration.
#[derive(Debug)]
pub struct AxfrRecords {
    dnssec_ok: bool,
    rrsets: Vec<Arc<RecordSet>>,
}

impl AxfrRecords {
    /// Construct this wrapper around the contents of a zone.
    pub fn new(dnssec_ok: bool, rrsets: Vec<Arc<RecordSet>>) -> Self {
        Self { dnssec_ok, rrsets }
    }

    fn iter(&self) -> AxfrRecordsIter<'_> {
        self.into_iter()
    }
}

impl<'r> IntoIterator for &'r AxfrRecords {
    type Item = &'r Record;
    type IntoIter = AxfrRecordsIter<'r>;

    fn into_iter(self) -> Self::IntoIter {
        AxfrRecordsIter {
            dnssec_ok: self.dnssec_ok,
            rrsets: self.rrsets.iter(),
            records: None,
        }
    }
}

/// An iterator over all records in a zone, except the SOA record.
pub struct AxfrRecordsIter<'r> {
    #[cfg_attr(not(feature = "__dnssec"), allow(dead_code))]
    dnssec_ok: bool,
    rrsets: Iter<'r, Arc<RecordSet>>,
    records: Option<RrsetRecords<'r>>,
}

impl<'r> Iterator for AxfrRecordsIter<'r> {
    type Item = &'r Record;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(records) = &mut self.records {
                if let Some(record) = records
                    .by_ref()
                    .find(|record| record.record_type() != RecordType::SOA)
                {
                    return Some(record);
                }
            }

            // Return if there are no more RRsets.
            let rrset = self.rrsets.next()?;

            #[cfg(feature = "__dnssec")]
            let records = rrset.records(self.dnssec_ok);

            #[cfg(not(feature = "__dnssec"))]
            let records = rrset.records_without_rrsigs();

            self.records = Some(records);
        }
    }
}

/// The result of a lookup
#[derive(Debug, Default)]
pub enum LookupRecords {
    /// The empty set of records
    #[default]
    Empty,
    /// The associate records
    Records {
        /// LookupOptions for the request, e.g. dnssec
        lookup_options: LookupOptions,
        /// the records found based on the query
        records: Arc<RecordSet>,
    },
    /// Vec of disjoint record sets
    ManyRecords(LookupOptions, Vec<Arc<RecordSet>>),
    /// A section from a response message
    Section(Vec<Record>),
}

impl LookupRecords {
    /// Construct a new LookupRecords
    pub fn new(lookup_options: LookupOptions, records: Arc<RecordSet>) -> Self {
        Self::Records {
            lookup_options,
            records,
        }
    }

    /// Construct a new LookupRecords over a set of RecordSets
    pub fn many(lookup_options: LookupOptions, mut records: Vec<Arc<RecordSet>>) -> Self {
        // we're reversing the records because they are output in reverse order, via pop()
        records.reverse();
        Self::ManyRecords(lookup_options, records)
    }

    /// This is an NxDomain or NameExists, and has no associated records
    ///
    /// this consumes the iterator, and verifies it is empty
    pub fn was_empty(&self) -> bool {
        self.iter().count() == 0
    }

    /// Conversion to an iterator
    pub fn iter(&self) -> LookupRecordsIter<'_> {
        self.into_iter()
    }
}

impl<'a> IntoIterator for &'a LookupRecords {
    type Item = &'a Record;
    type IntoIter = LookupRecordsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            LookupRecords::Empty => LookupRecordsIter::Empty,
            LookupRecords::Records {
                lookup_options,
                records,
            } => LookupRecordsIter::RecordsIter(lookup_options.rrset_with_rrigs(records)),
            LookupRecords::ManyRecords(lookup_options, r) => LookupRecordsIter::ManyRecordsIter(
                r.iter()
                    .map(|r| lookup_options.rrset_with_rrigs(r))
                    .collect(),
                None,
            ),
            LookupRecords::Section(vec) => LookupRecordsIter::SliceIter(vec.iter()),
        }
    }
}

/// Iterator over lookup records
#[derive(Default)]
pub enum LookupRecordsIter<'r> {
    /// An iteration over a single RecordSet
    RecordsIter(RrsetRecords<'r>),
    /// An iteration over many rrsets
    ManyRecordsIter(Vec<RrsetRecords<'r>>, Option<RrsetRecords<'r>>),
    /// An iteration over a slice of records
    SliceIter(Iter<'r, Record>),
    /// An empty set
    #[default]
    Empty,
}

impl<'r> Iterator for LookupRecordsIter<'r> {
    type Item = &'r Record;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            LookupRecordsIter::Empty => None,
            LookupRecordsIter::RecordsIter(current) => current.next(),
            LookupRecordsIter::SliceIter(current) => current.next(),
            LookupRecordsIter::ManyRecordsIter(set, current) => loop {
                if let Some(o) = current.as_mut().and_then(Iterator::next) {
                    return Some(o);
                }

                *current = set.pop();
                if current.is_none() {
                    return None;
                }
            },
        }
    }
}

/// A copy of all data in a zone.
///
/// This is used in the AXFR sub-protocol.
#[derive(Debug)]
pub struct ZoneTransfer {
    /// The SOA record, plus its RRSIG.
    ///
    /// This is sent at the start of the first message of the response.
    pub start_soa: LookupRecords,
    /// All the records in the zone.
    pub records: AxfrRecords,
    /// The SOA record again.
    ///
    /// This is sent at the end of the last message of the response.
    pub end_soa: LookupRecords,
}

impl ZoneTransfer {
    /// Iterate over all the records, starting and ending with the SOA record.
    pub fn iter(&self) -> impl Iterator<Item = &Record> {
        self.start_soa
            .iter()
            .chain(self.records.iter())
            .chain(self.end_soa.iter())
    }
}
