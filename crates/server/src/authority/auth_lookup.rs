// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::iter::Chain;
use std::slice::Iter;
use std::sync::Arc;

use trust_dns::rr::LowerName;

use crate::authority::LookupObject;
use crate::proto::rr::dnssec::SupportedAlgorithms;
use crate::proto::rr::{Record, RecordSet, RecordType, RrsetRecords};


/// The result of a lookup on an Authority
///
/// # Lifetimes
///
/// * `'c` - the catalogue lifetime
/// * `'r` - the recordset lifetime, subset of 'c
/// * `'q` - the queries lifetime
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum AuthLookup {
    /// No records
    Empty,
    // TODO: change the result of a lookup to a set of chained iterators...
    /// Records
    Records {
        /// Authoritative answers
        answers: LookupRecords,
        /// Optional set of LookupRecords
        additionals: Option<LookupRecords>,
    },
    /// Soa only differs from Records in that the lifetime on the name is from the authority, and not the query
    SOA(LookupRecords),
    /// An axfr starts with soa, chained to all the records, then another soa...
    AXFR {
        /// The first SOA record in an AXFR response
        start_soa: LookupRecords,
        /// The records to return
        records: LookupRecords,
        /// The last SOA record of an AXFR (matches the first)
        end_soa: LookupRecords,
    },
}

impl AuthLookup {
    /// Construct an answer with additional section
    pub fn answers(answers: LookupRecords, additionals: Option<LookupRecords>) -> Self {
        AuthLookup::Records {
            answers,
            additionals,
        }
    }

    /// Returns true if either the associated Records are empty, or this is a NameExists or NxDomain
    pub fn is_empty(&self) -> bool {
        // FIXME: this needs to be cheap
        self.was_empty()
    }

    /// This is an NxDomain or NameExists, and has no associated records
    ///
    /// this consumes the iterator, and verifies it is empty
    pub fn was_empty(&self) -> bool {
        self.iter().count() == 0
    }

    /// Conversion to an iterator
    pub fn iter(&self) -> AuthLookupIter {
        self.into_iter()
    }

    /// Does not panic, but will return no records if it is not of that type
    pub fn unwrap_records(self) -> LookupRecords {
        match self {
            // TODO: this is ugly, what about the additionals?
            AuthLookup::Records { answers, .. } => answers,
            _ => LookupRecords::default(),
        }
    }

    /// Takes the additional records, leaving behind None
    pub fn take_additionals(&mut self) -> Option<LookupRecords> {
        match self {
            AuthLookup::Records {
                ref mut additionals,
                ..
            } => additionals.take(),
            _ => None,
        }
    }
}

impl LookupObject for AuthLookup {
    fn is_empty(&self) -> bool {
        AuthLookup::is_empty(self)
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a> {
        let boxed_iter = AuthLookup::iter(self);
        Box::new(boxed_iter)
    }

    fn take_additionals(&mut self) -> Option<Box<dyn LookupObject>> {
        let additionals = AuthLookup::take_additionals(self);
        additionals.map(|a| Box::new(a) as Box<dyn LookupObject>)
    }
}

impl Default for AuthLookup {
    fn default() -> Self {
        AuthLookup::Empty
    }
}

impl<'a> IntoIterator for &'a AuthLookup {
    type Item = &'a Record;
    type IntoIter = AuthLookupIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            AuthLookup::Empty => AuthLookupIter::Empty,
            // FIXME: what about the additionals? is IntoIterator a bad idea?
            AuthLookup::Records { answers: r, .. } | AuthLookup::SOA(r) => {
                AuthLookupIter::Records(r.into_iter())
            }
            AuthLookup::AXFR {
                start_soa,
                records,
                end_soa,
            } => AuthLookupIter::AXFR(start_soa.into_iter().chain(records).chain(end_soa)),
        }
    }
}

/// An iterator over an Authority Lookup
#[allow(clippy::large_enum_variant)]
pub enum AuthLookupIter<'r> {
    /// The empty set
    Empty,
    /// An iteration over a set of Records
    Records(LookupRecordsIter<'r>),
    /// An iteration over an AXFR
    AXFR(Chain<Chain<LookupRecordsIter<'r>, LookupRecordsIter<'r>>, LookupRecordsIter<'r>>),
}

impl<'r> Iterator for AuthLookupIter<'r> {
    type Item = &'r Record;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            AuthLookupIter::Empty => None,
            AuthLookupIter::Records(i) => i.next(),
            AuthLookupIter::AXFR(i) => i.next(),
        }
    }
}

impl<'a> Default for AuthLookupIter<'a> {
    fn default() -> Self {
        AuthLookupIter::Empty
    }
}

impl From<LookupRecords> for AuthLookup {
    fn from(lookup: LookupRecords) -> Self {
        AuthLookup::Records {
            answers: lookup,
            additionals: None,
        }
    }
}

/// An iterator over an ANY query for Records.
///
/// The length of this result cannot be known without consuming the iterator.
///
/// # Lifetimes
///
/// * `'r` - the record_set's lifetime, from the catalog
/// * `'q` - the lifetime of the query/request
#[derive(Debug)]
pub struct AnyRecords {
    is_secure: bool,
    supported_algorithms: SupportedAlgorithms,
    rrsets: Vec<Arc<RecordSet>>,
    rrset: Option<Arc<RecordSet>>,
    records: Option<Arc<RecordSet>>,
    query_type: RecordType,
    query_name: LowerName,
}

impl AnyRecords {
    /// construct a new lookup of any set of records
    pub fn new(
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
        // TODO: potentially very expensive
        rrsets: Vec<Arc<RecordSet>>,
        query_type: RecordType,
        query_name: LowerName,
    ) -> Self {
        AnyRecords {
            is_secure,
            supported_algorithms,
            rrsets,
            rrset: None,
            records: None,
            query_type,
            query_name,
        }
    }

    fn iter(&self) -> AnyRecordsIter {
        self.into_iter()
    }
}

impl<'r> IntoIterator for &'r AnyRecords {
    type Item = &'r Record;
    type IntoIter = AnyRecordsIter<'r>;

    fn into_iter(self) -> Self::IntoIter {
        AnyRecordsIter {
            is_secure: self.is_secure,
            supported_algorithms: self.supported_algorithms,
            // TODO: potentially very expensive
            rrsets: self.rrsets.iter(),
            rrset: None,
            records: None,
            query_type: self.query_type,
            query_name: &self.query_name,
        }
    }
}

/// An iteration over a lookup for any Records
pub struct AnyRecordsIter<'r> {
    is_secure: bool,
    supported_algorithms: SupportedAlgorithms,
    rrsets: Iter<'r, Arc<RecordSet>>,
    rrset: Option<&'r RecordSet>,
    records: Option<RrsetRecords<'r>>,
    query_type: RecordType,
    query_name: &'r LowerName,
}

impl<'r> Iterator for AnyRecordsIter<'r> {
    type Item = &'r Record;

    fn next(&mut self) -> Option<Self::Item> {
        use std::borrow::Borrow;

        let query_type = self.query_type;
        let query_name = self.query_name;

        loop {
            if let Some(ref mut records) = self.records {
                let record = records
                    .by_ref()
                    .filter(|rr_set| {
                        query_type == RecordType::ANY || rr_set.record_type() != RecordType::SOA
                    })
                    .find(|rr_set| {
                        query_type == RecordType::AXFR
                            || &LowerName::from(rr_set.name()) == query_name
                    });

                if record.is_some() {
                    return record;
                }
            }

            self.rrset = self.rrsets.next().map(Borrow::borrow);

            // if there are no more RecordSets, then return
            self.rrset?;

            // getting here, we must have exhausted our records from the rrset
            self.records = Some(
                self.rrset
                    .expect("rrset should not be None at this point")
                    .records(self.is_secure, self.supported_algorithms),
            );
        }
    }
}

/// The result of a lookup
#[derive(Debug)]
pub enum LookupRecords {
    /// The empty set of records
    Empty,
    /// The associate records
    Records {
        /// was the search a secure search
        is_secure: bool,
        /// what are the requests supported algorithms
        supported_algorithms: SupportedAlgorithms,
        /// the records found based on the query
        records: Arc<RecordSet>,
    },
    /// Vec of disjoint record sets
    ManyRecords(bool, SupportedAlgorithms, Vec<Arc<RecordSet>>),
    // TODO: need a better option for very large zone xfrs...
    /// A generic lookup response where anything is desired
    AnyRecords(AnyRecords),
}

impl LookupRecords {
    /// Construct a new LookupRecords
    pub fn new(
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
        records: Arc<RecordSet>,
    ) -> Self {
        LookupRecords::Records {
            is_secure,
            supported_algorithms,
            records,
        }
    }

    /// Construct a new LookupRecords over a set of ResordSets
    pub fn many(
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
        mut records: Vec<Arc<RecordSet>>,
    ) -> Self {
        // we're reversing the records because they are output in reverse order, via pop()
        records.reverse();
        LookupRecords::ManyRecords(is_secure, supported_algorithms, records)
    }

    /// This is an NxDomain or NameExists, and has no associated records
    ///
    /// this consumes the iterator, and verifies it is empty
    pub fn was_empty(&self) -> bool {
        self.iter().count() == 0
    }

    /// Conversion to an iterator
    pub fn iter(&self) -> LookupRecordsIter {
        self.into_iter()
    }
}

impl Default for LookupRecords {
    fn default() -> Self {
        LookupRecords::Empty
    }
}

impl<'a> IntoIterator for &'a LookupRecords {
    type Item = &'a Record;
    type IntoIter = LookupRecordsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            LookupRecords::Empty => LookupRecordsIter::Empty,
            LookupRecords::Records {
                is_secure,
                supported_algorithms,
                records,
            } => LookupRecordsIter::RecordsIter(records.records(*is_secure, *supported_algorithms)),
            LookupRecords::ManyRecords(is_secure, supported_algorithms, r) => {
                LookupRecordsIter::ManyRecordsIter(
                    r.iter()
                        .map(|r| r.records(*is_secure, *supported_algorithms))
                        .collect(),
                    None,
                )
            }
            LookupRecords::AnyRecords(r) => LookupRecordsIter::AnyRecordsIter(r.iter()),
        }
    }
}

/// Iterator over lookup records
pub enum LookupRecordsIter<'r> {
    /// An iteration over batch record type results
    AnyRecordsIter(AnyRecordsIter<'r>),
    /// An iteration over a single RecordSet
    RecordsIter(RrsetRecords<'r>),
    /// An iteration over many rrsets
    ManyRecordsIter(Vec<RrsetRecords<'r>>, Option<RrsetRecords<'r>>),
    /// An empty set
    Empty,
}

impl<'r> Default for LookupRecordsIter<'r> {
    fn default() -> Self {
        LookupRecordsIter::Empty
    }
}

impl<'r> Iterator for LookupRecordsIter<'r> {
    type Item = &'r Record;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            LookupRecordsIter::Empty => None,
            LookupRecordsIter::AnyRecordsIter(current) => current.next(),
            LookupRecordsIter::RecordsIter(current) => current.next(),
            LookupRecordsIter::ManyRecordsIter(set, ref mut current) => loop {
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

// impl From<Arc<RecordSet>> for LookupRecords {
//     fn from(rrset_records: Arc<RecordSet>) -> Self {
//         match *rrset_records {
//             RrsetRecords::Empty => LookupRecords::NxDomain,
//             rrset_records => LookupRecords::RecordsIter(rrset_records),
//         }
//     }
// }

impl From<AnyRecords> for LookupRecords {
    fn from(rrset_records: AnyRecords) -> Self {
        LookupRecords::AnyRecords(rrset_records)
    }
}

impl LookupObject for LookupRecords {
    fn is_empty(&self) -> bool {
        LookupRecords::was_empty(self)
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a> {
        Box::new(self.iter())
    }

    fn take_additionals(&mut self) -> Option<Box<dyn LookupObject>> {
        None
    }
}
