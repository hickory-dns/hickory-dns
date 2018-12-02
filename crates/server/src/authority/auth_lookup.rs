// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::iter::Chain;
use std::slice::Iter;
use std::sync::Arc;

use proto::rr::dnssec::SupportedAlgorithms;
use proto::rr::{Record, RecordSet, RecordType, RrsetRecords};
use trust_dns::rr::LowerName;

/// The result of a lookup on an Authority
///
/// # Lifetimes
///
/// * `'c` - the catalogue lifetime
/// * `'r` - the recordset lifetime, subset of 'c
/// * `'q` - the queries lifetime
#[derive(Debug)]
pub enum AuthLookup {
    /// There is no matching name for the query
    NxDomain,
    /// There are no matching records for the query, but there are others associated to the name
    NameExists,
    /// The request was refused, eg AXFR is not supported
    Refused,
    // TODO: change the result of a lookup to a set of chained iterators...
    /// Records
    Records(LookupRecords),
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
    /// Returns true if either the associated Records are empty, or this is a NameExists or NxDomain
    pub fn is_empty(&self) -> bool {
        match *self {
            AuthLookup::NameExists | AuthLookup::NxDomain | AuthLookup::Refused => true,
            AuthLookup::Records(_) | AuthLookup::SOA(_) | AuthLookup::AXFR { .. } => false,
        }
    }

    /// This is an NxDomain or NameExists, and has no associated records
    ///
    /// this consumes the iterator, and verifies it is empty
    pub fn was_empty(&self) -> bool {
        self.iter().count() == 0
    }

    /// This is a non-existant domain name
    pub fn is_nx_domain(&self) -> bool {
        match *self {
            AuthLookup::NxDomain => true,
            _ => false,
        }
    }

    /// This is a non-existant domain name
    pub fn is_refused(&self) -> bool {
        match *self {
            AuthLookup::Refused => true,
            _ => false,
        }
    }

    /// Conversion to an iterator
    pub fn iter(&self) -> AuthLookupIter {
        self.into_iter()
    }

    /// Does not panic, but will return no records if it is not of that type
    pub fn unwrap_records(self) -> LookupRecords {
        match self {
            AuthLookup::Records(records) => records,
            _ => LookupRecords::default(),
        }
    }
}

impl Default for AuthLookup {
    fn default() -> Self {
        AuthLookup::NxDomain
    }
}

impl<'a> IntoIterator for &'a AuthLookup {
    type Item = &'a Record;
    type IntoIter = AuthLookupIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            AuthLookup::NxDomain | AuthLookup::NameExists | AuthLookup::Refused => {
                AuthLookupIter::Empty
            }
            AuthLookup::Records(r) | AuthLookup::SOA(r) => AuthLookupIter::Records(r.into_iter()),
            AuthLookup::AXFR {
                start_soa,
                records,
                end_soa,
            } => AuthLookupIter::AXFR(start_soa.into_iter().chain(records).chain(end_soa)),
        }
    }
}

/// An iterator over an Authority Lookup
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
        AuthLookup::Records(lookup)
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
                    }).find(|rr_set| {
                        query_type == RecordType::AXFR
                            || &LowerName::from(rr_set.name()) == query_name
                    });

                if record.is_some() {
                    return record;
                }
            }

            self.rrset = self.rrsets.next().map(|r| r.borrow());

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
    /// There is no record by the name
    NxDomain,
    /// There is no record for the given query, but there are other records at that name
    NameExists,
    /// The associate records
    Records(bool, SupportedAlgorithms, Arc<RecordSet>),
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
        LookupRecords::Records(is_secure, supported_algorithms, records)
    }

    /// This is an NxDomain or NameExists, and has no associated records
    ///
    /// this consumes the iterator, and verifies it is empty
    pub fn was_empty(&self) -> bool {
        self.iter().count() == 0
    }

    /// This is an NxDomain
    pub fn is_nx_domain(&self) -> bool {
        match *self {
            LookupRecords::NxDomain => true,
            _ => false,
        }
    }

    /// This is a NameExists
    pub fn is_name_exists(&self) -> bool {
        match *self {
            LookupRecords::NameExists => true,
            _ => false,
        }
    }

    /// Conversion to an iterator
    pub fn iter(&self) -> LookupRecordsIter {
        self.into_iter()
    }
}

impl Default for LookupRecords {
    fn default() -> Self {
        LookupRecords::NxDomain
    }
}

impl<'a> IntoIterator for &'a LookupRecords {
    type Item = &'a Record;
    type IntoIter = LookupRecordsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            LookupRecords::NxDomain | LookupRecords::NameExists => LookupRecordsIter::Empty,
            LookupRecords::Records(is_secure, supported_algorithms, r) => {
                LookupRecordsIter::RecordsIter(r.records(*is_secure, *supported_algorithms))
            }
            LookupRecords::AnyRecords(r) => LookupRecordsIter::AnyRecordsIter(r.iter()),
        }
    }
}

/// Iteratof over lookup records
pub enum LookupRecordsIter<'r> {
    /// An iteration over batch record type results
    AnyRecordsIter(AnyRecordsIter<'r>),
    /// An iteration over a single RecordSet
    RecordsIter(RrsetRecords<'r>),
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
