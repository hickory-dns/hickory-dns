// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::iter::Chain;

use trust_dns::rr::Record;

use store::sqlite::LookupRecords;

/// The result of a lookup on an Authority
///
/// # Lifetimes
///
/// * `'c` - the catalogue lifetime
/// * `'r` - the recordset lifetime, subset of 'c
/// * `'q` - the queries lifetime
#[derive(Debug)]
pub enum AuthLookup<'r, 'q> {
    /// There is no matching name for the query
    NxDomain,
    /// There are no matching records for the query, but there are others associated to the name
    NameExists,
    /// The request was refused, eg AXFR is not supported
    Refused,
    // TODO: change the result of a lookup to a set of chained iterators...
    /// Records
    Records(LookupRecords<'r, 'q>),
    /// Soa only differs from Records in that the lifetime on the name is from the authority, and not the query
    SOA(LookupRecords<'r, 'r>),
    /// An axfr starts with soa, chained to all the records, then another soa...
    AXFR(Chain<Chain<LookupRecords<'r, 'r>, LookupRecords<'r, 'q>>, LookupRecords<'r, 'r>>),
}

impl<'r, 'q> AuthLookup<'r, 'q> {
    /// Returns true if either the associated Records are empty, or this is a NameExists or NxDomain
    pub fn is_empty(&self) -> bool {
        match *self {
            AuthLookup::NameExists | AuthLookup::NxDomain | AuthLookup::Refused => true,
            AuthLookup::Records(_) | AuthLookup::SOA(_) | AuthLookup::AXFR(_) => false,
        }
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
}

impl<'r, 'q> Iterator for AuthLookup<'r, 'q> {
    type Item = &'r Record;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            AuthLookup::NxDomain | AuthLookup::NameExists | AuthLookup::Refused => None,
            AuthLookup::Records(ref mut i) => i.next(),
            AuthLookup::SOA(ref mut i) => i.next(),
            AuthLookup::AXFR(ref mut i) => i.next(),
        }
    }
}

impl<'r, 'q> Default for AuthLookup<'r, 'q> {
    fn default() -> Self {
        AuthLookup::NxDomain
    }
}
