// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::slice::Iter;

use trust_dns::rr::Record;

/// The result of a lookup on an Authority
#[derive(Debug, Eq, PartialEq)]
pub enum AuthLookup<'r> {
    /// There are other record types with the specified name
    NameExists,
    /// There is no matching name for the query
    NoName,
    // TODO: change the result of a lookup to a set of chained iterators...
    /// Records
    Records(Vec<&'r Record>),
}

impl<'r> AuthLookup<'r> {
    /// Returns true if either the associated Records are empty, or this is a NameExists or NoName
    pub fn is_empty(&self) -> bool {
        match *self {
            AuthLookup::NameExists | AuthLookup::NoName => true,
            AuthLookup::Records(ref records) => records.is_empty(),
        }
    }

    /// Returns an iterator over the records
    pub fn iter(&'r self) -> AuthLookupIter<'r> {
        match *self {
            AuthLookup::NameExists | AuthLookup::NoName => AuthLookupIter(None),
            AuthLookup::Records(ref records) => AuthLookupIter(Some(records.iter())),
        }
    }

    /// Unwraps the associated records, or panics if this is a NameExists or NoNmae
    pub fn unwrap(self) -> Vec<&'r Record> {
        if let AuthLookup::Records(records) = self {
            records
        } else {
            panic!("AuthLookup was not Records: {:?}", self)
        }
    }
}

/// An Iterator for AuthLookup
pub struct AuthLookupIter<'r>(Option<Iter<'r, &'r Record>>);

impl<'r> Iterator for AuthLookupIter<'r> {
    type Item = &'r Record;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(ref mut iter) = self.0 {
            iter.next().map(|r| *r)
        } else {
            None
        }
    }
}
