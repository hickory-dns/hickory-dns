// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::fmt::{self, Display};

use crate::error::*;
use crate::op::Query;
use crate::rr::LowerName;
use crate::rr::{DNSClass, RecordType};
use crate::serialize::binary::*;

/// Identical to [crate::op::Query], except that the Name is guaranteed to be in lower case form
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LowerQuery {
    name: LowerName,
    original: Query,
}

impl LowerQuery {
    /// Create a new query from name and type, class defaults to IN
    pub fn query(query: Query) -> Self {
        Self {
            name: LowerName::new(query.name()),
            original: query,
        }
    }

    /// ```text
    /// QNAME           a domain name represented as a sequence of labels, where
    ///                 each label consists of a length octet followed by that
    ///                 number of octets.  The domain name terminates with the
    ///                 zero length octet for the null label of the root.  Note
    ///                 that this field may be an odd number of octets; no
    ///                 padding is used.
    /// ```
    pub fn name(&self) -> &LowerName {
        &self.name
    }

    /// Returns the original with the `Name`s case preserved
    pub fn original(&self) -> &Query {
        &self.original
    }

    /// ```text
    /// QTYPE           a two octet code which specifies the type of the query.
    ///                 The values for this field include all codes valid for a
    ///                 TYPE field, together with some more general codes which
    ///                 can match more than one type of RR.
    /// ```
    pub fn query_type(&self) -> RecordType {
        self.original.query_type()
    }

    /// ```text
    /// QCLASS          a two octet code that specifies the class of the query.
    ///                 For example, the QCLASS field is IN for the Internet.
    /// ```
    pub fn query_class(&self) -> DNSClass {
        self.original.query_class()
    }
}

impl From<Query> for LowerQuery {
    fn from(query: Query) -> Self {
        Self::query(query)
    }
}

impl BinEncodable for LowerQuery {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        self.original.emit(encoder)
    }
}

impl<'r> BinDecodable<'r> for LowerQuery {
    fn read(decoder: &mut BinDecoder<'r>) -> ProtoResult<Self> {
        let original = Query::read(decoder)?;
        Ok(Self::query(original))
    }
}

impl Display for LowerQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "name: {} type: {} class: {}",
            self.name,
            self.original.query_type(),
            self.original.query_class()
        )
    }
}
