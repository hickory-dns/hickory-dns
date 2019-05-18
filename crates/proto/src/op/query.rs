/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Query struct for looking up resource records

use std::fmt;
use std::fmt::{Display, Formatter};

use crate::error::*;
use crate::rr::dns_class::DNSClass;
use crate::rr::domain::Name;
use crate::rr::record_type::RecordType;
use crate::serialize::binary::*;

/// Query struct for looking up resource records, basically a resource record without RDATA.
///
/// [RFC 1035, DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987](https://tools.ietf.org/html/rfc1035)
///
/// ```text
/// 4.1.2. Question section format
///
/// The question section is used to carry the "question" in most queries,
/// i.e., the parameters that define what is being asked.  The section
/// contains QDCOUNT (usually 1) entries, each of the following format:
///
///                                     1  1  1  1  1  1
///       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                                               |
///     /                     QNAME / ZNAME             /
///     /                                               /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                     QTYPE / ZTYPE             |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                     QCLASS / ZCLASS           |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
/// ```
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Query {
    name: Name,
    query_type: RecordType,
    query_class: DNSClass,
}

impl Default for Query {
    /// Return a default query with an empty name and A, IN for the query_type and query_class
    fn default() -> Self {
        Query {
            name: Name::new(),
            query_type: RecordType::A,
            query_class: DNSClass::IN,
        }
    }
}

impl Query {
    /// Return a default query with an empty name and A, IN for the query_type and query_class
    pub fn new() -> Self {
        Default::default()
    }

    /// Create a new query from name and type, class defaults to IN
    pub fn query(name: Name, query_type: RecordType) -> Self {
        Query {
            name,
            query_type,
            query_class: DNSClass::IN,
        }
    }

    /// replaces name with the new name
    pub fn set_name(&mut self, name: Name) -> &mut Self {
        self.name = name;
        self
    }

    /// Specify the RecordType being queried
    pub fn set_query_type(&mut self, query_type: RecordType) -> &mut Self {
        self.query_type = query_type;
        self
    }

    /// Specify÷ the DNS class of the Query, almost always IN
    pub fn set_query_class(&mut self, query_class: DNSClass) -> &mut Self {
        self.query_class = query_class;
        self
    }

    /// ```text
    /// QNAME           a domain name represented as a sequence of labels, where
    ///                 each label consists of a length octet followed by that
    ///                 number of octets.  The domain name terminates with the
    ///                 zero length octet for the null label of the root.  Note
    ///                 that this field may be an odd number of octets; no
    ///                 padding is used.
    /// ```
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// ```text
    /// QTYPE           a two octet code which specifies the type of the query.
    ///                 The values for this field include all codes valid for a
    ///                 TYPE field, together with some more general codes which
    ///                 can match more than one type of RR.
    /// ```
    pub fn query_type(&self) -> RecordType {
        self.query_type
    }

    /// ```text
    /// QCLASS          a two octet code that specifies the class of the query.
    ///                 For example, the QCLASS field is IN for the Internet.
    /// ```
    pub fn query_class(&self) -> DNSClass {
        self.query_class
    }
}

impl BinEncodable for Query {
    fn emit(&self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        self.name.emit(encoder)?;
        self.query_type.emit(encoder)?;
        self.query_class.emit(encoder)?;

        Ok(())
    }
}

impl<'r> BinDecodable<'r> for Query {
    fn read(decoder: &mut BinDecoder<'r>) -> ProtoResult<Self> {
        let name = Name::read(decoder)?;
        let query_type = RecordType::read(decoder)?;
        let query_class = DNSClass::read(decoder)?;

        Ok(Query {
            name,
            query_type,
            query_class,
        })
    }
}

impl Display for Query {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "name: {} type: {} class: {}",
            self.name, self.query_type, self.query_class
        )
    }
}

#[test]
fn test_read_and_emit() {
    let expect = Query {
        name: Name::from_ascii("WWW.example.com").unwrap(),
        query_type: RecordType::AAAA,
        query_class: DNSClass::IN,
    };

    let mut byte_vec: Vec<u8> = Vec::with_capacity(512);
    {
        let mut encoder = BinEncoder::new(&mut byte_vec);
        expect.emit(&mut encoder).unwrap();
    }

    let mut decoder = BinDecoder::new(&byte_vec);
    let got = Query::read(&mut decoder).unwrap();
    assert_eq!(got, expect);
}
