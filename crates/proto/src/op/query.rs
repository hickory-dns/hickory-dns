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

#[cfg(feature = "mdns")]
/// From [RFC 6762](https://tools.ietf.org/html/rfc6762#section-5.4)
/// ```text
// To avoid large floods of potentially unnecessary responses in these
// cases, Multicast DNS defines the top bit in the class field of a DNS
// question as the unicast-response bit.
/// ```
const MDNS_UNICAST_RESPONSE: u16 = 1 << 15;

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
    #[cfg(feature = "mdns")]
    mdns_unicast_response: bool,
}

impl Default for Query {
    /// Return a default query with an empty name and A, IN for the query_type and query_class
    fn default() -> Self {
        Self {
            name: Name::new(),
            query_type: RecordType::A,
            query_class: DNSClass::IN,
            #[cfg(feature = "mdns")]
            mdns_unicast_response: false,
        }
    }
}

impl Query {
    /// Return a default query with an empty name and A, IN for the query_type and query_class
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new query from name and type, class defaults to IN
    #[allow(clippy::self_named_constructors)]
    pub fn query(name: Name, query_type: RecordType) -> Self {
        Self {
            name,
            query_type,
            query_class: DNSClass::IN,
            #[cfg(feature = "mdns")]
            mdns_unicast_response: false,
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

    /// Changes mDNS unicast-response bit
    /// See [RFC 6762](https://tools.ietf.org/html/rfc6762#section-5.4)
    #[cfg(feature = "mdns")]
    #[cfg_attr(docsrs, doc(cfg(feature = "mdns")))]
    pub fn set_mdns_unicast_response(&mut self, flag: bool) -> &mut Self {
        self.mdns_unicast_response = flag;
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

    /// Returns if the mDNS unicast-response bit is set or not
    /// See [RFC 6762](https://tools.ietf.org/html/rfc6762#section-5.4)
    #[cfg(feature = "mdns")]
    #[cfg_attr(docsrs, doc(cfg(feature = "mdns")))]
    pub fn mdns_unicast_response(&self) -> bool {
        self.mdns_unicast_response
    }

    /// Consumes `Query` and returns it's components
    pub fn into_parts(self) -> QueryParts {
        self.into()
    }
}

/// Consumes `Query` giving public access to fields of `Query` so they can
/// be destructured and taken by value.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct QueryParts {
    /// QNAME
    pub name: Name,
    /// QTYPE
    pub query_type: RecordType,
    /// QCLASS
    pub query_class: DNSClass,
    /// mDNS unicast-response bit set or not
    #[cfg(feature = "mdns")]
    #[cfg_attr(docsrs, doc(cfg(feature = "mdns")))]
    pub mdns_unicast_response: bool,
}

impl From<Query> for QueryParts {
    fn from(q: Query) -> Self {
        cfg_if::cfg_if! {
            if #[cfg(feature = "mdns")] {
                let Query {
                    name,
                    query_type,
                    query_class,
                    mdns_unicast_response,
                } = q;
            } else {
                let Query {
                    name,
                    query_type,
                    query_class,
                } = q;
            }
        }

        Self {
            name,
            query_type,
            query_class,
            #[cfg(feature = "mdns")]
            mdns_unicast_response,
        }
    }
}

impl BinEncodable for Query {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        self.name.emit(encoder)?;
        self.query_type.emit(encoder)?;

        #[cfg(not(feature = "mdns"))]
        self.query_class.emit(encoder)?;

        #[cfg(feature = "mdns")]
        {
            if self.mdns_unicast_response {
                encoder.emit_u16(u16::from(self.query_class()) | MDNS_UNICAST_RESPONSE)?;
            } else {
                self.query_class.emit(encoder)?;
            }
        }

        Ok(())
    }
}

impl<'r> BinDecodable<'r> for Query {
    fn read(decoder: &mut BinDecoder<'r>) -> ProtoResult<Self> {
        let name = Name::read(decoder)?;
        let query_type = RecordType::read(decoder)?;

        #[cfg(feature = "mdns")]
        let mut mdns_unicast_response = false;

        #[cfg(not(feature = "mdns"))]
        let query_class = DNSClass::read(decoder)?;

        #[cfg(feature = "mdns")]
        let query_class = {
            let query_class_value =
                decoder.read_u16()?.unverified(/*DNSClass::from_u16 will verify the value*/);
            if query_class_value & MDNS_UNICAST_RESPONSE > 0 {
                mdns_unicast_response = true;
                DNSClass::from_u16(query_class_value & !MDNS_UNICAST_RESPONSE)?
            } else {
                DNSClass::from_u16(query_class_value)?
            }
        };

        Ok(Self {
            name,
            query_type,
            query_class,
            #[cfg(feature = "mdns")]
            mdns_unicast_response,
        })
    }
}

impl Display for Query {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        #[cfg(not(feature = "mdns"))]
        {
            write!(
                f,
                "name: {} type: {} class: {}",
                self.name, self.query_type, self.query_class
            )
        }

        #[cfg(feature = "mdns")]
        {
            write!(
                f,
                "name: {} type: {} class: {} mdns_unicast_response: {}",
                self.name, self.query_type, self.query_class, self.mdns_unicast_response
            )
        }
    }
}

#[test]
#[allow(clippy::needless_update)]
fn test_read_and_emit() {
    let expect = Query {
        name: Name::from_ascii("WWW.example.com").unwrap(),
        query_type: RecordType::AAAA,
        query_class: DNSClass::IN,
        ..Query::default()
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

#[cfg(feature = "mdns")]
#[test]
fn test_mdns_unicast_response_bit_handling() {
    const QCLASS_OFFSET: usize = 1 /* empty name */ +
        std::mem::size_of::<u16>() /* query_type */;

    let mut query = Query::new();
    query.set_mdns_unicast_response(true);

    let mut vec_bytes: Vec<u8> = Vec::with_capacity(512);
    {
        let mut encoder = BinEncoder::new(&mut vec_bytes);
        query.emit(&mut encoder).unwrap();

        let query_class_slice = encoder.slice_of(QCLASS_OFFSET, QCLASS_OFFSET + 2);
        assert_eq!(query_class_slice, &[0x80, 0x01]);
    }

    let mut decoder = BinDecoder::new(&vec_bytes);

    let got = Query::read(&mut decoder).unwrap();

    assert_eq!(got.query_class(), DNSClass::IN);
    assert!(got.mdns_unicast_response());
}
