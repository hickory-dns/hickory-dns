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

//! class of DNS operations, in general always IN for internet

use std::convert::From;
use std::cmp::Ordering;

use ::serialize::binary::*;
use ::error::*;

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
#[allow(dead_code)]
pub enum DNSClass {
    IN, //	1	RFC 1035	Internet (IN)
    CH, // 3 Chaos (CH)
    HS, // 4 Hesiod (HS)
    NONE, // 254 QCLASS NONE
    ANY, // 255 QCLASS * (ANY)
    OPT(u16), // Special class for OPT Version, it was overloaded for EDNS - RFC 6891
}

impl DNSClass {
    /// Convert from &str to DNSClass
    ///
    /// ```
    /// use trust_dns::rr::dns_class::DNSClass;
    ///
    /// let var: DNSClass = DNSClass::from_str("IN").unwrap();
    /// assert_eq!(DNSClass::IN, var);
    /// ```
    pub fn from_str(str: &str) -> DecodeResult<Self> {
        match str {
            "IN" => Ok(DNSClass::IN),
            "CH" => Ok(DNSClass::CH),
            "HS" => Ok(DNSClass::HS),
            "NONE" => Ok(DNSClass::NONE),
            "ANY" | "*" => Ok(DNSClass::ANY),
            _ => Err(DecodeErrorKind::UnknownDnsClassStr(str.to_string()).into()),
        }
    }


    /// Convert from u16 to DNSClass
    ///
    /// ```
    /// use trust_dns::rr::dns_class::DNSClass;
    ///
    /// let var = DNSClass::from_u16(1).unwrap();
    /// assert_eq!(DNSClass::IN, var);
    /// ```
    pub fn from_u16(value: u16) -> DecodeResult<Self> {
        match value {
            1 => Ok(DNSClass::IN),
            3 => Ok(DNSClass::CH),
            4 => Ok(DNSClass::HS),
            254 => Ok(DNSClass::NONE),
            255 => Ok(DNSClass::ANY),
            _ => Err(DecodeErrorKind::UnknownDnsClassValue(value).into()),
        }
    }

    pub fn for_opt(value: u16) -> Self {
        DNSClass::OPT(value)
    }
}

impl BinSerializable<DNSClass> for DNSClass {
    fn read(decoder: &mut BinDecoder) -> DecodeResult<Self> {
        Self::from_u16(try!(decoder.read_u16()))
    }

    fn emit(&self, encoder: &mut BinEncoder) -> EncodeResult {
        encoder.emit_u16((*self).into())
    }
}

// TODO make these a macro or annotation

/// Convert from DNSClass to &str
///
/// ```
/// use trust_dns::rr::dns_class::DNSClass;
///
/// let var: &'static str = DNSClass::IN.into();
/// assert_eq!("IN", var);
/// ```
impl From<DNSClass> for &'static str {
    fn from(rt: DNSClass) -> &'static str {
        match rt {
            DNSClass::IN => "IN",
            DNSClass::CH => "CH",
            DNSClass::HS => "HS",
            DNSClass::NONE => "NONE",
            DNSClass::ANY => "ANY",
            DNSClass::OPT(_) => "OPT",
        }
    }
}

/// Convert from DNSClass to u16
///
/// ```
/// use trust_dns::rr::dns_class::DNSClass;
///
/// let var: u16 = DNSClass::IN.into();
/// assert_eq!(1, var);
/// ```
impl From<DNSClass> for u16 {
    fn from(rt: DNSClass) -> Self {
        match rt {
            DNSClass::IN => 1,
            DNSClass::CH => 3,
            DNSClass::HS => 4,
            DNSClass::NONE => 254,
            DNSClass::ANY => 255,
            DNSClass::OPT(version) => version,
        }
    }
}

impl PartialOrd<DNSClass> for DNSClass {
    fn partial_cmp(&self, other: &DNSClass) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DNSClass {
    fn cmp(&self, other: &Self) -> Ordering {
        u16::from(*self).cmp(&u16::from(*other))
    }
}


#[test]
fn test_order() {
    let ordered = vec![DNSClass::IN, DNSClass::CH, DNSClass::HS, DNSClass::NONE, DNSClass::ANY];
    let mut unordered =
        vec![DNSClass::NONE, DNSClass::HS, DNSClass::CH, DNSClass::IN, DNSClass::ANY];

    unordered.sort();

    assert_eq!(unordered, ordered);
}
