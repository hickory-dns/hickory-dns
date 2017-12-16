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

//! record type definitions

use std::convert::From;
use std::cmp::Ordering;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serialize::binary::*;
use error::*;

#[cfg(feature = "dnssec")]
use rr::dnssec::rdata::DNSSECRecordType;

/// The type of the resource record.
///
/// This specifies the type of data in the RData field of the Resource Record
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
#[allow(dead_code)]
pub enum RecordType {
    /// RFC 1035[1]	IPv4 Address record
    A,
    /// RFC 3596[2]	IPv6 address record
    AAAA,
    //  AFSDB,      //	18	RFC 1183	AFS database record
    /// RFC 1035[1]	All cached records, aka ANY
    ANY,
    //  APL,        //	42	RFC 3123	Address Prefix List
    /// RFC 1035[1]	Authoritative Zone Transfer
    AXFR,
    /// RFC 6844 Certification Authority Authorization
    CAA,
    //  CERT,       //	37	RFC 4398	Certificate record
    /// RFC 1035[1]	Canonical name record
    CNAME,
    //  DHCID,      //	49	RFC 4701	DHCP identifier
    //  DNAME,      //	39	RFC 2672	Delegation Name
    //  HIP,        //	55	RFC 5205	Host Identity Protocol
    //  IPSECKEY,   //	45	RFC 4025	IPsec Key
    /// RFC 1996	Incremental Zone Transfer
    IXFR,
    //  KX,         //	36	RFC 2230	Key eXchanger record
    //  LOC,        //	29	RFC 1876	Location record
    /// RFC 1035[1]	Mail exchange record
    MX,
    //  NAPTR,      //	35	RFC 3403	Naming Authority Pointer
    /// RFC 1035[1]	Name server record
    NS,
    /// RFC 1035[1]	Null server record, for testing
    NULL,
    /// RFC 6891	Option
    OPT,
    /// RFC 1035[1]	Pointer record
    PTR,
    //  RP,         //	17	RFC 1183	Responsible person
    /// RFC 1035[1] and RFC 2308[9]	Start of [a zone of] authority record
    SOA,
    /// RFC 2782	Service locator
    SRV,
    //  SSHFP,      //	44	RFC 4255	SSH Public Key Fingerprint
    //  TA,         //	32768	N/A	DNSSEC Trust Authorities
    //  TKEY,       //	249	RFC 2930	Secret key record
    ///	RFC 6698	TLSA certificate association
    TLSA,
    //  TSIG,       //	250	RFC 2845	Transaction Signature
    /// RFC 1035[1]	Text record
    TXT,

    /// A DNSSEC- or SIG(0)- specific record type.
    ///
    /// These types are in `DNSSECRecordType` to make them easy to disable when
    /// crypto functionality isn't needed.
    #[cfg(feature = "dnssec")]
    DNSSEC(DNSSECRecordType),

    /// Unknown Record type, or unsupported
    Unknown(u16),
}

impl RecordType {
    /// Returns true if this is an ANY
    #[inline]
    pub fn is_any(&self) -> bool {
        *self == RecordType::ANY
    }

    /// Returns true if this is a CNAME
    #[inline]
    pub fn is_cname(&self) -> bool {
        *self == RecordType::CNAME
    }

    /// Returns true if this is an SRV
    #[inline]
    pub fn is_srv(&self) -> bool {
        *self == RecordType::SRV
    }
}

impl FromStr for RecordType {
    type Err = ProtoError;

    /// Convert `&str` to `RecordType`
    ///
    /// ```
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::record_type::RecordType;
    ///
    /// let var: RecordType = RecordType::from_str("A").unwrap();
    /// assert_eq!(RecordType::A, var);
    /// ```
    fn from_str(str: &str) -> ProtoResult<Self> {
        match str {
            "A" => Ok(RecordType::A),
            "AAAA" => Ok(RecordType::AAAA),
            "CAA" => Ok(RecordType::CAA),
            "CNAME" => Ok(RecordType::CNAME),
            "NULL" => Ok(RecordType::NULL),
            "MX" => Ok(RecordType::MX),
            "NS" => Ok(RecordType::NS),
            "PTR" => Ok(RecordType::PTR),
            "SOA" => Ok(RecordType::SOA),
            "SRV" => Ok(RecordType::SRV),
            "TLSA" => Ok(RecordType::TLSA),
            "TXT" => Ok(RecordType::TXT),
            "ANY" | "*" => Ok(RecordType::ANY),
            "AXFR" => Ok(RecordType::AXFR),
            _ => Err(ProtoErrorKind::UnknownRecordTypeStr(str.to_string()).into()),
        }
    }
}

impl From<u16> for RecordType {
    /// Convert from `u16` to `RecordType`
    ///
    /// ```
    /// use trust_dns_proto::rr::record_type::RecordType;
    ///
    /// let var = RecordType::from(1);
    /// assert_eq!(RecordType::A, var);
    /// ```
    fn from(value: u16) -> Self {
        match value {
            1 => RecordType::A,
            28 => RecordType::AAAA,
            255 => RecordType::ANY,
            252 => RecordType::AXFR,
            257 => RecordType::CAA,
            5 => RecordType::CNAME,
            15 => RecordType::MX,
            2 => RecordType::NS,
            0 => RecordType::NULL,
            41 => RecordType::OPT,
            12 => RecordType::PTR,
            6 => RecordType::SOA,
            33 => RecordType::SRV,
            52 => RecordType::TLSA,
            16 => RecordType::TXT,
            #[cfg(feature = "dnssec")]
            48/*DNSKEY*/ |
            43/*DS*/ |
            25/*KEY*/ |
            47/*NSEC*/|
            50/*NSEC3*/|
            51/*NSEC3PARAM*/|
            46/*RRSIG*/|
            24/*SIG*/ => RecordType::DNSSEC(DNSSECRecordType::from(value)),
            // all unknown record types
            _ => RecordType::Unknown(value),
        }
    }
}

impl BinEncodable for RecordType {
    fn emit(&self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        encoder.emit_u16((*self).into())
    }
}

impl<'r> BinSerializable<'r> for RecordType {
    fn read(decoder: &mut BinDecoder) -> ProtoResult<Self> {
        decoder.read_u16().map(Self::from)
    }
}


// TODO make these a macro...


/// Convert from RecordType to &str
///
/// ```
/// use std::convert::From;
/// use trust_dns_proto::rr::record_type::RecordType;
///
/// let var: &'static str = From::from(RecordType::A);
/// assert_eq!("A", var);
///
/// let var: &'static str = RecordType::A.into();
/// assert_eq!("A", var);
/// ```
impl From<RecordType> for &'static str {
    fn from(rt: RecordType) -> &'static str {
        match rt {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::ANY => "ANY",
            RecordType::AXFR => "AXFR",
            RecordType::CAA => "CAA",
            RecordType::CNAME => "CNAME",
            RecordType::IXFR => "IXFR",
            RecordType::MX => "MX",
            RecordType::NULL => "NULL",
            RecordType::NS => "NS",
            RecordType::OPT => "OPT",
            RecordType::PTR => "PTR",
            RecordType::SOA => "SOA",
            RecordType::SRV => "SRV",
            RecordType::TLSA => "TLSA",
            RecordType::TXT => "TXT",
            #[cfg(feature = "dnssec")]
            RecordType::DNSSEC(rt) => rt.into(),
            RecordType::Unknown(_) => "Unknown",
        }
    }
}

/// Convert from RecordType to &str
///
/// ```
/// use std::convert::From;
/// use trust_dns_proto::rr::record_type::RecordType;
///
/// let var: u16 = RecordType::A.into();
/// assert_eq!(1, var);
/// ```
impl From<RecordType> for u16 {
    fn from(rt: RecordType) -> Self {
        match rt {
            RecordType::A => 1,
            RecordType::AAAA => 28,
            RecordType::ANY => 255,
            RecordType::AXFR => 252,
            RecordType::CAA => 257,
            RecordType::CNAME => 5,
            RecordType::IXFR => 251,
            RecordType::MX => 15,
            RecordType::NS => 2,
            RecordType::NULL => 0,
            RecordType::OPT => 41,
            RecordType::PTR => 12,
            RecordType::SOA => 6,
            RecordType::SRV => 33,
            RecordType::TLSA => 52,
            RecordType::TXT => 16,
            #[cfg(feature = "dnssec")]
            RecordType::DNSSEC(rt) => rt.into(),
            RecordType::Unknown(code) => code,
        }
    }
}

impl PartialOrd<RecordType> for RecordType {
    fn partial_cmp(&self, other: &RecordType) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RecordType {
    fn cmp(&self, other: &Self) -> Ordering {
        u16::from(*self).cmp(&u16::from(*other))
    }
}

impl Display for RecordType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        f.write_str(Into::<&str>::into(*self))
    }
}

#[test]
fn test_order() {
    let ordered = vec![
        RecordType::NULL,
        RecordType::A,
        RecordType::NS,
        RecordType::CNAME,
        RecordType::SOA,
        RecordType::PTR,
        RecordType::MX,
        RecordType::TXT,
        RecordType::AAAA,
        RecordType::SRV,
        RecordType::AXFR,
        RecordType::ANY,
    ];

    let mut unordered = vec![
        RecordType::ANY,
        RecordType::NULL,
        RecordType::AXFR,
        RecordType::A,
        RecordType::NS,
        RecordType::SOA,
        RecordType::SRV,
        RecordType::PTR,
        RecordType::MX,
        RecordType::CNAME,
        RecordType::TXT,
        RecordType::AAAA,
    ];

    unordered.sort();

    for rtype in unordered.clone() {
        println!("u16 for {:?}: {}", rtype, u16::from(rtype));
    }

    assert_eq!(5.partial_cmp(&28), Some(Ordering::Less));

    assert_eq!(ordered, unordered);
}
