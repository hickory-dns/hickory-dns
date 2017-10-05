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

use serialize::binary::*;
use error::*;

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
    //  CAA,        //	257	RFC 6844	Certification Authority Authorization
    //  CDNSKEY,    //	60	RFC 7344	Child DNSKEY
    //  CDS,        //	59	RFC 7344	Child DS
    //  CERT,       //	37	RFC 4398	Certificate record
    /// RFC 1035[1]	Canonical name record
    CNAME,
    //  DHCID,      //	49	RFC 4701	DHCP identifier
    //  DLV,        //	32769	RFC 4431	DNSSEC Lookaside Validation record
    //  DNAME,      //	39	RFC 2672	Delegation Name
    /// RFC 4034	DNS Key record: RSASHA256 and RSASHA512, RFC5702
    DNSKEY,
    /// RFC 4034	Delegation signer: RSASHA256 and RSASHA512, RFC5702
    DS,
    //  HIP,        //	55	RFC 5205	Host Identity Protocol
    //  IPSECKEY,   //	45	RFC 4025	IPsec Key
    /// RFC 1996	Incremental Zone Transfer
    IXFR,
    /// RFC 2535[3] and RFC 2930[4]	Key record
    KEY,
    //  KX,         //	36	RFC 2230	Key eXchanger record
    //  LOC,        //	29	RFC 1876	Location record
    /// RFC 1035[1]	Mail exchange record
    MX,
    //  NAPTR,      //	35	RFC 3403	Naming Authority Pointer
    /// RFC 1035[1]	Name server record
    NS,
    /// RFC 1035[1]	Null server record, for testing
    NULL,
    /// RFC 4034	Next-Secure record
    NSEC,
    /// RFC 5155	NSEC record version 3
    NSEC3,
    /// RFC 5155	NSEC3 parameters
    NSEC3PARAM,
    /// RFC 6891	Option
    OPT,
    /// RFC 1035[1]	Pointer record
    PTR,
    /// RFC 4034	DNSSEC signature: RSASHA256 and RSASHA512, RFC5702
    RRSIG,
    //  RP,         //	17	RFC 1183	Responsible person
    /// RFC 2535 (2931)	Signature, to support 2137 Update
    SIG,
    /// RFC 1035[1] and RFC 2308[9]	Start of [a zone of] authority record
    SOA,
    /// RFC 2782	Service locator
    SRV,
    //  SSHFP,      //	44	RFC 4255	SSH Public Key Fingerprint
    //  TA,         //	32768	N/A	DNSSEC Trust Authorities
    //  TKEY,       //	249	RFC 2930	Secret key record
    //  TLSA,       //	52	RFC 6698	TLSA certificate association
    //  TSIG,       //	250	RFC 2845	Transaction Signature
    /// RFC 1035[1]	Text record
    TXT,
}

impl RecordType {
    /// Convert from RecordType to &str
    ///
    /// ```
    /// use trust_dns::rr::record_type::RecordType;
    ///
    /// let var: RecordType = RecordType::from_str("A").unwrap();
    /// assert_eq!(RecordType::A, var);
    /// ```
    pub fn from_str(str: &str) -> ProtoResult<Self> {
        match str {
            "A" => Ok(RecordType::A),
            "AAAA" => Ok(RecordType::AAAA),
            "CNAME" => Ok(RecordType::CNAME),
            "NULL" => Ok(RecordType::NULL),
            "MX" => Ok(RecordType::MX),
            "NS" => Ok(RecordType::NS),
            "PTR" => Ok(RecordType::PTR),
            "SOA" => Ok(RecordType::SOA),
            "SRV" => Ok(RecordType::SRV),
            "TXT" => Ok(RecordType::TXT),
            "ANY" | "*" => Ok(RecordType::ANY),
            "AXFR" => Ok(RecordType::AXFR),
            _ => Err(ProtoErrorKind::UnknownRecordTypeStr(str.to_string()).into()),
        }
    }

    /// Convert from RecordType to &str
    ///
    /// ```
    /// use trust_dns::rr::record_type::RecordType;
    ///
    /// let var = RecordType::from_u16(1).unwrap();
    /// assert_eq!(RecordType::A, var);
    /// ```
    pub fn from_u16(value: u16) -> ProtoResult<Self> {
        match value {
            1 => Ok(RecordType::A),
            28 => Ok(RecordType::AAAA),
            255 => Ok(RecordType::ANY),
            252 => Ok(RecordType::AXFR),
            5 => Ok(RecordType::CNAME),
            48 => Ok(RecordType::DNSKEY),
            43 => Ok(RecordType::DS),
            25 => Ok(RecordType::KEY),
            15 => Ok(RecordType::MX),
            2 => Ok(RecordType::NS),
            47 => Ok(RecordType::NSEC),
            50 => Ok(RecordType::NSEC3),
            51 => Ok(RecordType::NSEC3PARAM),
            0 => Ok(RecordType::NULL),
            41 => Ok(RecordType::OPT),
            12 => Ok(RecordType::PTR),
            46 => Ok(RecordType::RRSIG),
            24 => Ok(RecordType::SIG),
            6 => Ok(RecordType::SOA),
            33 => Ok(RecordType::SRV),
            16 => Ok(RecordType::TXT),
            // TODO: this should probably return a generic value wrapper.
            _ => Err(ProtoErrorKind::UnknownRecordTypeValue(value).into()),
        }
    }
}

impl BinSerializable<RecordType> for RecordType {
    fn read(decoder: &mut BinDecoder) -> ProtoResult<Self> {
        Self::from_u16(try!(decoder.read_u16()))
    }

    fn emit(&self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        encoder.emit_u16((*self).into())
    }
}


// TODO make these a macro...


/// Convert from RecordType to &str
///
/// ```
/// use std::convert::From;
/// use trust_dns::rr::record_type::RecordType;
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
            RecordType::CNAME => "CNAME",
            RecordType::DNSKEY => "DNSKEY",
            RecordType::DS => "DS",
            RecordType::IXFR => "IXFR",
            RecordType::KEY => "KEY",
            RecordType::MX => "MX",
            RecordType::NULL => "NULL",
            RecordType::NS => "NS",
            RecordType::NSEC => "NSEC",
            RecordType::NSEC3 => "NSEC3",
            RecordType::NSEC3PARAM => "NSEC3PARAM",
            RecordType::OPT => "OPT",
            RecordType::PTR => "PTR",
            RecordType::RRSIG => "RRSIG",
            RecordType::SIG => "SIG",
            RecordType::SOA => "SOA",
            RecordType::SRV => "SRV",
            RecordType::TXT => "TXT",
        }
    }
}

/// Convert from RecordType to &str
///
/// ```
/// use std::convert::From;
/// use trust_dns::rr::record_type::RecordType;
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
            RecordType::CNAME => 5,
            RecordType::KEY => 25,
            RecordType::DNSKEY => 48,
            RecordType::DS => 43,
            RecordType::IXFR => 251,
            RecordType::MX => 15,
            RecordType::NS => 2,
            RecordType::NULL => 0,
            RecordType::NSEC => 47,
            RecordType::NSEC3 => 50,
            RecordType::NSEC3PARAM => 51,
            RecordType::OPT => 41,
            RecordType::PTR => 12,
            RecordType::RRSIG => 46,
            RecordType::SIG => 24,
            RecordType::SOA => 6,
            RecordType::SRV => 33,
            RecordType::TXT => 16,
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
