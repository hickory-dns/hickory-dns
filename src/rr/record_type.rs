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
use std::convert::From;
use std::cmp::Ordering;

use ::serialize::binary::*;
use ::error::*;

type FromResult = Result<RecordType, DecodeError>;

#[derive(Debug, PartialEq, Eq, Hash, Ord, Copy, Clone)]
#[allow(dead_code)]
pub enum RecordType {
    A,          //	1	RFC 1035[1]	IPv4 Address record
    AAAA,       //	28	RFC 3596[2]	IPv6 address record
  //  AFSDB,      //	18	RFC 1183	AFS database record
  //  APL,        //	42	RFC 3123	Address Prefix List
  //  CAA,        //	257	RFC 6844	Certification Authority Authorization
  //  CDNSKEY,    //	60	RFC 7344	Child DNSKEY
  //  CDS,        //	59	RFC 7344	Child DS
  //  CERT,       //	37	RFC 4398	Certificate record
    CNAME,      //	5	RFC 1035[1]	Canonical name record
  //  DHCID,      //	49	RFC 4701	DHCP identifier
  //  DLV,        //	32769	RFC 4431	DNSSEC Lookaside Validation record
  //  DNAME,      //	39	RFC 2672	Delegation Name
    DNSKEY,     //	48	RFC 4034	DNS Key record: RSASHA256 and RSASHA512, RFC5702
    DS,         //	43	RFC 4034	Delegation signer: RSASHA256 and RSASHA512, RFC5702
  //  HIP,        //	55	RFC 5205	Host Identity Protocol
  //  IPSECKEY,   //	45	RFC 4025	IPsec Key
  //  KEY,        //	25	RFC 2535[3] and RFC 2930[4]	Key record
  //  KX,         //	36	RFC 2230	Key eXchanger record
  //  LOC,        //	29	RFC 1876	Location record
    MX,         //	15	RFC 1035[1]	Mail exchange record
  //  NAPTR,      //	35	RFC 3403	Naming Authority Pointer
    NS,         //	2	RFC 1035[1]	Name server record
    NULL,         //	0	RFC 1035[1]	Null server record, for testing
  //  NSEC,       //	47	RFC 4034	Next-Secure record
    NSEC3,      //	50	RFC 5155	NSEC record version 3
  //  NSEC3PARAM, //	51	RFC 5155	NSEC3 parameters
    PTR,        //	12	RFC 1035[1]	Pointer record
    RRSIG,      //	46	RFC 4034	DNSSEC signature: RSASHA256 and RSASHA512, RFC5702
  //  RP,         //	17	RFC 1183	Responsible person
    SIG,        //	24	RFC 2535 (2931)	Signature, to support 2137 Update
    SOA,        //	6	RFC 1035[1] and RFC 2308[9]	Start of [a zone of] authority record
    SRV,        //	33	RFC 2782	Service locator
  //  SSHFP,      //	44	RFC 4255	SSH Public Key Fingerprint
  //  TA,         //	32768	N/A	DNSSEC Trust Authorities
  //  TKEY,       //	249	RFC 2930	Secret key record
  //  TLSA,       //	52	RFC 6698	TLSA certificate association
  //  TSIG,       //	250	RFC 2845	Transaction Signature
    TXT,        //	16	RFC 1035[1]	Text record
    ANY,        //  *	255	RFC 1035[1]	All cached records, aka ANY
    AXFR,       //	252	RFC 1035[1]	Authoritative Zone Transfer
    IXFR,       //	251	RFC 1996	Incremental Zone Transfer
    OPT,        //	41	RFC 6891	Option
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
  pub fn from_str(str: &str) -> DecodeResult<Self> {
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
      _ => Err(DecodeError::UnknownRecordTypeStr(str.to_string())),
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
  pub fn from_u16(value: u16) -> DecodeResult<Self> {
    match value {
      1 => Ok(RecordType::A),
      28 => Ok(RecordType::AAAA),
      5 => Ok(RecordType::CNAME),
      0 => Ok(RecordType::NULL),
      15 => Ok(RecordType::MX),
      2 => Ok(RecordType::NS),
      12 => Ok(RecordType::PTR),
      6 => Ok(RecordType::SOA),
      33 => Ok(RecordType::SRV),
      16 => Ok(RecordType::TXT),
      255 => Ok(RecordType::ANY),
      252 => Ok(RecordType::AXFR),
      _ => Err(DecodeError::UnknownRecordTypeValue(value)),
    }
  }
}

impl BinSerializable<RecordType> for RecordType {
  fn read(decoder: &mut BinDecoder) -> DecodeResult<Self> {
    Self::from_u16(try!(decoder.read_u16()))
  }

  fn emit(&self, encoder: &mut BinEncoder) -> EncodeResult {
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
      RecordType::CNAME => "CNAME",
      RecordType::NULL => "NULL",
      RecordType::MX => "MX",
      RecordType::NS => "NS",
      RecordType::PTR => "PTR",
      RecordType::SOA => "SOA",
      RecordType::SRV => "SRV",
      RecordType::TXT => "TXT",
      RecordType::ANY => "ANY",
      RecordType::AXFR => "AXFR",
      _ => panic!("unsupported RecordType: {:?}", rt), // other types are planned
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
      RecordType::CNAME => 5,
      RecordType::NULL => 0,
      RecordType::MX => 15,
      RecordType::NS => 2,
      RecordType::PTR => 12,
      RecordType::SOA => 6,
      RecordType::SRV => 33,
      RecordType::TXT => 16,
      RecordType::ANY => 255,
      RecordType::AXFR => 252,
      _ => panic!("unsupported RecordType: {:?}", rt), // other types are planned...
    }
  }
}

impl PartialOrd<RecordType> for RecordType {
  fn partial_cmp(&self, other: &RecordType) -> Option<Ordering> {
    u16::from(*self).partial_cmp(&u16::from(*other))
  }
}
