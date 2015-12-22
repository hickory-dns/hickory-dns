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
use std::net::{Ipv4Addr, Ipv6Addr};
use std::convert::From;
use std::cmp::Ordering;

use ::error::*;
use ::serialize::binary::*;
use ::serialize::txt::*;
use ::rr::dnssec::Algorithm;
use super::domain::Name;
use super::record_type::RecordType;
use super::rdata;

/// 3.3. Standard RRs
///
/// The following RR definitions are expected to occur, at least
/// potentially, in all classes.  In particular, NS, SOA, CNAME, and PTR
/// will be used in all classes, and have the same format in all classes.
/// Because their RDATA format is known, all domain names in the RDATA
/// section of these RRs may be compressed.
///
/// <domain-name> is a domain name represented as a series of labels, and
/// terminated by a label with zero length.  <character-string> is a single
/// length octet followed by that number of characters.  <character-string>
/// is treated as binary information, and can be up to 256 characters in
/// length (including the length octet).
///
/// TODO: clean this up, see this: https://www.reddit.com/r/rust/comments/2rdoxx/enum_variants_as_types/
///  and this: https://play.rust-lang.org/?code=%23!%5Bfeature(associated_types)%5D%0A%0Aenum%20ColorV%20%7B%20Red%2C%20Blue%2C%20Green%20%7D%0A%0A%23%5Bderive(Show%2C%20PartialEq)%5D%0Astruct%20Red%3B%0A%23%5Bderive(Show%2C%20PartialEq)%5D%0Astruct%20Blue%3B%0A%23%5Bderive(Show%2C%20PartialEq)%5D%0Astruct%20Green%3B%0A%0Atrait%20Color%20%7B%0A%20%20%20%20type%20Variant%3B%0A%20%20%20%20%2F%2F%20fn%20repr()%20-%3E%20Variant%0A%20%20%20%20fn%20value(%26self)%20-%3E%20ColorV%3B%0A%7D%0A%0Aimpl%20Color%20for%20Red%20%7B%0A%20%20%20%20type%20Variant%20%3D%20Red%3B%0A%20%20%20%20fn%20value(%26self)%20-%3E%20ColorV%20%7B%20ColorV%3A%3ARed%20%7D%0A%7D%0A%0Aimpl%20Color%20for%20Blue%20%7B%0A%20%20%20%20type%20Variant%20%3D%20Blue%3B%0A%20%20%20%20fn%20value(%26self)%20-%3E%20ColorV%20%7B%20ColorV%3A%3ABlue%20%7D%0A%7D%0A%0Aimpl%20Color%20for%20Green%20%7B%0A%20%20%20%20type%20Variant%20%3D%20Green%3B%0A%20%20%20%20fn%20value(%26self)%20-%3E%20ColorV%20%7B%20ColorV%3A%3AGreen%20%7D%0A%7D%0A%0Atrait%20TypeEq%3CA%3E%20%7B%7D%0Aimpl%3CA%3E%20TypeEq%3CA%3E%20for%20A%20%7B%7D%0A%0Afn%20openminded_function%3CC%3A%20Color%3E(c%3A%20C)%20%7B%20%0A%20%20%20%20panic!(%22Types%20are%20for%20humans%22)%20%20%0A%7D%0A%0A%2F%2F%20Eventually%20this%20should%20just%20be%20C%3A%20Color%3CVariant%3DBlue%3E%0Afn%20closeminded_function%3CC%3A%20Color%3E(c%3A%20C)%20where%20C%3A%3AVariant%3A%20TypeEq%3CBlue%3E%20%7B%20%0A%20%20%20%20panic!(%22Types%20are%20for%20compilers%22)%20%0A%7D%0A%0Afn%20i_want_pattern_matching%3CC%3A%20Color%3E(c%3A%20C)%20%7B%0A%20%20%20%20match%20c.value()%20%7B%0A%20%20%20%20%20%20%20%20ColorV%3A%3ARed%20%3D%3E%20println!(%22red%22)%2C%0A%20%20%20%20%20%20%20%20ColorV%3A%3ABlue%20%3D%3E%20println!(%22blue%22)%2C%0A%20%20%20%20%20%20%20%20ColorV%3A%3AGreen%20%3D%3E%20println!(%22green%22)%0A%20%20%20%20%7D%0A%7D%0A%0A%2F%2F%20This%20is%20a%20type%20level%20function%20between%20Colors%20that%20encodes%0A%2F%2F%20that%20the%20variant's%20info%20statically%20allowing%20%0A%2F%2F%20to%20track%20which%20variant%20we%20have%20and%20disallow%20rule%20violations.%0Atrait%20Invert%20%7B%0A%20%20%20%20type%20Result%3A%20Color%3B%0A%20%20%20%20fn%20inversion(%26self)%20-%3E%20Self%3A%3AResult%3B%0A%7D%0A%0Aimpl%20Invert%20for%20Red%20%7B%0A%20%20%20%20type%20Result%20%3D%20Blue%3B%0A%20%20%20%20fn%20inversion(%26self)%20-%3E%20Blue%20%7B%20Blue%20%7D%0A%7D%0A%0Aimpl%20Invert%20for%20Blue%20%7B%0A%20%20%20%20type%20Result%20%3D%20Green%3B%0A%20%20%20%20fn%20inversion(%26self)%20-%3E%20Green%20%7B%20Green%20%7D%0A%7D%0A%0Aimpl%20Invert%20for%20Green%20%7B%0A%20%20%20%20type%20Result%20%3D%20Red%3B%0A%20%20%20%20fn%20inversion(%26self)%20-%3E%20Red%20%7B%20Red%20%7D%0A%7D%0A%0A%2F%2F%20Example%20use%20right%20now%0Afn%20main()%20%7B%0A%20%20%20%20let%20color%20%3D%20Red%3B%0A%20%20%20%20%2F%2F%20works%20fine%20openminded_function(color)%3B%0A%20%20%20%20%2F%2F%20fails%20closeminded_function(color)%3B%20error%20messages%20would%20be%20better%20with%20real%20equality%20constraints%0A%20%20%20%20closeminded_function(Blue)%3B%0A%20%20%20%20assert_eq!(Green%2C%20Red.inversion().inversion())%0A%7D
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum RData {
  //-- RFC 1035 -- Domain Implementation and Specification    November 1987
  //
  // 3.4. Internet specific RRs
  //
  // 3.4.1. A RDATA format
  //
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     |                    ADDRESS                    |
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //
  // where:
  //
  // ADDRESS         A 32 bit Internet address.
  //
  // Hosts that have multiple Internet addresses will have multiple A
  // records.
  //
  // A records cause no additional section processing.  The RDATA section of
  // an A line in a master file is an Internet address expressed as four
  // decimal numbers separated by dots without any imbedded spaces (e.g.,
  // "10.2.0.52" or "192.0.5.6").
  A { address: Ipv4Addr },

  //-- RFC 1886 -- IPv6 DNS Extensions              December 1995
  //
  // 2.2 AAAA data format
  //
  //    A 128 bit IPv6 address is encoded in the data portion of an AAAA
  //    resource record in network byte order (high-order byte first).
  AAAA { address: Ipv6Addr },


  //   3.3. Standard RRs
  //
  // The following RR definitions are expected to occur, at least
  // potentially, in all classes.  In particular, NS, SOA, CNAME, and PTR
  // will be used in all classes, and have the same format in all classes.
  // Because their RDATA format is known, all domain names in the RDATA
  // section of these RRs may be compressed.
  //
  // <domain-name> is a domain name represented as a series of labels, and
  // terminated by a label with zero length.  <character-string> is a single
  // length octet followed by that number of characters.  <character-string>
  // is treated as binary information, and can be up to 256 characters in
  // length (including the length octet).
  //
  // 3.3.1. CNAME RDATA format
  //
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     /                     CNAME                     /
  //     /                                               /
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //
  // where:
  //
  // CNAME           A <domain-name> which specifies the canonical or primary
  //                 name for the owner.  The owner name is an alias.
  //
  // CNAME RRs cause no additional section processing, but name servers may
  // choose to restart the query at the canonical name in certain cases.  See
  // the description of name server logic in [RFC-1034] for details.
  CNAME { cname: Name },


  // 3.3.9. MX RDATA format
  //
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     |                  PREFERENCE                   |
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     /                   EXCHANGE                    /
  //     /                                               /
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //
  // where:
  //
  // PREFERENCE      A 16 bit integer which specifies the preference given to
  //                 this RR among others at the same owner.  Lower values
  //                 are preferred.
  //
  // EXCHANGE        A <domain-name> which specifies a host willing to act as
  //                 a mail exchange for the owner name.
  //
  // MX records cause type A additional section processing for the host
  // specified by EXCHANGE.  The use of MX RRs is explained in detail in
  // [RFC-974].
  MX { preference: u16, exchange: Name },

  // 3.3.10. NULL RDATA format (EXPERIMENTAL)
  //
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     /                  <anything>                   /
  //     /                                               /
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //
  // Anything at all may be in the RDATA field so long as it is 65535 octets
  // or less.
  //
  // NULL records cause no additional section processing.  NULL RRs are not
  // allowed in master files.  NULLs are used as placeholders in some
  // experimental extensions of the DNS.
  NULL { anything: Vec<u8> },

  // 3.3.11. NS RDATA format
  //
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     /                   NSDNAME                     /
  //     /                                               /
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //
  // where:
  //
  // NSDNAME         A <domain-name> which specifies a host which should be
  //                 authoritative for the specified class and domain.
  //
  // NS records cause both the usual additional section processing to locate
  // a type A record, and, when used in a referral, a special search of the
  // zone in which they reside for glue information.
  //
  // The NS RR states that the named host should be expected to have a zone
  // starting at owner name of the specified class.  Note that the class may
  // not indicate the protocol family which should be used to communicate
  // with the host, although it is typically a strong hint.  For example,
  // hosts which are name servers for either Internet (IN) or Hesiod (HS)
  // class information are normally queried using IN class protocols.
  NS { nsdname: Name },

  // RFC 6891                   EDNS(0) Extensions                 April 2013
  // 6.1.2.  Wire Format
  //
  //        +------------+--------------+------------------------------+
  //        | Field Name | Field Type   | Description                  |
  //        +------------+--------------+------------------------------+
  //        | NAME       | domain name  | MUST be 0 (root domain)      |
  //        | TYPE       | u_int16_t    | OPT (41)                     |
  //        | CLASS      | u_int16_t    | requestor's UDP payload size |
  //        | TTL        | u_int32_t    | extended RCODE and flags     |
  //        | RDLEN      | u_int16_t    | length of all RDATA          |
  //        | RDATA      | octet stream | {attribute,value} pairs      |
  //        +------------+--------------+------------------------------+
  //
  // The variable part of an OPT RR may contain zero or more options in
  //    the RDATA.  Each option MUST be treated as a bit field.  Each option
  //    is encoded as:
  //
  //                   +0 (MSB)                            +1 (LSB)
  //        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  //     0: |                          OPTION-CODE                          |
  //        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  //     2: |                         OPTION-LENGTH                         |
  //        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  //     4: |                                                               |
  //        /                          OPTION-DATA                          /
  //        /                                                               /
  //        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  OPT { option_rdata: Vec<u8> },

  // 3.3.12. PTR RDATA format
  //
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     /                   PTRDNAME                    /
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //
  // where:
  //
  // PTRDNAME        A <domain-name> which points to some location in the
  //                 domain name space.
  //
  // PTR records cause no additional section processing.  These RRs are used
  // in special domains to point to some other location in the domain space.
  // These records are simple data, and don't imply any special processing
  // similar to that performed by CNAME, which identifies aliases.  See the
  // description of the IN-ADDR.ARPA domain for an example.
  PTR { ptrdname: Name },

  // RFC 2535 & 2931   DNS Security Extensions               March 1999
  //
  // 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
  // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |        type covered           |  algorithm    |     labels    |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                         original TTL                          |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                      signature expiration                     |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                      signature inception                      |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |            key  tag           |                               |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         signer's name         +
  // |                                                               /
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-/
  // /                                                               /
  // /                            signature                          /
  // /                                                               /
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  SIG { type_covered: u16, algorithm: Algorithm, num_labels: u8, original_ttl: u32,
        sig_expiration: u32, sig_inception: u32, key_tag: u16, signer_name: Name, sig: Vec<u8> },

  // 3.3.13. SOA RDATA format
  //
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     /                     MNAME                     /
  //     /                                               /
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     /                     RNAME                     /
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     |                    SERIAL                     |
  //     |                                               |
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     |                    REFRESH                    |
  //     |                                               |
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     |                     RETRY                     |
  //     |                                               |
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     |                    EXPIRE                     |
  //     |                                               |
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     |                    MINIMUM                    |
  //     |                                               |
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //
  // where:
  //
  // MNAME           The <domain-name> of the name server that was the
  //                 original or primary source of data for this zone.
  //
  // RNAME           A <domain-name> which specifies the mailbox of the
  //                 person responsible for this zone.
  //
  // SERIAL          The unsigned 32 bit version number of the original copy
  //                 of the zone.  Zone transfers preserve this value.  This
  //                 value wraps and should be compared using sequence space
  //                 arithmetic.
  //
  // REFRESH         A 32 bit time interval before the zone should be
  //                 refreshed.
  //
  // RETRY           A 32 bit time interval that should elapse before a
  //                 failed refresh should be retried.
  //
  // EXPIRE          A 32 bit time value that specifies the upper limit on
  //                 the time interval that can elapse before the zone is no
  //                 longer authoritative.
  //
  // MINIMUM         The unsigned 32 bit minimum TTL field that should be
  //                 exported with any RR from this zone.
  //
  // SOA records cause no additional section processing.
  //
  // All times are in units of seconds.
  //
  // Most of these fields are pertinent only for name server maintenance
  // operations.  However, MINIMUM is used in all query operations that
  // retrieve RRs from a zone.  Whenever a RR is sent in a response to a
  // query, the TTL field is set to the maximum of the TTL field from the RR
  // and the MINIMUM field in the appropriate SOA.  Thus MINIMUM is a lower
  // bound on the TTL field for all RRs in a zone.  Note that this use of
  // MINIMUM should occur when the RRs are copied into the response and not
  // when the zone is loaded from a master file or via a zone transfer.  The
  // reason for this provison is to allow future dynamic update facilities to
  // change the SOA RR with known semantics.
  SOA { mname: Name, rname: Name, serial: u32, refresh: i32, retry: i32, expire: i32, minimum: u32, },

  // RFC 2782                       DNS SRV RR                  February 2000
  //
  // The format of the SRV RR
  //
  //  _Service._Proto.Name TTL Class SRV Priority Weight Port Target
  SRV { priority: u16, weight: u16, port: u16, target: Name, },

  // 3.3.14. TXT RDATA format
  //
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     /                   TXT-DATA                    /
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //
  // where:
  //
  // TXT-DATA        One or more <character-string>s.
  //
  // TXT RRs are used to hold descriptive text.  The semantics of the text
  // depends on the domain where it is found.
  TXT { txt_data: Vec<String> },


}

impl RData {
  pub fn parse(record_type: RecordType, tokens: &Vec<Token>, origin: Option<&Name>) -> ParseResult<Self> {
    match record_type {
      RecordType::A => rdata::a::parse(tokens),
      RecordType::AAAA => rdata::aaaa::parse(tokens),
      RecordType::CNAME => rdata::cname::parse(tokens, origin),
      RecordType::MX => rdata::mx::parse(tokens, origin),
      RecordType::NULL => rdata::null::parse(tokens),
      RecordType::NS => rdata::ns::parse(tokens, origin),
      RecordType::PTR => rdata::ptr::parse(tokens, origin),
      RecordType::SOA => rdata::soa::parse(tokens, origin),
      RecordType::SRV => rdata::srv::parse(tokens, origin),
      RecordType::TXT => rdata::txt::parse(tokens),
      _ => panic!("parser not yet implemented for: {:?}", record_type),
    }
  }

  fn to_bytes(&self) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    {
      let mut encoder: BinEncoder = BinEncoder::new(&mut buf);
      self.emit(&mut encoder).unwrap_or_else(|_| { warn!("could not encode RDATA: {:?}", self); ()});
    }
    buf
  }
}

impl BinSerializable<RData> for RData {
  fn read(decoder: &mut BinDecoder) -> DecodeResult<Self> {
    match try!(decoder.record_type().ok_or(DecodeError::NoRecordDataType)) {
      RecordType::A => rdata::a::read(decoder),
      RecordType::AAAA => rdata::aaaa::read(decoder),
      RecordType::CNAME => rdata::cname::read(decoder),
      RecordType::MX => rdata::mx::read(decoder),
      RecordType::NULL => rdata::null::read(decoder),
      RecordType::NS => rdata::ns::read(decoder),
      RecordType::OPT => rdata::opt::read(decoder),
      RecordType::PTR => rdata::ptr::read(decoder),
      RecordType::SIG => rdata::sig::read(decoder),
      RecordType::SOA => rdata::soa::read(decoder),
      RecordType::SRV => rdata::srv::read(decoder),
      RecordType::TXT => rdata::txt::read(decoder),
      record_type @ _ => panic!("read not yet implemented for: {:?}", record_type),
    }
  }

  fn emit(&self, encoder: &mut BinEncoder) -> EncodeResult {
    match *self {
      RData::A{..} => rdata::a::emit(encoder, self),
      RData::AAAA{..} => rdata::aaaa::emit(encoder, self),RData::CNAME{..} => rdata::cname::emit(encoder, self),
      RData::MX{..} => rdata::mx::emit(encoder, self),
      RData::NULL{..} => rdata::null::emit(encoder, self),
      RData::NS{..} => rdata::ns::emit(encoder, self),
      RData::OPT{..} => rdata::opt::emit(encoder, self),
      RData::PTR{..} => rdata::ptr::emit(encoder, self),
      RData::SIG{..} => rdata::sig::emit(encoder, self),
      RData::SOA{..} => rdata::soa::emit(encoder, self),
      RData::SRV{..} => rdata::srv::emit(encoder, self),
      RData::TXT{..} => rdata::txt::emit(encoder, self),
    }
  }
}

impl<'a> From<&'a RData> for RecordType {
  fn from(rdata: &'a RData) -> Self {
    match *rdata {
      RData::A{..} => RecordType::A,
      RData::AAAA{..} => RecordType::AAAA,
      RData::CNAME{..} => RecordType::CNAME,
      RData::MX{..} => RecordType::MX,
      RData::NS{..} => RecordType::NS,
      RData::NULL{..} => RecordType::NULL,
      RData::OPT{..} => RecordType::OPT,
      RData::PTR{..} => RecordType::PTR,
      RData::SIG{..} => RecordType::SIG,
      RData::SOA{..} => RecordType::SOA,
      RData::SRV{..} => RecordType::SRV,
      RData::TXT{..} => RecordType::TXT,
    }
  }
}

impl PartialOrd<RData> for RData {
  fn partial_cmp(&self, other: &RData) -> Option<Ordering> {
    Some(self.cmp(&other))
  }
}

impl Ord for RData {
  // RFC 4034                DNSSEC Resource Records               March 2005
  //
  // 6.3.  Canonical RR Ordering within an RRset
  //
  //    For the purposes of DNS security, RRs with the same owner name,
  //    class, and type are sorted by treating the RDATA portion of the
  //    canonical form of each RR as a left-justified unsigned octet sequence
  //    in which the absence of an octet sorts before a zero octet.
  //
  //    [RFC2181] specifies that an RRset is not allowed to contain duplicate
  //    records (multiple RRs with the same owner name, class, type, and
  //    RDATA).  Therefore, if an implementation detects duplicate RRs when
  //    putting the RRset in canonical form, it MUST treat this as a protocol
  //    error.  If the implementation chooses to handle this protocol error
  //    in the spirit of the robustness principle (being liberal in what it
  //    accepts), it MUST remove all but one of the duplicate RR(s) for the
  //    purposes of calculating the canonical form of the RRset.
  fn cmp(&self, other: &Self) -> Ordering {
    // TODO: how about we just store the bytes with the decoded data?
    //  the decoded data is useful for queries, the encoded data is needed for transfers, signing
    //  and ordering.
    self.to_bytes().cmp(&other.to_bytes())
  }
}

#[cfg(test)]
mod tests {
  use std::net::Ipv6Addr;
  use std::net::Ipv4Addr;
  use std::str::FromStr;

  use super::*;
  use ::serialize::binary::*;
  use ::serialize::binary::bin_tests::test_emit_data_set;
  use ::rr::domain::Name;

  fn get_data() -> Vec<(RData, Vec<u8>)> {
    vec![
    (RData::CNAME{cname: Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()])}, vec![3,b'w',b'w',b'w',7,b'e',b'x',b'a',b'm',b'p',b'l',b'e',3,b'c',b'o',b'm',0]),
    (RData::MX{preference: 256, exchange: Name::with_labels(vec!["n".to_string()])}, vec![1,0,1,b'n',0]),
    (RData::NS{nsdname: Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()])}, vec![3,b'w',b'w',b'w',7,b'e',b'x',b'a',b'm',b'p',b'l',b'e',3,b'c',b'o',b'm',0]),
    (RData::PTR{ptrdname: Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()])}, vec![3,b'w',b'w',b'w',7,b'e',b'x',b'a',b'm',b'p',b'l',b'e',3,b'c',b'o',b'm',0]),
    (RData::SOA{mname: Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()]),
    rname: Name::with_labels(vec!["xxx".to_string(),"example".to_string(),"com".to_string()]),
    serial: u32::max_value(), refresh: -1 as i32, retry: -1 as i32, expire: -1 as i32, minimum: u32::max_value()},
    vec![3,b'w',b'w',b'w',7,b'e',b'x',b'a',b'm',b'p',b'l',b'e',3,b'c',b'o',b'm',0,
    3,b'x',b'x',b'x',0xC0, 0x04,
    0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF]),
    (RData::TXT{txt_data: vec!["abcdef".to_string(), "ghi".to_string(), "".to_string(), "j".to_string()]},
    vec![6,b'a',b'b',b'c',b'd',b'e',b'f', 3,b'g',b'h',b'i', 0, 1,b'j']),
    (RData::A{ address: Ipv4Addr::from_str("0.0.0.0").unwrap()}, vec![0,0,0,0]),
    (RData::AAAA{ address: Ipv6Addr::from_str("::").unwrap()}, vec![0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0]),
    (RData::SRV{ priority: 1, weight: 2, port: 3, target: Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()]),}, vec![0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 3,b'w',b'w',b'w',7,b'e',b'x',b'a',b'm',b'p',b'l',b'e',3,b'c',b'o',b'm',0]),
    ]
  }

  // TODO this test kinda sucks, shows the problem with not storing the binary parts
  #[test]
  fn test_order() {
    let ordered: Vec<RData> = vec![
      RData::A{ address: Ipv4Addr::from_str("0.0.0.0").unwrap()},
      RData::AAAA{ address: Ipv6Addr::from_str("::").unwrap()},
      RData::SRV{ priority: 1, weight: 2, port: 3, target: Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()]),},
      RData::MX{preference: 256, exchange: Name::with_labels(vec!["n".to_string()])},
      RData::CNAME{cname: Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()])},
      RData::PTR{ptrdname: Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()])},
      RData::NS{nsdname: Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()])},
      RData::SOA{mname: Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()]),
                 rname: Name::with_labels(vec!["xxx".to_string(),"example".to_string(),"com".to_string()]),
                 serial: u32::max_value(), refresh: -1 as i32, retry: -1 as i32, expire: -1 as i32, minimum: u32::max_value()},
      RData::TXT{txt_data: vec!["abcdef".to_string(), "ghi".to_string(), "".to_string(), "j".to_string()]},
    ];
    let mut unordered = vec![
      RData::CNAME{cname: Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()])},
      RData::MX{preference: 256, exchange: Name::with_labels(vec!["n".to_string()])},
      RData::PTR{ptrdname: Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()])},
      RData::NS{nsdname: Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()])},
      RData::SOA{mname: Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()]),
                 rname: Name::with_labels(vec!["xxx".to_string(),"example".to_string(),"com".to_string()]),
                 serial: u32::max_value(), refresh: -1 as i32, retry: -1 as i32, expire: -1 as i32, minimum: u32::max_value()},
      RData::TXT{txt_data: vec!["abcdef".to_string(), "ghi".to_string(), "".to_string(), "j".to_string()]},
      RData::A{ address: Ipv4Addr::from_str("0.0.0.0").unwrap()},
      RData::AAAA{ address: Ipv6Addr::from_str("::").unwrap()},
      RData::SRV{ priority: 1, weight: 2, port: 3, target: Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()]),},
    ];

    unordered.sort();
    assert_eq!(ordered, unordered);
  }

  #[test]
  fn test_read() {
    let mut test_pass = 0;
    for (expect, binary) in get_data() {
      test_pass += 1;
      println!("test {}: {:?}", test_pass, binary);
      let length = binary.len() as u16; // pre exclusive borrow
      let mut decoder = BinDecoder::new(&binary);

      decoder.set_rdata_length(length);
      decoder.set_record_type(::rr::record_type::RecordType::from(&expect));

      assert_eq!(RData::read(&mut decoder).unwrap(), expect);
    }
  }

  #[test]
  fn test_write_to() {
    test_emit_data_set(get_data(), |e,d| d.emit(e));
  }
}
