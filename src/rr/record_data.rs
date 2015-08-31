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

use ::error::*;
use ::serialize::binary::*;
use ::serialize::txt::*;
use super::domain::Name;
use super::record_type::RecordType;
use super::rdata;

// 3.3. Standard RRs
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
#[derive(Debug, PartialEq)]
pub enum RData {
  //-- RFC 1035 -- Domain Implementation and Specification    November 1987

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

  // 3.3.2. HINFO RDATA format
  //
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     /                      CPU                      /
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     /                       OS                      /
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //
  // where:
  //
  // CPU             A <character-string> which specifies the CPU type.
  //
  // OS              A <character-string> which specifies the operating
  //                 system type.
  //
  // Standard values for CPU and OS can be found in [RFC-1010].
  //
  // HINFO records are used to acquire general information about a host.  The
  // main use is for protocols such as FTP that can use special procedures
  // when talking between machines or operating systems of the same type.
  HINFO { cpu: String, os: String},

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

  // 3.4.2. WKS RDATA format
  //
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     |                    ADDRESS                    |
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     |       PROTOCOL        |                       |
  //     +--+--+--+--+--+--+--+--+                       |
  //     |                                               |
  //     /                   <BIT MAP>                   /
  //     /                                               /
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //
  // where:
  //
  // ADDRESS         An 32 bit Internet address
  //
  // PROTOCOL        An 8 bit IP protocol number
  //
  // <BIT MAP>       A variable length bit map.  The bit map must be a
  //                 multiple of 8 bits long.
  //
  // The WKS record is used to describe the well known services supported by
  // a particular protocol on a particular internet address.  The PROTOCOL
  // field specifies an IP protocol number, and the bit map has one bit per
  // port of the specified protocol.  The first bit corresponds to port 0,
  // the second to port 1, etc.  If the bit map does not include a bit for a
  // protocol of interest, that bit is assumed zero.  The appropriate values
  // and mnemonics for ports and protocols are specified in [RFC-1010].
  //
  // For example, if PROTOCOL=TCP (6), the 26th bit corresponds to TCP port
  // 25 (SMTP).  If this bit is set, a SMTP server should be listening on TCP
  // port 25; if zero, SMTP service is not supported on the specified
  // address.
  //
  // The purpose of WKS RRs is to provide availability information for
  // servers for TCP and UDP.  If a server supports both TCP and UDP, or has
  // multiple Internet addresses, then multiple WKS RRs are used.
  //
  // WKS RRs cause no additional section processing.
  //
  // In master files, both ports and protocols are expressed using mnemonics
  // or decimal numbers.
  WKS { address: Ipv4Addr, protocol: u8, bitmap: Vec<u8> },

  //-- RFC 1886 -- IPv6 DNS Extensions              December 1995

  // 2.2 AAAA data format
  //
  //    A 128 bit IPv6 address is encoded in the data portion of an AAAA
  //    resource record in network byte order (high-order byte first).
  AAAA { address: Ipv6Addr },
}

impl RData {
  pub fn parse(record_type: RecordType, tokens: &Vec<Token>) -> ParseResult<Self> {
    match record_type {
      RecordType::CNAME => rdata::cname::parse(tokens),
      RecordType::MX => rdata::mx::parse(tokens),
      RecordType::NULL => rdata::null::parse(tokens),
      RecordType::NS => rdata::ns::parse(tokens),
      RecordType::PTR => rdata::ptr::parse(tokens),
      RecordType::SOA => rdata::soa::parse(tokens),
      RecordType::TXT => rdata::txt::parse(tokens),
      RecordType::A => rdata::a::parse(tokens),
      RecordType::AAAA => rdata::aaaa::parse(tokens),
      _ => panic!("unsupported RecordType: {:?}", record_type)
    }
  }
}

impl BinSerializable for RData {
  fn read(decoder: &mut BinDecoder) -> DecodeResult<Self> {
    match try!(decoder.record_type().ok_or(DecodeError::NoRecordDataType)) {
      RecordType::CNAME => rdata::cname::read(decoder),
      RecordType::MX => rdata::mx::read(decoder),
      RecordType::NULL => rdata::null::read(decoder),
      RecordType::NS => rdata::ns::read(decoder),
      RecordType::PTR => rdata::ptr::read(decoder),
      RecordType::SOA => rdata::soa::read(decoder),
      RecordType::TXT => rdata::txt::read(decoder),
      RecordType::A => rdata::a::read(decoder),
      RecordType::AAAA => rdata::aaaa::read(decoder),
      _ => panic!("unsupported RecordType: {:?}", decoder.record_type().unwrap()) // safe unwrap
    }
  }

  fn emit(&self, encoder: &mut BinEncoder) -> EncodeResult {
    match *self {
      RData::CNAME{..} => rdata::cname::emit(encoder, self),
      RData::MX{..} => rdata::mx::emit(encoder, self),
      RData::NULL{..} => rdata::null::emit(encoder, self),
      RData::NS{..} => rdata::ns::emit(encoder, self),
      RData::PTR{..} => rdata::ptr::emit(encoder, self),
      RData::SOA{..} => rdata::soa::emit(encoder, self),
      RData::TXT{..} => rdata::txt::emit(encoder, self),
      RData::A{..} => rdata::a::emit(encoder, self),
      RData::AAAA{..} => rdata::aaaa::emit(encoder, self),
      _ => panic!("unsupported RecordType: {:?}", self)
    }
  }
}

impl<'a> From<&'a RData> for RecordType {
  fn from(rdata: &'a RData) -> Self {
    match *rdata {
      RData::CNAME{..} => RecordType::CNAME,
      RData::MX{..} => RecordType::MX,
      RData::NS{..} => RecordType::NS,
      RData::PTR{..} => RecordType::PTR,
      RData::SOA{..} => RecordType::SOA,
      RData::TXT{..} => RecordType::TXT,
      RData::A{..} => RecordType::A,
      RData::AAAA{..} => RecordType::AAAA,
      _ => panic!("unsupported RecordType: {:?}", rdata)
    }
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
    3,b'x',b'x',b'x',7,b'e',b'x',b'a',b'm',b'p',b'l',b'e',3,b'c',b'o',b'm',0,
    0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF]),
    (RData::TXT{txt_data: vec!["abcdef".to_string(), "ghi".to_string(), "".to_string(), "j".to_string()]},
    vec![6,b'a',b'b',b'c',b'd',b'e',b'f', 3,b'g',b'h',b'i', 0, 1,b'j']),
    (RData::A{ address: Ipv4Addr::from_str("0.0.0.0").unwrap()}, vec![0,0,0,0]),
    (RData::AAAA{ address: Ipv6Addr::from_str("::").unwrap()}, vec![0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0])
    ]
  }

  #[test]
  fn test_read() {
    let mut test_pass = 0;
    for (expect, binary) in get_data() {
      test_pass += 1;
      println!("test {}: {:?}", test_pass, binary);
      let length = binary.len() as u16; // pre exclusive borrow
      let mut decoder = BinDecoder::new(binary);

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
