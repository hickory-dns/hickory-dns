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
use std::collections::HashMap;

use ::rr::{Record, RecordType, RData};
use ::rr::dnssec::SupportedAlgorithms;

#[derive(Debug, PartialEq)]
pub struct Edns {
  // high 8 bits that make up the 12 bit total field when included with the 4bit rcode from the
  //  header (from TTL)
  extended_rcode_high: u8,
  // Indicates the implementation level of the setter. (from TTL)
  version: u8,
  // Is DNSSec supported (from TTL)
  dnssec_ok: bool,
  // max payload size, minimum of 512, (from RR CLASS)
  max_payload: u16,

  options: HashMap<EdnsCode, EdnsOption>,
}

impl<'a> From<&'a Record> for Edns {
  fn from(value: &'a Record) -> Self {
    assert!(value.get_rr_type() == RecordType::OPT);

    let extended_rcode_high: u8 = ((value.get_ttl() & 0x0000FF00u32) >> 8) as u8;
    let version: u8 = (value.get_ttl() & 0x000000FFu32) as u8;
    let dnssec_ok: bool = value.get_ttl() & 0x80000000 == 0x80000000;
    let max_payload: u16 = if u16::from(value.get_dns_class()) < 512 { 512 } else { value.get_dns_class().into() };
    let mut options: HashMap<EdnsCode, EdnsOption> = HashMap::new();

    if let &RData::OPT{ ref option_rdata } = value.get_rdata() {
      let mut state: OptReadState = OptReadState::Code1;
      //    OPTION-CODE
      //       Assigned by the Expert Review process as defined by the DNSEXT
      //       working group and the IESG.
      //
      //    OPTION-LENGTH
      //       Size (in octets) of OPTION-DATA.
      //
      //    OPTION-DATA
      //       Varies per OPTION-CODE.  MUST be treated as a bit field.
      for (i, byte) in option_rdata.iter().enumerate() {
        match state {
          OptReadState::Code1 => {
            state = OptReadState::Code2{ high: *byte };
          },
          OptReadState::Code2{high} => {
            state = OptReadState::Length1{ code: ((((high as u16) << 8) & 0xFF00u16) + (*byte as u16 & 0x00FFu16)).into() };
          },
          OptReadState::Length1{code} => {
            state = OptReadState::Length2{ code: code, high: *byte };
          },
          OptReadState::Length2{code, high } => {
            state = OptReadState::Data{code:code, length: (((high as usize) << 8) & 0xFF00usize) + (*byte as usize & 0x00FFusize), collected: 0 };
          },
          OptReadState::Data{code, length, collected } => {
            let collected = collected + 1;
            if length == collected {
              options.insert(code, (code, &option_rdata[(i - length)..i]).into());
              state = OptReadState::Code1;
            } else {
              state = OptReadState::Data{code: code, length: length, collected: collected};
            }
          },
        }
      }

      if state != OptReadState::Code1 {
        // there was some problem parsing the data for the options, ignoring them
        // TODO: should we ignore all of the EDNS data in this case?
        warn!("incomplete or poorly formatted EDNS options: {:?}", option_rdata);
        options.clear();
      }

      Edns {
        extended_rcode_high: extended_rcode_high,
        version: version,
        dnssec_ok: dnssec_ok,
        max_payload: max_payload,
        options: options,
      }
    } else {
      // this should be a coding error, as opposed to a parsing error.
      panic!("rr_type doesn't match the RData: {:?}", value.get_rdata());
    }
  }
}

#[derive(PartialEq, Eq)]
enum OptReadState {
  Code1, // expect MSB for the code
  Code2{ high: u8 }, // expect LSB for the opt code, store the high byte
  Length1{ code: EdnsCode }, // expect MSB for the length, store the option code
  Length2{ code: EdnsCode, high: u8 },  // expect the LSB for the length, store the LSB and code
  Data { code: EdnsCode, length: usize, collected: usize }, // expect the data for the option
}

#[derive(Hash, Debug, Copy, Clone, PartialEq, Eq)]
pub enum EdnsCode {
  // 0	Reserved		[RFC6891]
  Zero,
  // 1	LLQ	On-hold	[http://files.dns-sd.org/draft-sekar-dns-llq.txt]
  LLQ,
  // 2	UL	On-hold	[http://files.dns-sd.org/draft-sekar-dns-ul.txt]
  UL,
  // 3	NSID	Standard	[RFC5001]
  NSID,
  // 4	Reserved		[draft-cheshire-edns0-owner-option] (EXPIRED)
  // 5	DAU	Standard	[RFC6975]
  DAU,
  // 6	DHU	Standard	[RFC6975]
  DHU,
  // 7	N3U	Standard	[RFC6975]
  N3U,
  // 8	edns-client-subnet	Optional	[draft-vandergaast-edns-client-subnet][Wilmer_van_der_Gaast]
  //    https://tools.ietf.org/html/draft-vandergaast-edns-client-subnet-02
  Subnet,
  // 9	EDNS EXPIRE	Optional	[RFC7314]
  Expire,
  // 10	COOKIE	Standard	[draft-ietf-dnsop-cookies]
  //  https://tools.ietf.org/html/draft-ietf-dnsop-cookies-07
  Cookie,

  // 11	edns-tcp-keepalive	Optional	[draft-ietf-dnsop-edns-tcp-keepalive]
  //  https://tools.ietf.org/html/draft-ietf-dnsop-edns-tcp-keepalive-04
  Keepalive,

  // 12	Padding	Optional	[draft-mayrhofer-edns0-padding]
  //  https://tools.ietf.org/html/draft-mayrhofer-edns0-padding-01
  Padding,

  // 13	CHAIN	Optional	[draft-ietf-dnsop-edns-chain-query]
  Chain,

  // Unknown, used to deal with unknown or unsupported codes
  Unknown(u16)
}

impl From<u16> for EdnsCode {
  fn from(value: u16) -> EdnsCode {
    match value {
      0 => EdnsCode::Zero,
      1 => EdnsCode::LLQ,
      2 => EdnsCode::UL,
      3 => EdnsCode::NSID,
      5 => EdnsCode::DAU,
      6 => EdnsCode::DHU,
      7 => EdnsCode::N3U,
      8 => EdnsCode::Subnet,
      9 => EdnsCode::Expire,
      10 => EdnsCode::Cookie,
      11 => EdnsCode::Keepalive,
      12 => EdnsCode::Padding,
      13 => EdnsCode::Chain,
      _ => EdnsCode::Unknown(value),
    }
  }
}

impl From<EdnsCode> for u16 {
  fn from(value: EdnsCode) -> u16 {
    match value {
      EdnsCode::Zero => 0,
      EdnsCode::LLQ => 1,
      EdnsCode::UL => 2,
      EdnsCode::NSID => 3,
      EdnsCode::DAU => 5,
      EdnsCode::DHU => 6,
      EdnsCode::N3U => 7,
      EdnsCode::Subnet => 8,
      EdnsCode::Expire => 9,
      EdnsCode::Cookie => 10,
      EdnsCode::Keepalive => 11,
      EdnsCode::Padding => 12,
      EdnsCode::Chain => 13,
      EdnsCode::Unknown(value) => value,
    }
  }
}

// http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-13
#[derive(Debug, PartialOrd, PartialEq)]
pub enum EdnsOption {
  /// 0	Reserved		[RFC6891]
  // Zero,
  /// 1	LLQ	On-hold	[http://files.dns-sd.org/draft-sekar-dns-llq.txt]
  // LLQ,
  /// 2	UL	On-hold	[http://files.dns-sd.org/draft-sekar-dns-ul.txt]
  // UL,
  /// 3	NSID	Standard	[RFC5001]
  // NSID,
  /// 4	Reserved		[draft-cheshire-edns0-owner-option] (EXPIRED)
  /// 5	DAU	Standard	[RFC6975]
  DAU(SupportedAlgorithms),
  /// 6	DHU	Standard	[RFC6975]
  DHU(SupportedAlgorithms),
  /// 7	N3U	Standard	[RFC6975]
  N3U(SupportedAlgorithms),
  /// 8	edns-client-subnet	Optional	[draft-vandergaast-edns-client-subnet][Wilmer_van_der_Gaast]
  ///    https://tools.ietf.org/html/draft-vandergaast-edns-client-subnet-02
  // Subnet
  /// 9	EDNS EXPIRE	Optional	[RFC7314]
  // Expire
  /// 10	COOKIE	Standard	[draft-ietf-dnsop-cookies]
  ///  https://tools.ietf.org/html/draft-ietf-dnsop-cookies-07
  // Cookie,

  /// 11	edns-tcp-keepalive	Optional	[draft-ietf-dnsop-edns-tcp-keepalive]
  ///  https://tools.ietf.org/html/draft-ietf-dnsop-edns-tcp-keepalive-04
  // Keepalive,

  /// 12	Padding	Optional	[draft-mayrhofer-edns0-padding]
  ///  https://tools.ietf.org/html/draft-mayrhofer-edns0-padding-01
  // Padding,

  /// 13	CHAIN	Optional	[draft-ietf-dnsop-edns-chain-query]
  // Chain,

  // Unknown, used to deal with unknown or unsupported codes
  Unknown(u16, Vec<u8>)
}

/// only the supported extensions are listed right now.
impl<'a> From<(EdnsCode, &'a[u8])> for EdnsOption {
  fn from(value: (EdnsCode, &'a[u8])) -> EdnsOption {
    match value.0 {
      EdnsCode::DAU => EdnsOption::DAU(value.1.into()),
      EdnsCode::DHU => EdnsOption::DHU(value.1.into()),
      EdnsCode::N3U => EdnsOption::N3U(value.1.into()),
      _ => EdnsOption::Unknown(value.0.into(), value.1.to_vec()),
    }
  }
}

impl From<EdnsOption> for EdnsCode {
  fn from(value: EdnsOption) -> EdnsCode {
    match value {
      EdnsOption::DAU(..) => EdnsCode::DAU,
      EdnsOption::DHU(..) => EdnsCode::DHU,
      EdnsOption::N3U(..)=> EdnsCode::N3U,
      EdnsOption::Unknown(code, _) => EdnsCode::Unknown(code),
    }
  }
}
