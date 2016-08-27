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

//! Extended DNS options

use ::rr::{DNSClass, Name, Record, RecordType, RData};
use ::rr::rdata::OPT;
use ::rr::rdata::opt::{ EdnsCode, EdnsOption };

/// Edns implements the higher level concepts for working with Edns as it is used to create or be
/// created from OPT record data.
#[derive(Debug, PartialEq, Clone)]
pub struct Edns {
  // high 8 bits that make up the 12 bit total field when included with the 4bit rcode from the
  //  header (from TTL)
  rcode_high: u8,
  // Indicates the implementation level of the setter. (from TTL)
  version: u8,
  // Is DNSSec supported (from TTL)
  dnssec_ok: bool,
  // max payload size, minimum of 512, (from RR CLASS)
  max_payload: u16,

  options: OPT,
}

impl Edns {
  pub fn new() -> Self {
    Edns{ rcode_high: 0, version: 0, dnssec_ok: false, max_payload: 512, options: OPT::default() }
  }

  pub fn get_rcode_high(&self) -> u8 { self.rcode_high }
  pub fn get_version(&self) -> u8 { self.version }
  pub fn is_dnssec_ok(&self) -> bool { self.dnssec_ok }
  pub fn get_max_payload(&self) -> u16 { self.max_payload }
  pub fn get_option(&self, code: &EdnsCode) -> Option<&EdnsOption> { self.options.get(code) }
  pub fn get_options(&self) -> &OPT { &self.options }

  pub fn set_rcode_high(&mut self, rcode_high: u8) { self.rcode_high = rcode_high }
  pub fn set_version(&mut self, version: u8) { self.version = version }
  pub fn set_dnssec_ok(&mut self, dnssec_ok: bool) { self.dnssec_ok = dnssec_ok }
  pub fn set_max_payload(&mut self, max_payload: u16) { self.max_payload = max_payload }
  pub fn set_option(&mut self, option: EdnsOption) { self.options.insert(option); }
}

impl<'a> From<&'a Record> for Edns {
  fn from(value: &'a Record) -> Self {
    assert!(value.get_rr_type() == RecordType::OPT);

    let rcode_high: u8 = ((value.get_ttl() & 0xFF000000u32) >> 24) as u8;
    let version: u8 = ((value.get_ttl() & 0x00FF0000u32) >> 16) as u8;
    let dnssec_ok: bool = value.get_ttl() & 0x00008000 == 0x00008000;
    let max_payload: u16 = if u16::from(value.get_dns_class()) < 512 { 512 } else { value.get_dns_class().into() };

    let options: OPT = match value.get_rdata() {
      &RData::NULL( .. ) => {
        // NULL, there was no data in the OPT
        OPT::default()
      },
      &RData::OPT(ref option_data) => {
        option_data.clone() // TODO: Edns should just refer to this, have the same lifetime as the Record
      },
      _ => {
        // this should be a coding error, as opposed to a parsing error.
        panic!("rr_type doesn't match the RData: {:?}", value.get_rdata()); // valid panic, never should happen
      },
    };

    Edns {
      rcode_high: rcode_high,
      version: version,
      dnssec_ok: dnssec_ok,
      max_payload: max_payload,
      options: options,
    }
  }
}

impl<'a> From<&'a Edns> for Record {
  /// This returns a Resource Record that is formatted for Edns(0).
  /// Note: the rcode_high value is only part of the rcode, the rest is part of the base
  fn from(value: &'a Edns) -> Record {
    let mut record: Record = Record::new();

    record.name(Name::root());
    record.rr_type(RecordType::OPT);
    record.dns_class(DNSClass::OPT(value.get_max_payload()));

    // rebuild the TTL field
    let mut ttl: u32 = (value.get_rcode_high() as u32) << 24;
    ttl |= (value.get_version() as u32) << 16;

    if value.is_dnssec_ok() {
      ttl |= 0x00008000;
    }
    record.ttl(ttl);

    // now for each option, write out the option array
    //  also, since this is a hash, there is no guarantee that ordering will be preserved from
    //  the original binary format.
    // maybe switch to: https://crates.io/crates/linked-hash-map/
    record.rdata(RData::OPT(value.get_options().clone()));

    record
  }
}

#[test]
fn test_encode_decode() {
  use ::rr::dnssec::SupportedAlgorithms;

  let mut edns: Edns = Edns::new();

  edns.set_dnssec_ok(true);
  edns.set_max_payload(0x8008);
  edns.set_version(0x40);
  edns.set_rcode_high(0x01);
  edns.set_option(EdnsOption::DAU(SupportedAlgorithms::all()));

  let record: Record = (&edns).into();
  let edns_decode: Edns = (&record).into();

  assert_eq!(edns.is_dnssec_ok(), edns_decode.is_dnssec_ok());
  assert_eq!(edns.get_max_payload(), edns_decode.get_max_payload());
  assert_eq!(edns.get_version(), edns_decode.get_version());
  assert_eq!(edns.get_rcode_high(), edns_decode.get_rcode_high());
  assert_eq!(edns.get_options(), edns_decode.get_options());
}
