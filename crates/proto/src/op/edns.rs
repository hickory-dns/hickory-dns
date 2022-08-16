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

use std::fmt;

use crate::error::*;
use crate::rr::rdata::opt::{self, EdnsCode, EdnsOption};
use crate::rr::rdata::OPT;
use crate::rr::{DNSClass, Name, RData, Record, RecordType};

use crate::serialize::binary::{BinEncodable, BinEncoder};

/// Edns implements the higher level concepts for working with extended dns as it is used to create or be
/// created from OPT record data.
#[derive(Debug, PartialEq, Eq, Clone)]
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

impl Default for Edns {
    fn default() -> Self {
        Self {
            rcode_high: 0,
            version: 0,
            dnssec_ok: false,
            max_payload: 512,
            options: OPT::default(),
        }
    }
}

impl Edns {
    /// Creates a new extended DNS object.
    pub fn new() -> Self {
        Self::default()
    }

    /// The high order bytes for the response code in the DNS Message
    pub fn rcode_high(&self) -> u8 {
        self.rcode_high
    }

    /// Returns the EDNS version
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Specifies that DNSSec is supported for this Client or Server
    pub fn dnssec_ok(&self) -> bool {
        self.dnssec_ok
    }

    /// Maximum supported size of the DNS payload
    pub fn max_payload(&self) -> u16 {
        self.max_payload
    }

    /// Returns the Option associated with the code
    pub fn option(&self, code: EdnsCode) -> Option<&EdnsOption> {
        self.options.get(code)
    }

    /// Returns the options portion of EDNS
    pub fn options(&self) -> &OPT {
        &self.options
    }

    /// Returns a mutable options portion of EDNS
    pub fn options_mut(&mut self) -> &mut OPT {
        &mut self.options
    }

    /// Set the high order bits for the result code.
    pub fn set_rcode_high(&mut self, rcode_high: u8) -> &mut Self {
        self.rcode_high = rcode_high;
        self
    }

    /// Set the EDNS version
    pub fn set_version(&mut self, version: u8) -> &mut Self {
        self.version = version;
        self
    }

    /// Set to true if DNSSec is supported
    pub fn set_dnssec_ok(&mut self, dnssec_ok: bool) -> &mut Self {
        self.dnssec_ok = dnssec_ok;
        self
    }

    /// Set the maximum payload which can be supported
    /// From RFC 6891: `Values lower than 512 MUST be treated as equal to 512`
    pub fn set_max_payload(&mut self, max_payload: u16) -> &mut Self {
        self.max_payload = max_payload.max(512);
        self
    }

    /// Set the specified EDNS option
    #[deprecated(note = "Please use options_mut().insert() to modify")]
    pub fn set_option(&mut self, option: EdnsOption) {
        self.options.insert(option);
    }
}

// FIXME: this should be a TryFrom
impl<'a> From<&'a Record> for Edns {
    fn from(value: &'a Record) -> Self {
        assert!(value.rr_type() == RecordType::OPT);

        let rcode_high: u8 = ((value.ttl() & 0xFF00_0000u32) >> 24) as u8;
        let version: u8 = ((value.ttl() & 0x00FF_0000u32) >> 16) as u8;
        let dnssec_ok: bool = value.ttl() & 0x0000_8000 == 0x0000_8000;
        let max_payload: u16 = u16::from(value.dns_class());

        let options: OPT = match value.data() {
            Some(RData::NULL(..)) | None => {
                // NULL, there was no data in the OPT
                OPT::default()
            }
            Some(RData::OPT(ref option_data)) => {
                option_data.clone() // TODO: Edns should just refer to this, have the same lifetime as the Record
            }
            _ => {
                // this should be a coding error, as opposed to a parsing error.
                panic!("rr_type doesn't match the RData: {:?}", value.data()) // valid panic, never should happen
            }
        };

        Self {
            rcode_high,
            version,
            dnssec_ok,
            max_payload,
            options,
        }
    }
}

impl<'a> From<&'a Edns> for Record {
    /// This returns a Resource Record that is formatted for Edns(0).
    /// Note: the rcode_high value is only part of the rcode, the rest is part of the base
    fn from(value: &'a Edns) -> Self {
        let mut record = Self::new();

        record.set_name(Name::root());
        record.set_rr_type(RecordType::OPT);
        record.set_dns_class(DNSClass::for_opt(value.max_payload()));

        // rebuild the TTL field
        let mut ttl: u32 = u32::from(value.rcode_high()) << 24;
        ttl |= u32::from(value.version()) << 16;

        if value.dnssec_ok() {
            ttl |= 0x0000_8000;
        }
        record.set_ttl(ttl);

        // now for each option, write out the option array
        //  also, since this is a hash, there is no guarantee that ordering will be preserved from
        //  the original binary format.
        // maybe switch to: https://crates.io/crates/linked-hash-map/
        record.set_data(Some(RData::OPT(value.options().clone())));

        record
    }
}

impl BinEncodable for Edns {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.emit(0)?; // Name::root
        RecordType::OPT.emit(encoder)?; //self.rr_type.emit(encoder)?;
        DNSClass::for_opt(self.max_payload()).emit(encoder)?; // self.dns_class.emit(encoder)?;

        // rebuild the TTL field
        let mut ttl: u32 = u32::from(self.rcode_high()) << 24;
        ttl |= u32::from(self.version()) << 16;

        if self.dnssec_ok() {
            ttl |= 0x0000_8000;
        }

        encoder.emit_u32(ttl)?;

        // write the opts as rdata...
        let place = encoder.place::<u16>()?;
        opt::emit(encoder, &self.options)?;
        let len = encoder.len_since_place(&place);
        assert!(len <= u16::max_value() as usize);

        place.replace(encoder, len as u16)?;
        Ok(())
    }
}

impl fmt::Display for Edns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let version = self.version;
        let dnssec_ok = self.dnssec_ok;
        let max_payload = self.max_payload;

        write!(
            f,
            "version: {version} dnssec_ok: {dnssec_ok} max_payload: {max_payload} opts: {opts_len}",
            version = version,
            dnssec_ok = dnssec_ok,
            max_payload = max_payload,
            opts_len = self.options().as_ref().len()
        )
    }
}

#[cfg(feature = "dnssec")]
#[test]
fn test_encode_decode() {
    use crate::rr::dnssec::SupportedAlgorithms;

    let mut edns: Edns = Edns::new();

    edns.set_dnssec_ok(true);
    edns.set_max_payload(0x8008);
    edns.set_version(0x40);
    edns.set_rcode_high(0x01);
    edns.options_mut()
        .insert(EdnsOption::DAU(SupportedAlgorithms::all()));

    let record: Record = (&edns).into();
    let edns_decode: Edns = (&record).into();

    assert_eq!(edns.dnssec_ok(), edns_decode.dnssec_ok());
    assert_eq!(edns.max_payload(), edns_decode.max_payload());
    assert_eq!(edns.version(), edns_decode.version());
    assert_eq!(edns.rcode_high(), edns_decode.rcode_high());
    assert_eq!(edns.options(), edns_decode.options());

    // re-insert and remove using mut
    edns.options_mut()
        .insert(EdnsOption::DAU(SupportedAlgorithms::all()));
    edns.options_mut().remove(EdnsCode::DAU);
    assert!(edns.option(EdnsCode::DAU).is_none());
}
