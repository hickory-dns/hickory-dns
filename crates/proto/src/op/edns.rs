// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Extended DNS options

use std::fmt;

#[cfg(feature = "dnssec")]
use crate::dnssec::{Algorithm, SupportedAlgorithms};
use crate::{
    error::*,
    rr::{
        rdata::{
            opt::{EdnsCode, EdnsOption},
            OPT,
        },
        DNSClass, Name, RData, Record, RecordType,
    },
    serialize::binary::{BinEncodable, BinEncoder},
};

/// Edns implements the higher level concepts for working with extended dns as it is used to create or be
/// created from OPT record data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Edns {
    // high 8 bits that make up the 12 bit total field when included with the 4bit rcode from the
    //  header (from TTL)
    rcode_high: u8,
    // Indicates the implementation level of the setter. (from TTL)
    version: u8,
    flags: EdnsFlags,
    // max payload size, minimum of 512, (from RR CLASS)
    max_payload: u16,

    options: OPT,
}

impl Default for Edns {
    fn default() -> Self {
        Self {
            rcode_high: 0,
            version: 0,
            flags: EdnsFlags::default(),
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

    /// Returns the [`EdnsFlags`] portion of EDNS
    pub fn flags(&self) -> &EdnsFlags {
        &self.flags
    }

    /// Returns a mutable reference to the [`EdnsFlags`]
    pub fn flags_mut(&mut self) -> &mut EdnsFlags {
        &mut self.flags
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

    /// Creates a new extended DNS object prepared for DNSSEC messages.
    #[cfg(feature = "dnssec")]
    pub fn enable_dnssec(&mut self) {
        self.set_dnssec_ok(true);
        self.set_default_algorithms();
    }

    /// Set the default algorithms which are supported by this handle
    ///
    /// Set both Algorithms Understood (DAU) and Hash Understood (DHU) to the same algorithms.
    #[cfg(feature = "dnssec")]
    pub fn set_default_algorithms(&mut self) -> &mut Self {
        let mut algorithms = SupportedAlgorithms::new();

        #[cfg(feature = "dnssec-ring")]
        algorithms.set(Algorithm::ED25519);
        algorithms.set(Algorithm::ECDSAP256SHA256);
        algorithms.set(Algorithm::ECDSAP384SHA384);
        algorithms.set(Algorithm::RSASHA256);

        let dau = EdnsOption::DAU(algorithms);
        let dhu = EdnsOption::DHU(algorithms);

        self.options_mut().insert(dau);
        self.options_mut().insert(dhu);
        self
    }

    /// Set to true if DNSSEC is supported
    pub fn set_dnssec_ok(&mut self, dnssec_ok: bool) -> &mut Self {
        self.flags.dnssec_ok = dnssec_ok;
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
        assert!(value.record_type() == RecordType::OPT);

        let rcode_high = ((value.ttl() & 0xFF00_0000u32) >> 24) as u8;
        let version = ((value.ttl() & 0x00FF_0000u32) >> 16) as u8;
        let flags = EdnsFlags::from((value.ttl() & 0x0000_FFFFu32) as u16);
        let max_payload = u16::from(value.dns_class());

        let options = match value.data() {
            RData::Update0(..) | RData::NULL(..) => {
                // NULL, there was no data in the OPT
                OPT::default()
            }
            RData::OPT(option_data) => {
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
            flags,
            max_payload,
            options,
        }
    }
}

impl<'a> From<&'a Edns> for Record {
    /// This returns a Resource Record that is formatted for Edns(0).
    /// Note: the rcode_high value is only part of the rcode, the rest is part of the base
    fn from(value: &'a Edns) -> Self {
        // rebuild the TTL field
        let mut ttl: u32 = u32::from(value.rcode_high()) << 24;
        ttl |= u32::from(value.version()) << 16;
        ttl |= u32::from(u16::from(value.flags));

        // now for each option, write out the option array
        //  also, since this is a hash, there is no guarantee that ordering will be preserved from
        //  the original binary format.
        // maybe switch to: https://crates.io/crates/linked-hash-map/
        let mut record = Self::from_rdata(Name::root(), ttl, RData::OPT(value.options().clone()));

        record.set_dns_class(DNSClass::for_opt(value.max_payload()));

        record
    }
}

impl BinEncodable for Edns {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.emit(0)?; // Name::root
        RecordType::OPT.emit(encoder)?; //self.rr_type.emit(encoder)?;
        DNSClass::for_opt(self.max_payload()).emit(encoder)?; // self.dns_class.emit(encoder)?;

        // rebuild the TTL field
        let mut ttl = u32::from(self.rcode_high()) << 24;
        ttl |= u32::from(self.version()) << 16;
        ttl |= u32::from(u16::from(self.flags));

        encoder.emit_u32(ttl)?;

        // write the opts as rdata...
        let place = encoder.place::<u16>()?;
        self.options.emit(encoder)?;
        let len = encoder.len_since_place(&place);
        assert!(len <= u16::MAX as usize);

        place.replace(encoder, len as u16)?;
        Ok(())
    }
}

impl fmt::Display for Edns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let version = self.version;
        let dnssec_ok = self.flags.dnssec_ok;
        let z_flags = self.flags.z;
        let max_payload = self.max_payload;

        write!(
            f,
            "version: {version} dnssec_ok: {dnssec_ok} z_flags: {z_flags} max_payload: {max_payload} opts: {opts_len}",
            opts_len = self.options().as_ref().len()
        )
    }
}

/// EDNS flags
///
/// <https://www.rfc-editor.org/rfc/rfc6891#section-6.1.4>
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EdnsFlags {
    /// DNSSEC OK bit as defined by RFC 3225
    pub dnssec_ok: bool,
    /// Set to zero by senders and ignored by receivers
    pub z: bool,
}

impl From<u16> for EdnsFlags {
    fn from(flags: u16) -> Self {
        Self {
            dnssec_ok: flags & 0x8000 == 0x8000,
            z: flags & 0x7FFF != 0,
        }
    }
}

impl From<EdnsFlags> for u16 {
    fn from(flags: EdnsFlags) -> Self {
        let mut result = 0;
        if flags.dnssec_ok {
            result |= 0x8000;
        }
        if flags.z {
            result |= 0x7FFF;
        }
        result
    }
}

#[cfg(all(test, feature = "dnssec"))]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let mut edns = Edns::new();

        let flags = edns.flags_mut();
        flags.dnssec_ok = true;
        flags.z = true;
        edns.set_max_payload(0x8008);
        edns.set_version(0x40);
        edns.set_rcode_high(0x01);
        edns.options_mut()
            .insert(EdnsOption::DAU(SupportedAlgorithms::all()));

        let record = Record::from(&edns);
        let edns_decode = Edns::from(&record);

        assert_eq!(edns.flags().dnssec_ok, edns_decode.flags().dnssec_ok);
        assert_eq!(edns.flags().z, edns_decode.flags().z);
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
}
