// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Extended DNS options

use alloc::boxed::Box;
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "__dnssec")]
use crate::dnssec::{Algorithm, SupportedAlgorithms};
use crate::{
    error::*,
    rr::{
        DNSClass, Name, RecordDataDecodable,
        rdata::{
            EdnsOptions,
            opt::{EdnsCode, EdnsOption},
        },
    },
    serialize::binary::{BinDecoder, BinEncodable, BinEncoder, DecodeError},
};

/// Edns implements the higher level concepts for working with extended dns as it is used to create or be
/// created from OPT record data.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Edns {
    /// Max payload size, minimum of 512, (from RR CLASS)
    pub udp_payload_size: u16,
    /// High 8 bits that make up the 12 bit total result code
    pub extended_rcode: u8,
    /// Indicates the implementation level of the setter
    pub version: u8,
    /// Flags for EDNS (currently only DNSSEC OK)
    pub flags: EdnsFlags,
    /// Options for EDNS, these are the variable length portion of the OPT record
    pub options: EdnsOptions,
}

impl Edns {
    pub(crate) fn decode(name: Name, decoder: &mut BinDecoder<'_>) -> Result<Self, DecodeError> {
        if !name.is_root() {
            return Err(DecodeError::EdnsNameNotRoot(Box::new(name)));
        }

        let udp_payload_size = decoder.read_u16()?.unverified();
        let extended_rcode = decoder.read_u8()?.unverified();
        let version = decoder.read_u8()?.unverified();
        let flags = EdnsFlags::from(decoder.read_u16()?.unverified());

        // RDLENGTH        an unsigned 16 bit integer that specifies the length in
        //                octets of the RDATA field.
        let rd_length = decoder.read_u16()?;
        let options = EdnsOptions::read_data(decoder, rd_length)?;
        Ok(Self {
            udp_payload_size,
            extended_rcode,
            version,
            flags,
            options,
        })
    }

    /// Creates a new extended DNS object.
    #[deprecated(since = "0.26.1", note = "use `Edns::default()` instead")]
    pub fn new() -> Self {
        Self::default()
    }

    /// The high order bytes for the response code in the DNS Message
    #[deprecated(
        since = "0.26.1",
        note = "use the `Ends::extended_rcode` field instead"
    )]
    pub fn rcode_high(&self) -> u8 {
        self.extended_rcode
    }

    /// Returns the EDNS version
    #[deprecated(since = "0.26.1", note = "use the `Ends::version` field instead")]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Returns the [`EdnsFlags`] portion of EDNS
    #[deprecated(since = "0.26.1", note = "use the `Ends::flags` field instead")]
    pub fn flags(&self) -> &EdnsFlags {
        &self.flags
    }

    /// Returns a mutable reference to the [`EdnsFlags`]
    #[deprecated(since = "0.26.1", note = "use the `Ends::flags` field instead")]
    pub fn flags_mut(&mut self) -> &mut EdnsFlags {
        &mut self.flags
    }

    /// Maximum supported size of the DNS payload
    #[deprecated(
        since = "0.26.1",
        note = "use the `Ends::udp_payload_size` field instead"
    )]
    pub fn max_payload(&self) -> u16 {
        self.udp_payload_size
    }

    /// Returns the Option associated with the code
    pub fn option(&self, code: EdnsCode) -> Option<&EdnsOption> {
        self.options.get(code)
    }

    /// Returns the options portion of EDNS
    #[deprecated(since = "0.26.1", note = "use the `Ends::options` field instead")]
    pub fn options(&self) -> &EdnsOptions {
        &self.options
    }

    /// Returns a mutable options portion of EDNS
    #[deprecated(since = "0.26.1", note = "use the `Ends::options` field instead")]
    pub fn options_mut(&mut self) -> &mut EdnsOptions {
        &mut self.options
    }

    /// Set the high order bits for the result code.
    #[deprecated(
        since = "0.26.1",
        note = "use the `Ends::extended_rcode` field instead"
    )]
    pub fn set_rcode_high(&mut self, rcode_high: u8) -> &mut Self {
        self.extended_rcode = rcode_high;
        self
    }

    /// Set the EDNS version
    #[deprecated(since = "0.26.1", note = "use the `Ends::version` field instead")]
    pub fn set_version(&mut self, version: u8) -> &mut Self {
        self.version = version;
        self
    }

    /// Creates a new extended DNS object prepared for DNSSEC messages.
    #[cfg(feature = "__dnssec")]
    pub fn enable_dnssec(&mut self) {
        self.flags.dnssec_ok = true;
        self.set_default_algorithms();
    }

    /// Set the default algorithms which are supported by this handle
    #[cfg(feature = "__dnssec")]
    pub fn set_default_algorithms(&mut self) -> &mut Self {
        let mut algorithms = SupportedAlgorithms::new();

        for algorithm in [
            Algorithm::RSASHA256,
            Algorithm::RSASHA512,
            Algorithm::ECDSAP256SHA256,
            Algorithm::ECDSAP384SHA384,
            Algorithm::ED25519,
        ] {
            if algorithm.is_supported() {
                algorithms.set(algorithm);
            }
        }

        let dau = EdnsOption::DAU(algorithms);

        self.options.insert(dau);
        self
    }

    /// Set to true if DNSSEC is supported
    #[deprecated(since = "0.26.1", note = "use the `Ends::flags` field instead")]
    pub fn set_dnssec_ok(&mut self, dnssec_ok: bool) -> &mut Self {
        self.flags.dnssec_ok = dnssec_ok;
        self
    }

    /// Set the maximum payload which can be supported
    /// From RFC 6891: `Values lower than 512 MUST be treated as equal to 512`
    #[deprecated(
        since = "0.26.1",
        note = "use the `Ends::udp_payload_size` field instead"
    )]
    pub fn set_max_payload(&mut self, max_payload: u16) -> &mut Self {
        self.udp_payload_size = max_payload.max(512);
        self
    }
}

impl BinEncodable for Edns {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        DNSClass::for_opt(self.udp_payload_size).emit(encoder)?;

        // rebuild the TTL field
        let mut ttl = u32::from(self.extended_rcode) << 24;
        ttl |= u32::from(self.version) << 16;
        ttl |= u32::from(u16::from(self.flags));

        ttl.emit(encoder)?;

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
        let max_payload = self.udp_payload_size;

        write!(
            f,
            "version: {version} dnssec_ok: {dnssec_ok} z_flags: {z_flags} max_payload: {max_payload} opts: {opts_len}",
            opts_len = self.options.as_ref().len()
        )
    }
}

impl Default for Edns {
    fn default() -> Self {
        Self {
            udp_payload_size: DEFAULT_MAX_PAYLOAD_LEN,
            extended_rcode: 0,
            version: 0,
            flags: EdnsFlags::default(),
            options: EdnsOptions::default(),
        }
    }
}

/// EDNS flags
///
/// <https://www.rfc-editor.org/rfc/rfc6891#section-6.1.4>
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct EdnsFlags {
    /// DNSSEC OK bit as defined by RFC 3225
    pub dnssec_ok: bool,
    /// Remaining bits in the flags field
    ///
    /// Note that the most significant bit in this value is represented by the `dnssec_ok` field.
    /// As such, it will be zero when decoding and will not be encoded.
    ///
    /// Unless you have a specific need to set this value, we recommend leaving this as zero.
    pub z: u16,
}

impl From<u16> for EdnsFlags {
    fn from(flags: u16) -> Self {
        Self {
            dnssec_ok: flags & 0x8000 == 0x8000,
            z: flags & 0x7FFF,
        }
    }
}

impl From<EdnsFlags> for u16 {
    fn from(flags: EdnsFlags) -> Self {
        match flags.dnssec_ok {
            true => 0x8000 | flags.z,
            false => 0x7FFF & flags.z,
        }
    }
}

/// Default maximum payload length for EDNS messages.
///
/// Per 2020 DNS flag day, default to 1232 bytes.
///
/// <https://www.dnsflagday.net/2020/>
pub const DEFAULT_MAX_PAYLOAD_LEN: u16 = 1232;

#[cfg(all(test, feature = "__dnssec"))]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let mut edns = Edns::default();
        edns.flags.dnssec_ok = true;
        edns.flags.z = 1;
        edns.udp_payload_size = 0x8008;
        edns.version = 0x40;
        edns.extended_rcode = 0x01;
        edns.options
            .insert(EdnsOption::DAU(SupportedAlgorithms::all()));

        let bytes = edns.to_bytes().expect("failed to encode");
        let edns_decode =
            Edns::decode(Name::root(), &mut BinDecoder::new(&bytes)).expect("failed to decode");

        assert_eq!(edns.flags.dnssec_ok, edns_decode.flags.dnssec_ok);
        assert_eq!(edns.flags.z, edns_decode.flags.z);
        assert_eq!(edns.udp_payload_size, edns_decode.udp_payload_size);
        assert_eq!(edns.version, edns_decode.version);
        assert_eq!(edns.extended_rcode, edns_decode.extended_rcode);
        assert_eq!(edns.options, edns_decode.options);

        // re-insert and remove using mut
        edns.options
            .insert(EdnsOption::DAU(SupportedAlgorithms::all()));
        edns.options.remove(EdnsCode::DAU);
        assert!(edns.option(EdnsCode::DAU).is_none());
    }
}
