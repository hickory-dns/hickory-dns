// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! CSYNC record for synchronizing data from a child zone to the parent

use std::fmt;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::rr::type_bit_map::{decode_type_bit_maps, encode_type_bit_maps};
use crate::rr::RecordType;
use crate::serialize::binary::*;

/// [RFC 7477, Child-to-Parent Synchronization in DNS, March 2015][rfc7477]
///
/// ```text
/// 2.1.1.  The CSYNC Resource Record Wire Format
///
/// The CSYNC RDATA consists of the following fields:
///
///                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                          SOA Serial                           |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |       Flags                   |            Type Bit Map       /
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  /                     Type Bit Map (continued)                  /
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// [rfc7477]: https://tools.ietf.org/html/rfc7477
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct CSYNC {
    soa_serial: u32,
    immediate: bool,
    soa_minimum: bool,
    type_bit_maps: Vec<RecordType>,
}

impl CSYNC {
    /// Creates a new CSYNC record data.
    ///
    /// # Arguments
    ///
    /// * `soa_serial` - A serial number for the zone
    /// * `immediate` - A flag signalling if the change should happen immediately
    /// * `soa_minimum` - A flag to used to signal if the soa_serial should be validated
    /// * `type_bit_maps` - a bit map of the types to synchronize
    ///
    /// # Return value
    ///
    /// The new CSYNC record data.
    pub fn new(
        soa_serial: u32,
        immediate: bool,
        soa_minimum: bool,
        type_bit_maps: Vec<RecordType>,
    ) -> Self {
        Self {
            soa_serial,
            immediate,
            soa_minimum,
            type_bit_maps,
        }
    }

    /// [RFC 7477](https://tools.ietf.org/html/rfc7477#section-2.1.1.2.1), Child-to-Parent Synchronization in DNS, March 2015
    ///
    /// ```text
    /// 2.1.1.2.1.  The Type Bit Map Field
    ///
    ///    The Type Bit Map field indicates the record types to be processed by
    ///    the parental agent, according to the procedures in Section 3.  The
    ///    Type Bit Map field is encoded in the same way as the Type Bit Map
    ///    field of the NSEC record, described in [RFC4034], Section 4.1.2.  If
    ///    a bit has been set that a parental agent implementation does not
    ///    understand, the parental agent MUST NOT act upon the record.
    ///    Specifically, a parental agent must not simply copy the data, and it
    ///    must understand the semantics associated with a bit in the Type Bit
    ///    Map field that has been set to 1.
    /// ```
    pub fn type_bit_maps(&self) -> &[RecordType] {
        &self.type_bit_maps
    }

    /// [RFC 7477](https://tools.ietf.org/html/rfc7477#section-2.1.1.2), Child-to-Parent Synchronization in DNS, March 2015
    ///
    /// ```text
    /// 2.1.1.2.  The Flags Field
    ///
    ///    The Flags field contains 16 bits of boolean flags that define
    ///    operations that affect the processing of the CSYNC record.  The flags
    ///    defined in this document are as follows:
    ///
    ///       0x00 0x01: "immediate"
    ///
    ///       0x00 0x02: "soaminimum"
    ///
    ///    The definitions for how the flags are to be used can be found in
    ///    Section 3.
    ///
    ///    The remaining flags are reserved for use by future specifications.
    ///    Undefined flags MUST be set to 0 by CSYNC publishers.  Parental
    ///    agents MUST NOT process a CSYNC record if it contains a 1 value for a
    ///    flag that is unknown to or unsupported by the parental agent.
    /// ```
    pub fn flags(&self) -> u16 {
        let mut flags: u16 = 0;
        if self.immediate {
            flags |= 0b0000_0001
        };
        if self.soa_minimum {
            flags |= 0b0000_0010
        };
        flags
    }
}

/// Read the RData from the given Decoder
pub fn read(decoder: &mut BinDecoder<'_>, rdata_length: Restrict<u16>) -> ProtoResult<CSYNC> {
    let start_idx = decoder.index();

    let soa_serial = decoder.read_u32()?.unverified();

    let flags: u16 = decoder
        .read_u16()?
        .verify_unwrap(|flags| flags & 0b1111_1100 == 0)
        .map_err(|flags| ProtoError::from(ProtoErrorKind::UnrecognizedCsyncFlags(flags)))?;

    let immediate: bool = flags & 0b0000_0001 == 0b0000_0001;
    let soa_minimum: bool = flags & 0b0000_0010 == 0b0000_0010;

    let bit_map_len = rdata_length
        .map(|u| u as usize)
        .checked_sub(decoder.index() - start_idx)
        .map_err(|_| ProtoError::from("invalid rdata length in CSYNC"))?;
    let record_types = decode_type_bit_maps(decoder, bit_map_len)?;

    Ok(CSYNC::new(soa_serial, immediate, soa_minimum, record_types))
}

/// Write the RData from the given Decoder
pub fn emit(encoder: &mut BinEncoder<'_>, csync: &CSYNC) -> ProtoResult<()> {
    encoder.emit_u32(csync.soa_serial)?;
    encoder.emit_u16(csync.flags())?;
    encode_type_bit_maps(encoder, csync.type_bit_maps())?;

    Ok(())
}

impl fmt::Display for CSYNC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{soa_serial} {flags}",
            soa_serial = &self.soa_serial,
            flags = &self.flags(),
        )?;

        for ty in &self.type_bit_maps {
            write!(f, " {}", ty)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;

    #[test]
    fn test() {
        let types = vec![RecordType::A, RecordType::NS, RecordType::AAAA];

        let rdata = CSYNC::new(123, true, true, types);

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(emit(&mut encoder, &rdata).is_ok());
        let bytes = encoder.into_bytes();

        println!("bytes: {:?}", bytes);

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let restrict = Restrict::new(bytes.len() as u16);
        let read_rdata = read(&mut decoder, restrict).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }
}
