// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! CSYNC record for synchronizing data from a child zone to the parent

use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    error::*,
    rr::{RData, RecordData, RecordDataDecodable, RecordType, RecordTypeSet},
    serialize::binary::*,
};

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
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct CSYNC {
    soa_serial: u32,
    immediate: bool,
    soa_minimum: bool,
    reserved_flags: u16,
    type_bit_maps: RecordTypeSet,
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
        type_bit_maps: impl IntoIterator<Item = RecordType>,
    ) -> Self {
        Self {
            soa_serial,
            immediate,
            soa_minimum,
            reserved_flags: 0,
            type_bit_maps: RecordTypeSet::new(type_bit_maps),
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
    pub fn type_bit_maps(&self) -> impl Iterator<Item = RecordType> + '_ {
        self.type_bit_maps.iter()
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
        let mut flags = self.reserved_flags & 0b1111_1111_1111_1100;
        if self.immediate {
            flags |= 0b0000_0001
        };
        if self.soa_minimum {
            flags |= 0b0000_0010
        };
        flags
    }
}

impl BinEncodable for CSYNC {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.emit_u32(self.soa_serial)?;
        encoder.emit_u16(self.flags())?;
        self.type_bit_maps.emit(encoder)?;

        Ok(())
    }
}

impl<'r> RecordDataDecodable<'r> for CSYNC {
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> ProtoResult<Self> {
        let start_idx = decoder.index();

        let soa_serial = decoder.read_u32()?.unverified();

        let flags: u16 = decoder
            .read_u16()?
            .verify_unwrap(|flags| flags & 0b1111_1100 == 0)
            .map_err(|flags| ProtoError::from(ProtoErrorKind::UnrecognizedCsyncFlags(flags)))?;

        let immediate: bool = flags & 0b0000_0001 == 0b0000_0001;
        let soa_minimum: bool = flags & 0b0000_0010 == 0b0000_0010;
        let reserved_flags = flags & 0b1111_1111_1111_1100;

        let offset = u16::try_from(decoder.index() - start_idx)
            .map_err(|_| ProtoError::from("decoding offset too large in CSYNC"))?;
        let bit_map_len = length
            .checked_sub(offset)
            .map_err(|_| ProtoError::from("invalid rdata length in CSYNC"))?;
        let type_bit_maps = RecordTypeSet::read_data(decoder, bit_map_len)?;

        Ok(Self {
            soa_serial,
            immediate,
            soa_minimum,
            reserved_flags,
            type_bit_maps,
        })
    }
}

impl RecordData for CSYNC {
    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::CSYNC(csync) => Some(csync),
            _ => None,
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::CSYNC
    }

    fn into_rdata(self) -> RData {
        RData::CSYNC(self)
    }
}

impl fmt::Display for CSYNC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{soa_serial} {flags}",
            soa_serial = &self.soa_serial,
            flags = &self.flags(),
        )?;

        for ty in self.type_bit_maps.iter() {
            write!(f, " {ty}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    #[cfg(feature = "std")]
    use std::println;

    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn test() {
        let types = [RecordType::A, RecordType::NS, RecordType::AAAA];

        let rdata = CSYNC::new(123, true, true, types);

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(rdata.emit(&mut encoder).is_ok());
        let bytes = encoder.into_bytes();

        #[cfg(feature = "std")]
        println!("bytes: {bytes:?}");

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let restrict = Restrict::new(bytes.len() as u16);
        let read_rdata = CSYNC::read_data(&mut decoder, restrict).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }
}
