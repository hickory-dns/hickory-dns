// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! null record type, generally not used except as an internal tool for representing null data
use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    error::ProtoResult,
    rr::{RData, RecordData, RecordDataDecodable, RecordType},
    serialize::binary::{BinDecoder, BinEncodable, BinEncoder, Restrict},
};

/// [RFC 1035, DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987](https://tools.ietf.org/html/rfc1035)
///
/// ```text
/// 3.3.10. NULL RDATA format (EXPERIMENTAL)
///
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     /                  <anything>                   /
///     /                                               /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
/// Anything at all may be in the RDATA field so long as it is 65535 octets
/// or less.
///
/// NULL records cause no additional section processing.  NULL RRs are not
/// allowed in Zone Files.  NULLs are used as placeholders in some
/// experimental extensions of the DNS.
/// ```
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Default, Debug, PartialEq, Eq, Hash, Clone)]
pub struct NULL {
    anything: Vec<u8>,
}

impl NULL {
    /// Construct a new NULL RData
    pub const fn new() -> Self {
        Self {
            anything: Vec::new(),
        }
    }

    /// Constructs a new NULL RData with the associated data
    pub fn with(anything: Vec<u8>) -> Self {
        // FIXME: we don't want empty data for NULL's, should be Option in the Record
        debug_assert!(!anything.is_empty());

        Self { anything }
    }

    /// Returns the buffer stored in the NULL
    pub fn anything(&self) -> &[u8] {
        &self.anything
    }
}

impl BinEncodable for NULL {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        for b in self.anything() {
            encoder.emit(*b)?;
        }

        Ok(())
    }
}

impl<'r> RecordDataDecodable<'r> for NULL {
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> ProtoResult<Self> {
        let rdata_length = length.map(|u| u as usize).unverified(/*any u16 is valid*/);
        if rdata_length > 0 {
            let anything = decoder.read_vec(rdata_length)?.unverified(/*any byte array is good*/);
            Ok(Self::with(anything))
        } else {
            Ok(Self::new())
        }
    }
}

impl RecordData for NULL {
    fn try_from_rdata(data: RData) -> Result<Self, RData> {
        match data {
            RData::NULL(csync) => Ok(csync),
            _ => Err(data),
        }
    }

    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::NULL(csync) => Some(csync),
            _ => None,
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::NULL
    }

    fn into_rdata(self) -> RData {
        RData::NULL(self)
    }
}

impl fmt::Display for NULL {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&data_encoding::BASE64.encode(&self.anything))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use std::println;

    use super::*;

    #[test]
    fn test() {
        let rdata = NULL::with(vec![0, 1, 2, 3, 4, 5, 6, 7]);

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(rdata.emit(&mut encoder).is_ok());
        let bytes = encoder.into_bytes();

        println!("bytes: {bytes:?}");

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let restrict = Restrict::new(bytes.len() as u16);
        let read_rdata = NULL::read_data(&mut decoder, restrict).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }
}
