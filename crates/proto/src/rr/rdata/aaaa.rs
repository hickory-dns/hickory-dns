// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! IPv6 address record data
//!
//! [RFC 3596, DNS Extensions to Support IPv6, October 2003](https://tools.ietf.org/html/rfc3596)
//!
//! ```text
//! 2.1 AAAA record type
//!
//!   The AAAA resource record type is a record specific to the Internet
//!   class that stores a single IPv6 address.
//!
//!   The IANA assigned value of the type is 28 (decimal).
//!
//! 2.2 AAAA data format
//!
//!   A 128 bit IPv6 address is encoded in the data portion of an AAAA
//!   resource record in network byte order (high-order byte first).
//! ```

use core::{fmt, ops::Deref, str};
use std::net::AddrParseError;

pub use std::net::Ipv6Addr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    error::ProtoResult,
    rr::{RData, RecordData, RecordType},
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};

/// The DNS AAAA record type, an IPv6 address
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct AAAA(pub Ipv6Addr);

impl AAAA {
    /// Construct a new AAAA record with the 128 bits of IPv6 address
    #[allow(clippy::too_many_arguments)]
    pub const fn new(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> Self {
        Self(Ipv6Addr::new(a, b, c, d, e, f, g, h))
    }
}

impl RecordData for AAAA {
    fn try_from_rdata(data: RData) -> Result<Self, crate::rr::RData> {
        match data {
            RData::AAAA(ipv4) => Ok(ipv4),
            _ => Err(data),
        }
    }

    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::AAAA(ipv6) => Some(ipv6),
            _ => None,
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::AAAA
    }

    fn into_rdata(self) -> RData {
        RData::AAAA(self)
    }
}

impl BinEncodable for AAAA {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        let segments = self.segments();

        // TODO: this might be more efficient as a single write of the array
        encoder.emit_u16(segments[0])?;
        encoder.emit_u16(segments[1])?;
        encoder.emit_u16(segments[2])?;
        encoder.emit_u16(segments[3])?;
        encoder.emit_u16(segments[4])?;
        encoder.emit_u16(segments[5])?;
        encoder.emit_u16(segments[6])?;
        encoder.emit_u16(segments[7])?;
        Ok(())
    }
}

impl<'r> BinDecodable<'r> for AAAA {
    fn read(decoder: &mut BinDecoder<'r>) -> ProtoResult<Self> {
        // TODO: would this be more efficient as two u64 reads?
        let a: u16 = decoder.read_u16()?.unverified(/*valid as any u16*/);
        let b: u16 = decoder.read_u16()?.unverified(/*valid as any u16*/);
        let c: u16 = decoder.read_u16()?.unverified(/*valid as any u16*/);
        let d: u16 = decoder.read_u16()?.unverified(/*valid as any u16*/);
        let e: u16 = decoder.read_u16()?.unverified(/*valid as any u16*/);
        let f: u16 = decoder.read_u16()?.unverified(/*valid as any u16*/);
        let g: u16 = decoder.read_u16()?.unverified(/*valid as any u16*/);
        let h: u16 = decoder.read_u16()?.unverified(/*valid as any u16*/);

        Ok(Ipv6Addr::new(a, b, c, d, e, f, g, h).into())
    }
}

/// Read the RData from the given Decoder
#[allow(clippy::many_single_char_names)]
#[deprecated(note = "use the BinDecodable::read method instead")]
pub fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<AAAA> {
    <AAAA as BinDecodable>::read(decoder)
}

/// Write the RData from the given Decoder
#[deprecated(note = "use the BinEncodable::emit method instead")]
pub fn emit(encoder: &mut BinEncoder<'_>, address: &Ipv6Addr) -> ProtoResult<()> {
    BinEncodable::emit(&AAAA::from(*address), encoder)
}

impl From<Ipv6Addr> for AAAA {
    fn from(aaaa: Ipv6Addr) -> Self {
        Self(aaaa)
    }
}

impl From<AAAA> for Ipv6Addr {
    fn from(aaaa: AAAA) -> Self {
        aaaa.0
    }
}

impl Deref for AAAA {
    type Target = Ipv6Addr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for AAAA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl str::FromStr for AAAA {
    type Err = AddrParseError;
    fn from_str(s: &str) -> Result<Self, AddrParseError> {
        Ipv6Addr::from_str(s).map(From::from)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::str::FromStr;

    use super::*;
    use crate::serialize::binary::bin_tests::{test_emit_data_set, test_read_data_set};

    fn get_data() -> Vec<(AAAA, Vec<u8>)> {
        vec![
            (
                AAAA::from_str("::").unwrap(),
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ), // base case
            (
                AAAA::from_str("1::").unwrap(),
                vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            (
                AAAA::from_str("0:1::").unwrap(),
                vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            (
                AAAA::from_str("0:0:1::").unwrap(),
                vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            (
                AAAA::from_str("0:0:0:1::").unwrap(),
                vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            (
                AAAA::from_str("::1:0:0:0").unwrap(),
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
            ),
            (
                AAAA::from_str("::1:0:0").unwrap(),
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
            ),
            (
                AAAA::from_str("::1:0").unwrap(),
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
            ),
            (
                AAAA::from_str("::1").unwrap(),
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            ),
            (
                AAAA::from_str("::127.0.0.1").unwrap(),
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1],
            ),
            (
                AAAA::from_str("FF00::192.168.64.32").unwrap(),
                vec![255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 64, 32],
            ),
        ]
    }

    #[test]
    fn test_read() {
        test_read_data_set(get_data(), |mut d| AAAA::read(&mut d));
    }

    #[test]
    fn test_emit() {
        test_emit_data_set(get_data(), |e, d| d.emit(e));
    }
}
