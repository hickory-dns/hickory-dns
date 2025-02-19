// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! IPv4 address record data
//!
//! [RFC 1035, DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987](https://tools.ietf.org/html/rfc1035)
//!
//! ```text
//! 3.4. Internet specific RRs
//!
//! 3.4.1. A RDATA format
//!
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                    ADDRESS                    |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!
//! where:
//!
//! ADDRESS         A 32 bit Internet address.
//!
//! Hosts that have multiple Internet addresses will have multiple A
//! records.
//!
//! A records cause no additional section processing.  The RDATA section of
//! an A line in a Zone File is an Internet address expressed as four
//! decimal numbers separated by dots without any embedded spaces (e.g.,
//! "10.2.0.52" or "192.0.5.6").
//! ```

use core::{fmt, ops::Deref, str};
use std::net::AddrParseError;
pub use std::net::Ipv4Addr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    error::*,
    rr::{RData, RecordData, RecordType},
    serialize::binary::*,
};

/// The DNS A record type, an IPv4 address
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct A(pub Ipv4Addr);

impl A {
    /// Construct a new AAAA record with the 32 bits of IPv4 address
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self(Ipv4Addr::new(a, b, c, d))
    }
}

impl RecordData for A {
    fn try_from_rdata(data: RData) -> Result<Self, crate::rr::RData> {
        match data {
            RData::A(ipv4) => Ok(ipv4),
            _ => Err(data),
        }
    }

    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::A(ipv4) => Some(ipv4),
            _ => None,
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::A
    }

    fn into_rdata(self) -> RData {
        RData::A(self)
    }
}

impl BinEncodable for A {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        let segments = self.octets();

        encoder.emit(segments[0])?;
        encoder.emit(segments[1])?;
        encoder.emit(segments[2])?;
        encoder.emit(segments[3])?;
        Ok(())
    }
}

impl<'r> BinDecodable<'r> for A {
    fn read(decoder: &mut BinDecoder<'r>) -> ProtoResult<Self> {
        // TODO: would this be more efficient as a single u32 read?
        Ok(Ipv4Addr::new(
            decoder.pop()?.unverified(/*valid as any u8*/),
            decoder.pop()?.unverified(/*valid as any u8*/),
            decoder.pop()?.unverified(/*valid as any u8*/),
            decoder.pop()?.unverified(/*valid as any u8*/),
        )
        .into())
    }
}

/// Read the RData from the given Decoder
#[deprecated(note = "use the BinDecodable::read method instead")]
pub fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<A> {
    <A as BinDecodable>::read(decoder)
}

/// Write the RData from the given Decoder
#[deprecated(note = "use the BinEncodable::emit method instead")]
pub fn emit(encoder: &mut BinEncoder<'_>, address: Ipv4Addr) -> ProtoResult<()> {
    BinEncodable::emit(&A::from(address), encoder)
}

impl From<Ipv4Addr> for A {
    fn from(a: Ipv4Addr) -> Self {
        Self(a)
    }
}

impl From<A> for Ipv4Addr {
    fn from(a: A) -> Self {
        a.0
    }
}

impl Deref for A {
    type Target = Ipv4Addr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl str::FromStr for A {
    type Err = AddrParseError;
    fn from_str(s: &str) -> Result<Self, AddrParseError> {
        Ipv4Addr::from_str(s).map(From::from)
    }
}

#[cfg(test)]
mod mytests {
    use alloc::vec::Vec;

    use super::*;
    use crate::serialize::binary::bin_tests::{test_emit_data_set, test_read_data_set};

    fn get_data() -> Vec<(A, Vec<u8>)> {
        vec![
            (A::from(Ipv4Addr::UNSPECIFIED), vec![0, 0, 0, 0]), // base case
            (A::from(Ipv4Addr::new(1, 0, 0, 0)), vec![1, 0, 0, 0]),
            (A::from(Ipv4Addr::new(0, 1, 0, 0)), vec![0, 1, 0, 0]),
            (A::from(Ipv4Addr::new(0, 0, 1, 0)), vec![0, 0, 1, 0]),
            (A::from(Ipv4Addr::new(0, 0, 0, 1)), vec![0, 0, 0, 1]),
            (A::from(Ipv4Addr::LOCALHOST), vec![127, 0, 0, 1]),
            (
                A::from(Ipv4Addr::new(192, 168, 64, 32)),
                vec![192, 168, 64, 32],
            ),
        ]
    }

    #[test]
    fn test_parse() {
        test_read_data_set(get_data(), |mut d| A::read(&mut d));
    }

    #[test]
    fn test_write_to() {
        test_emit_data_set(get_data(), |e, d| d.emit(e));
    }
}
