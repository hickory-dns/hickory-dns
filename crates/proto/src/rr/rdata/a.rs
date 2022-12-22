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

pub use std::net::Ipv4Addr;

use crate::error::*;
use crate::rr::{RData, RecordData, RecordType};
use crate::serialize::binary::*;

impl RecordData for Ipv4Addr {
    fn try_from_rdata(data: RData) -> Result<Self, crate::rr::RData> {
        match data {
            RData::A(ipv4) => Ok(ipv4),
            _ => Err(data),
        }
    }

    fn try_borrow(data: &RData) -> Result<&Self, &RData> {
        match data {
            RData::A(ipv4) => Ok(ipv4),
            _ => Err(data),
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::A
    }

    fn into_rdata(self) -> RData {
        RData::A(self)
    }
}

/// Read the RData from the given Decoder
#[deprecated(note = "use the BinDecodable::read method instead")]
pub fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<Ipv4Addr> {
    <Ipv4Addr as BinDecodable>::read(decoder)
}

/// Write the RData from the given Decoder
#[deprecated(note = "use the BinEncodable::emit method instead")]
pub fn emit(encoder: &mut BinEncoder<'_>, address: Ipv4Addr) -> ProtoResult<()> {
    BinEncodable::emit(&address, encoder)
}

#[cfg(test)]
mod mytests {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use super::*;
    use crate::serialize::binary::bin_tests::{test_emit_data_set, test_read_data_set};

    fn get_data() -> Vec<(Ipv4Addr, Vec<u8>)> {
        vec![
            (Ipv4Addr::from_str("0.0.0.0").unwrap(), vec![0, 0, 0, 0]), // base case
            (Ipv4Addr::from_str("1.0.0.0").unwrap(), vec![1, 0, 0, 0]),
            (Ipv4Addr::from_str("0.1.0.0").unwrap(), vec![0, 1, 0, 0]),
            (Ipv4Addr::from_str("0.0.1.0").unwrap(), vec![0, 0, 1, 0]),
            (Ipv4Addr::from_str("0.0.0.1").unwrap(), vec![0, 0, 0, 1]),
            (Ipv4Addr::from_str("127.0.0.1").unwrap(), vec![127, 0, 0, 1]),
            (
                Ipv4Addr::from_str("192.168.64.32").unwrap(),
                vec![192, 168, 64, 32],
            ),
        ]
    }

    #[test]
    fn test_parse() {
        test_read_data_set(get_data(), |ref mut d| Ipv4Addr::read(d));
    }

    #[test]
    fn test_write_to() {
        test_emit_data_set(get_data(), |ref mut e, d| d.emit(e));
    }
}
