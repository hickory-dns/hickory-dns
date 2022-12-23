// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
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

use std::net::Ipv6Addr;

use crate::error::*;
use crate::rr::{RData, RecordData, RecordType};
use crate::serialize::binary::*;

impl RecordData for Ipv6Addr {
    fn try_from_rdata(data: RData) -> Result<Self, crate::rr::RData> {
        match data {
            RData::AAAA(ipv4) => Ok(ipv4),
            _ => Err(data),
        }
    }

    fn try_borrow(data: &RData) -> Result<&Self, &RData> {
        match data {
            RData::AAAA(ipv6) => Ok(ipv6),
            _ => Err(data),
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::A
    }

    fn into_rdata(self) -> RData {
        RData::AAAA(self)
    }
}

/// Read the RData from the given Decoder
#[allow(clippy::many_single_char_names)]
#[deprecated(note = "use the BinDecodable::read method instead")]
pub fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<Ipv6Addr> {
    <Ipv6Addr as BinDecodable>::read(decoder)
}

/// Write the RData from the given Decoder
#[deprecated(note = "use the BinEncodable::emit method instead")]
pub fn emit(encoder: &mut BinEncoder<'_>, address: &Ipv6Addr) -> ProtoResult<()> {
    BinEncodable::emit(address, encoder)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    use super::*;
    use crate::serialize::binary::bin_tests::{test_emit_data_set, test_read_data_set};

    fn get_data() -> Vec<(Ipv6Addr, Vec<u8>)> {
        vec![
            (
                Ipv6Addr::from_str("::").unwrap(),
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ), // base case
            (
                Ipv6Addr::from_str("1::").unwrap(),
                vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            (
                Ipv6Addr::from_str("0:1::").unwrap(),
                vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            (
                Ipv6Addr::from_str("0:0:1::").unwrap(),
                vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            (
                Ipv6Addr::from_str("0:0:0:1::").unwrap(),
                vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            (
                Ipv6Addr::from_str("::1:0:0:0").unwrap(),
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
            ),
            (
                Ipv6Addr::from_str("::1:0:0").unwrap(),
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
            ),
            (
                Ipv6Addr::from_str("::1:0").unwrap(),
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
            ),
            (
                Ipv6Addr::from_str("::1").unwrap(),
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            ),
            (
                Ipv6Addr::from_str("::127.0.0.1").unwrap(),
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1],
            ),
            (
                Ipv6Addr::from_str("FF00::192.168.64.32").unwrap(),
                vec![255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 64, 32],
            ),
        ]
    }

    #[test]
    fn test_read() {
        test_read_data_set(get_data(), |ref mut d| Ipv6Addr::read(d));
    }

    #[test]
    fn test_emit() {
        test_emit_data_set(get_data(), |e, d| d.emit(e));
    }
}
