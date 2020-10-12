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
use crate::serialize::binary::*;

/// Read the RData from the given Decoder
#[allow(clippy::many_single_char_names)]
pub fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<Ipv6Addr> {
    let a: u16 = decoder.read_u16()?.unverified(/*valid as any u16*/);
    let b: u16 = decoder.read_u16()?.unverified(/*valid as any u16*/);
    let c: u16 = decoder.read_u16()?.unverified(/*valid as any u16*/);
    let d: u16 = decoder.read_u16()?.unverified(/*valid as any u16*/);
    let e: u16 = decoder.read_u16()?.unverified(/*valid as any u16*/);
    let f: u16 = decoder.read_u16()?.unverified(/*valid as any u16*/);
    let g: u16 = decoder.read_u16()?.unverified(/*valid as any u16*/);
    let h: u16 = decoder.read_u16()?.unverified(/*valid as any u16*/);

    Ok(Ipv6Addr::new(a, b, c, d, e, f, g, h))
}

/// Write the RData from the given Decoder
pub fn emit(encoder: &mut BinEncoder<'_>, address: &Ipv6Addr) -> ProtoResult<()> {
    let segments = address.segments();

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
        test_read_data_set(get_data(), |ref mut d| read(d));
    }

    #[test]
    fn test_emit() {
        test_emit_data_set(get_data(), |e, d| emit(e, &d));
    }
}
