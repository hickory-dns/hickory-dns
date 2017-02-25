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

use ::serialize::txt::*;
use ::serialize::binary::*;
use ::error::*;

//
// AAAA { address: Ipv6Addr }
pub fn read(decoder: &mut BinDecoder) -> DecodeResult<Ipv6Addr> {
    let a: u16 = try!(decoder.read_u16());
    let b: u16 = try!(decoder.read_u16());
    let c: u16 = try!(decoder.read_u16());
    let d: u16 = try!(decoder.read_u16());
    let e: u16 = try!(decoder.read_u16());
    let f: u16 = try!(decoder.read_u16());
    let g: u16 = try!(decoder.read_u16());
    let h: u16 = try!(decoder.read_u16());

    Ok(Ipv6Addr::new(a, b, c, d, e, f, g, h))
}

pub fn emit(encoder: &mut BinEncoder, address: &Ipv6Addr) -> EncodeResult {
    let segments = address.segments();

    try!(encoder.emit_u16(segments[0]));
    try!(encoder.emit_u16(segments[1]));
    try!(encoder.emit_u16(segments[2]));
    try!(encoder.emit_u16(segments[3]));
    try!(encoder.emit_u16(segments[4]));
    try!(encoder.emit_u16(segments[5]));
    try!(encoder.emit_u16(segments[6]));
    try!(encoder.emit_u16(segments[7]));
    Ok(())
}

pub fn parse(tokens: &Vec<Token>) -> ParseResult<Ipv6Addr> {
    let mut token = tokens.iter();

    let address: Ipv6Addr = try!(token.next()
        .ok_or(ParseError::from(ParseErrorKind::MissingToken("ipv6 address".to_string())))
        .and_then(|t| if let &Token::CharData(ref s) = t {
            Ok(try!(s.parse()))
        } else {
            Err(ParseErrorKind::UnexpectedToken(t.clone()).into())
        }));
    Ok(address)
}


#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    use super::*;
    use serialize::binary::bin_tests::{test_read_data_set, test_emit_data_set};

    fn get_data() -> Vec<(Ipv6Addr, Vec<u8>)> {
        vec![(Ipv6Addr::from_str("::").unwrap(),
              vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), // base case
             (Ipv6Addr::from_str("1::").unwrap(),
              vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
             (Ipv6Addr::from_str("0:1::").unwrap(),
              vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
             (Ipv6Addr::from_str("0:0:1::").unwrap(),
              vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
             (Ipv6Addr::from_str("0:0:0:1::").unwrap(),
              vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]),
             (Ipv6Addr::from_str("::1:0:0:0").unwrap(),
              vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
             (Ipv6Addr::from_str("::1:0:0").unwrap(),
              vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]),
             (Ipv6Addr::from_str("::1:0").unwrap(),
              vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]),
             (Ipv6Addr::from_str("::1").unwrap(),
              vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
             (Ipv6Addr::from_str("::127.0.0.1").unwrap(),
              vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1]),
             (Ipv6Addr::from_str("FF00::192.168.64.32").unwrap(),
              vec![255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 64, 32])]
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
