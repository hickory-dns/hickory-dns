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

use std::net::Ipv4Addr;

use ::serialize::txt::*;
use ::serialize::binary::*;
use ::error::*;
use ::rr::record_data::RData;

// 3.4. Internet specific RRs
//
// 3.4.1. A RDATA format
//
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ADDRESS                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// where:
//
// ADDRESS         A 32 bit Internet address.
//
// Hosts that have multiple Internet addresses will have multiple A
// records.
//
// A records cause no additional section processing.  The RDATA section of
// an A line in a master file is an Internet address expressed as four
// decimal numbers separated by dots without any imbedded spaces (e.g.,
// "10.2.0.52" or "192.0.5.6").
//
// A { address: Ipv4Addr }
pub fn read(decoder: &mut BinDecoder) -> DecodeResult<RData> {
  Ok(RData::A{ address: Ipv4Addr::new(
    try!(decoder.pop()),
    try!(decoder.pop()),
    try!(decoder.pop()),
    try!(decoder.pop()))
    })
}

pub fn emit(encoder: &mut BinEncoder, a: &RData) -> EncodeResult {
  if let RData::A { address } = *a {
    let segments = address.octets();

    try!(encoder.emit(segments[0]));
    try!(encoder.emit(segments[1]));
    try!(encoder.emit(segments[2]));
    try!(encoder.emit(segments[3]));
    Ok(())
  } else {
    panic!("wrong type here {:?}", a)
  }
}

pub fn parse(tokens: &Vec<Token>) -> ParseResult<RData> {
  let mut token = tokens.iter();

  let address: Ipv4Addr = try!(token.next().ok_or(ParseError::MissingToken("ipv4 address".to_string())).and_then(|t| if let &Token::CharData(ref s) = t {Ok(try!(s.parse()))} else {Err(ParseError::UnexpectedToken(t.clone()))} ));
  Ok(RData::A{ address: address })
}

#[cfg(test)]
mod mytests {
  use std::net::Ipv4Addr;
  use std::str::FromStr;

  use super::*;
  use ::rr::record_data::RData;
  use ::serialize::binary::bin_tests::{test_read_data_set, test_emit_data_set};

  fn get_data() -> Vec<(RData, Vec<u8>)> {
    vec![
    (RData::A{ address: Ipv4Addr::from_str("0.0.0.0").unwrap()}, vec![0,0,0,0]), // base case
    (RData::A{ address: Ipv4Addr::from_str("1.0.0.0").unwrap()}, vec![1,0,0,0]),
    (RData::A{ address: Ipv4Addr::from_str("0.1.0.0").unwrap()}, vec![0,1,0,0]),
    (RData::A{ address: Ipv4Addr::from_str("0.0.1.0").unwrap()}, vec![0,0,1,0]),
    (RData::A{ address: Ipv4Addr::from_str("0.0.0.1").unwrap()}, vec![0,0,0,1]),
    (RData::A{ address: Ipv4Addr::from_str("127.0.0.1").unwrap()}, vec![127,0,0,1]),
    (RData::A{ address: Ipv4Addr::from_str("192.168.64.32").unwrap()}, vec![192,168,64,32]),
    ]
  }

  #[test]
  fn test_parse() {
    test_read_data_set(get_data(), |ref mut d| read(d));
  }

  #[test]
  fn test_write_to() {
    test_emit_data_set(get_data(), |ref mut e, d| emit(e, &d));
  }
}
