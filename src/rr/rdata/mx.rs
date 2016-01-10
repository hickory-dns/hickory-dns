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

use ::serialize::txt::*;
use ::serialize::binary::*;
use ::error::*;
use ::rr::record_data::RData;
use ::rr::domain::Name;

// 3.3.9. MX RDATA format
//
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                  PREFERENCE                   |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                   EXCHANGE                    /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// where:
//
// PREFERENCE      A 16 bit integer which specifies the preference given to
//                 this RR among others at the same owner.  Lower values
//                 are preferred.
//
// EXCHANGE        A <domain-name> which specifies a host willing to act as
//                 a mail exchange for the owner name.
//
// MX records cause type A additional section processing for the host
// specified by EXCHANGE.  The use of MX RRs is explained in detail in
// [RFC-974].
//
// MX { preference: u16, exchange: Name },
pub fn read(decoder: &mut BinDecoder) -> DecodeResult<RData> {
  Ok(RData::MX { preference: try!(decoder.read_u16()), exchange: try!(Name::read(decoder)) })
}

pub fn emit(encoder: &mut BinEncoder, mx: &RData) -> EncodeResult {
  if let RData::MX { preference, ref exchange } = *mx {
    try!(encoder.emit_u16(preference));
    try!(exchange.emit(encoder));
    Ok(())
  } else {
    panic!("wrong type here {:?}", mx);
  }
}

pub fn parse(tokens: &Vec<Token>, origin: Option<&Name>) -> ParseResult<RData> {
  let mut token = tokens.iter();

  let preference: u16 = try!(token.next().ok_or(ParseError::MissingToken("preference".to_string())).and_then(|t| if let &Token::CharData(ref s) = t {Ok(try!(s.parse()))} else {Err(ParseError::UnexpectedToken(t.clone()))} ));
  let exchange: Name = try!(token.next().ok_or(ParseError::MissingToken("exchange".to_string())).and_then(|t| if let &Token::CharData(ref s) = t {Name::parse(s, origin)} else {Err(ParseError::UnexpectedToken(t.clone()))} ));

  Ok(RData::MX { preference: preference, exchange: exchange})
}

#[test]
pub fn test() {
  let rdata = RData::MX{ preference: 16,
    exchange: Name::new().label("mail").label("example").label("com") };

  let mut bytes = Vec::new();
  let mut encoder: BinEncoder = BinEncoder::new(&mut bytes);
  assert!(emit(&mut encoder, &rdata).is_ok());
  let bytes = encoder.as_bytes();

  println!("bytes: {:?}", bytes);

  let mut decoder: BinDecoder = BinDecoder::new(bytes);
  let read_rdata = read(&mut decoder);
  assert!(read_rdata.is_ok(), format!("error decoding: {:?}", read_rdata.unwrap_err()));
  assert_eq!(rdata, read_rdata.unwrap());
}
