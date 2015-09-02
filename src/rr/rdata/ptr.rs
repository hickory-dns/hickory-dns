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

// 3.3.12. PTR RDATA format
//
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                   PTRDNAME                    /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// where:
//
// PTRDNAME        A <domain-name> which points to some location in the
//                 domain name space.
//
// PTR records cause no additional section processing.  These RRs are used
// in special domains to point to some other location in the domain space.
// These records are simple data, and don't imply any special processing
// similar to that performed by CNAME, which identifies aliases.  See the
// description of the IN-ADDR.ARPA domain for an example.
//
// PTR { ptrdname: Name },
pub fn read(decoder: &mut BinDecoder) -> DecodeResult<RData> {
  Ok(RData::PTR{ ptrdname: try!(Name::read(decoder)) })
}

pub fn emit(encoder: &mut BinEncoder, ptr: &RData) -> EncodeResult {
  if let RData::PTR { ref ptrdname } = *ptr {
    try!(ptrdname.emit(encoder));
    Ok(())
  } else {
    panic!("wrong type: {:?}", ptr)
  }
}

pub fn parse(tokens: &Vec<Token>, origin: Option<&Name>) -> ParseResult<RData> {
  let mut token = tokens.iter();

  let ptrdname: Name = try!(token.next().ok_or(ParseError::MissingToken("ptrdname".to_string())).and_then(|t| if let &Token::CharData(ref s) = t {Name::parse(s, origin)} else {Err(ParseError::UnexpectedToken(t.clone()))} ));
  Ok(RData::PTR{ ptrdname: ptrdname })
}
