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

// 3.3.1. CNAME RDATA format
//
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                     CNAME                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// where:
//
// CNAME           A <domain-name> which specifies the canonical or primary
//                 name for the owner.  The owner name is an alias.
//
// CNAME RRs cause no additional section processing, but name servers may
// choose to restart the query at the canonical name in certain cases.  See
// the description of name server logic in [RFC-1034] for details.
//
// CNAME { cname: Name },
pub fn read(decoder: &mut BinDecoder) -> DecodeResult<RData> {
  Ok(RData::CNAME{ cname: try!(Name::read(decoder)) })
}

pub fn emit(encoder: &mut BinEncoder, cname_data: &RData) -> EncodeResult {
  if let RData::CNAME { ref cname } = *cname_data {
    try!(cname.emit(encoder));
    Ok(())
  } else {
    panic!("wrong type: {:?}", cname_data)
  }
}

pub fn parse(tokens: &Vec<Token>, origin: Option<&Name>) -> ParseResult<RData> {
  let mut token = tokens.iter();

  let cname: Name = try!(token.next().ok_or(ParseError::MissingToken("cname".to_string())).and_then(|t| if let &Token::CharData(ref s) = t {Name::parse(s, origin)} else {Err(ParseError::UnexpectedToken(t.clone()))} ));
  Ok(RData::CNAME{ cname: cname })
}


// #[test] is performed at the record_data module, the inner name in domain::Name
