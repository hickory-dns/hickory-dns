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

// 3.3.11. NS RDATA format
//
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                   NSDNAME                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// where:
//
// NSDNAME         A <domain-name> which specifies a host which should be
//                 authoritative for the specified class and domain.
//
// NS records cause both the usual additional section processing to locate
// a type A record, and, when used in a referral, a special search of the
// zone in which they reside for glue information.
//
// The NS RR states that the named host should be expected to have a zone
// starting at owner name of the specified class.  Note that the class may
// not indicate the protocol family which should be used to communicate
// with the host, although it is typically a strong hint.  For example,
// hosts which are name servers for either Internet (IN) or Hesiod (HS)
// class information are normally queried using IN class protocols.
//
// NS { nsdname: Name },
pub fn read(decoder: &mut BinDecoder) -> DecodeResult<RData> {
  Ok(RData::NS{ nsdname: try!(Name::read(decoder)) })
}

pub fn emit(encoder: &mut BinEncoder, ns: &RData) -> EncodeResult {
  if let RData::NS{ ref nsdname } = *ns {
    try!(nsdname.emit(encoder));
    Ok(())
  } else {
    panic!("wrong type here {:?}", ns);
  }
}

pub fn parse(tokens: &Vec<Token>) -> ParseResult<RData> {
  unimplemented!()
}
