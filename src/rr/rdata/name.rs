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

 //! Record type for all cname like records.
 //!
 //! A generic struct for all {*}NAME pointer RData records, CNAME, NS, and PTR. Here is the text for
 //! CNAME from RFC 1035, Domain Implementation and Specification, November 1987:
 //!
 //! [RFC 1035, DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987](https://tools.ietf.org/html/rfc1035)
 //!
 //! ```text
 //! 3.3.1. CNAME RDATA format
 //!
 //!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 //!     /                     CNAME                     /
 //!     /                                               /
 //!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 //!
 //! where:
 //!
 //! CNAME           A <domain-name> which specifies the canonical or primary
 //!                 name for the owner.  The owner name is an alias.
 //!
 //! CNAME RRs cause no additional section processing, but name servers may
 //! choose to restart the query at the canonical name in certain cases.  See
 //! the description of name server logic in [RFC-1034] for details.
 //! ```

use ::serialize::txt::*;
use ::serialize::binary::*;
use ::error::*;
use ::rr::domain::Name;


pub fn read(decoder: &mut BinDecoder) -> DecodeResult<Name> {
  Name::read(decoder)
}

pub fn emit(encoder: &mut BinEncoder, name_data: &Name) -> EncodeResult {
  try!(name_data.emit(encoder));
  Ok(())
}

pub fn parse(tokens: &Vec<Token>, origin: Option<&Name>) -> ParseResult<Name> {
  let mut token = tokens.iter();

  let name: Name = try!(token.next().ok_or(ParseErrorKind::MissingToken("name".to_string()).into()).and_then(|t| if let &Token::CharData(ref s) = t {Name::parse(s, origin)} else {Err(ParseErrorKind::UnexpectedToken(t.clone()).into())} ));
  Ok(name)
}


#[test]
pub fn test() {
  let rdata = Name::new().label("www").label("example").label("com");

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
