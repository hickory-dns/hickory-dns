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

//! start of authority record defining ownership and defaults for the zone

use ::serialize::txt::*;
use ::serialize::binary::*;
use ::error::*;
use ::rr::domain::Name;

/// [RFC 1035, DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987](https://tools.ietf.org/html/rfc1035)
///
/// ```text
/// 3.3.13. SOA RDATA format
///
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     /                     MNAME                     /
///     /                                               /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     /                     RNAME                     /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    SERIAL                     |
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    REFRESH                    |
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                     RETRY                     |
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    EXPIRE                     |
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    MINIMUM                    |
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
/// where:
///
/// SOA records cause no additional section processing.
///
/// All times are in units of seconds.
///
/// Most of these fields are pertinent only for name server maintenance
/// operations.  However, MINIMUM is used in all query operations that
/// retrieve RRs from a zone.  Whenever a RR is sent in a response to a
/// query, the TTL field is set to the maximum of the TTL field from the RR
/// and the MINIMUM field in the appropriate SOA.  Thus MINIMUM is a lower
/// bound on the TTL field for all RRs in a zone.  Note that this use of
/// MINIMUM should occur when the RRs are copied into the response and not
/// when the zone is loaded from a master file or via a zone transfer.  The
/// reason for this provison is to allow future dynamic update facilities to
/// change the SOA RR with known semantics.
/// ```
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SOA { mname: Name, rname: Name, serial: u32,
                 refresh: i32, retry: i32, expire: i32,
                 minimum: u32, }

impl SOA {
  pub fn new(mname: Name, rname: Name, serial: u32,
             refresh: i32, retry: i32, expire: i32,
             minimum: u32) -> Self {
    SOA { mname: mname, rname: rname, serial: serial,
          refresh: refresh, retry: retry, expire: expire,
          minimum: minimum, }
  }

  /// Increments the serial number by one
  pub fn increment_serial(&mut self) {
    self.serial += 1;
  }

  /// ```text
  /// MNAME           The <domain-name> of the name server that was the
  ///                 original or primary source of data for this zone.
  /// ```
  ///
  /// # Return value
  ///
  /// The `domain-name` of the name server that was the original or primary source of data for
  /// this zone, i.e. the master name server.
  pub fn get_mname(&self) -> &Name { &self.mname }

  /// ```text
  /// RNAME           A <domain-name> which specifies the mailbox of the
  ///                 person responsible for this zone.
  /// ```
  ///
  /// # Return value
  ///
  /// A `domain-name` which specifies the mailbox of the person responsible for this zone, i.e.
  /// the responsible name.
  pub fn get_rname(&self) -> &Name { &self.rname }

  /// ```text
  /// SERIAL          The unsigned 32 bit version number of the original copy
  ///                 of the zone.  Zone transfers preserve this value.  This
  ///                 value wraps and should be compared using sequence space
  ///                 arithmetic.
  /// ```
  ///
  /// # Return value
  ///
  /// The unsigned 32 bit version number of the original copy of the zone. Zone transfers
  /// preserve this value. This value wraps and should be compared using sequence space arithmetic.
  pub fn get_serial(&self) -> u32 { self.serial }

  /// ```text
  /// REFRESH         A 32 bit time interval before the zone should be
  ///                 refreshed.
  /// ```
  ///
  /// # Return value
  ///
  /// A 32 bit time interval before the zone should be refreshed, in seconds.
  pub fn get_refresh(&self) -> i32 { self.refresh }

  /// ```text
  /// RETRY           A 32 bit time interval that should elapse before a
  ///                 failed refresh should be retried.
  /// ```
  ///
  /// # Return value
  ///
  /// A 32 bit time interval that should elapse before a failed refresh should be retried,
  /// in seconds.
  pub fn get_retry(&self) -> i32 { self.retry }

  /// ```text
  /// EXPIRE          A 32 bit time value that specifies the upper limit on
  ///                 the time interval that can elapse before the zone is no
  ///                 longer authoritative.
  /// ```
  ///
  /// # Return value
  ///
  /// A 32 bit time value that specifies the upper limit on the time interval that can elapse
  /// before the zone is no longer authoritative, in seconds
  pub fn get_expire(&self) -> i32 { self.expire }

  /// ```text
  /// MINIMUM         The unsigned 32 bit minimum TTL field that should be
  ///                 exported with any RR from this zone.
  /// ```
  ///
  /// # Return value
  ///
  /// The unsigned 32 bit minimum TTL field that should be exported with any RR from this zone.
  pub fn get_minimum(&self) -> u32 { self.minimum }
}

// SOA { mname: Name, rname: Name, serial: u32, refresh: i32, retry: i32, expire: i32, minimum: u32, },
pub fn read(decoder: &mut BinDecoder) -> DecodeResult<SOA> {
  Ok(SOA{
    mname:   try!(Name::read(decoder)),
    rname:   try!(Name::read(decoder)),
    serial:  try!(decoder.read_u32()),
    refresh: try!(decoder.read_i32()),
    retry:   try!(decoder.read_i32()),
    expire:  try!(decoder.read_i32()),
    minimum: try!(decoder.read_u32()),
  })
}

pub fn emit(encoder: &mut BinEncoder, soa: &SOA) -> EncodeResult {
  try!(soa.mname.emit(encoder));
  try!(soa.rname.emit(encoder));
  try!(encoder.emit_u32(soa.serial));
  try!(encoder.emit_i32(soa.refresh));
  try!(encoder.emit_i32(soa.retry));
  try!(encoder.emit_i32(soa.expire));
  try!(encoder.emit_u32(soa.minimum));
  Ok(())
}

// VENERA      Action\.domains (
//                                 20     ; SERIAL
//                                 7200   ; REFRESH
//                                 600    ; RETRY
//                                 3600000; EXPIRE
//                                 60)    ; MINIMUM
pub fn parse(tokens: &Vec<Token>, origin: Option<&Name>) -> ParseResult<SOA> {
  let mut token = tokens.iter();

  let mname: Name = try!(token.next().ok_or(ParseError::MissingToken("mname".to_string())).and_then(|t| if let &Token::CharData(ref s) = t {Name::parse(s, origin)} else {Err(ParseError::UnexpectedToken(t.clone()))} ));
  let rname: Name = try!(token.next().ok_or(ParseError::MissingToken("rname".to_string())).and_then(|t| if let &Token::CharData(ref s) = t {Name::parse(s, origin)} else {Err(ParseError::UnexpectedToken(t.clone()))} ));
  let mut list = try!(token.next().ok_or(ParseError::MissingToken("List".to_string())).and_then(|t| if let &Token::List(ref v) = t {Ok(v)} else {Err(ParseError::UnexpectedToken(t.clone()))} )).iter();

  let serial: u32 = try!(list.next().ok_or(ParseError::MissingToken("serial".to_string())).and_then(|s| Ok(try!(s.parse()))));
  let refresh: i32 = try!(list.next().ok_or(ParseError::MissingToken("refresh".to_string())).and_then(|s| Ok(try!(s.parse()))));
  let retry: i32 = try!(list.next().ok_or(ParseError::MissingToken("retry".to_string())).and_then(|s| Ok(try!(s.parse()))));
  let expire: i32 = try!(list.next().ok_or(ParseError::MissingToken("expire".to_string())).and_then(|s| Ok(try!(s.parse()))));
  let minimum: u32 = try!(list.next().ok_or(ParseError::MissingToken("minimum".to_string())).and_then(|s| Ok(try!(s.parse()))));


  // let serial: u32 = try!(token.next().ok_or(ParseError::MissingToken("serial".to_string())).and_then(|t| if let &Token::CharData(ref s) = t {Ok(try!(s.parse()))} else {Err(ParseError::UnexpectedToken(t.clone()))} ));
  // let refresh: i32 = try!(token.next().ok_or(ParseError::MissingToken("refresh".to_string())).and_then(|t| if let &Token::CharData(ref s) = t {Ok(try!(s.parse()))} else {Err(ParseError::UnexpectedToken(t.clone()))} ));
  // let retry: i32 = try!(token.next().ok_or(ParseError::MissingToken("retry".to_string())).and_then(|t| if let &Token::CharData(ref s) = t {Ok(try!(s.parse()))} else {Err(ParseError::UnexpectedToken(t.clone()))} ));
  // let expire: i32 = try!(token.next().ok_or(ParseError::MissingToken("expire".to_string())).and_then(|t| if let &Token::CharData(ref s) = t {Ok(try!(s.parse()))} else {Err(ParseError::UnexpectedToken(t.clone()))} ));
  // let minimum: u32 = try!(token.next().ok_or(ParseError::MissingToken("minimum".to_string())).and_then(|t| if let &Token::CharData(ref s) = t {Ok(try!(s.parse()))} else {Err(ParseError::UnexpectedToken(t.clone()))} ));

  Ok(SOA::new(mname, rname, serial, refresh, retry, expire, minimum))
}

#[test]
fn test() {
  let rdata = SOA::new(Name::new().label("m").label("example").label("com"),
                       Name::new().label("r").label("example").label("com"),
                       1, 2, 3, 4, 5);

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
