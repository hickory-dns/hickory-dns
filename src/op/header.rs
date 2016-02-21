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

use std::convert::From;

use ::serialize::binary::*;
use ::error::*;
use super::op_code::OpCode;
use super::response_code::ResponseCode;

/*
 * RFC 1035        Domain Implementation and Specification    November 1987
 *
 * 4.1.1. Header section format
 *
 * The header contains the following fields
 *
 *                                    1  1  1  1  1  1
 *      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                      ID                       |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |QR|   Opcode  |AA|TC|RD|RA|ZZ|AD|CD|   RCODE   |  // AD and CD from RFC4035
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    QDCOUNT / ZCOUNT           |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    ANCOUNT / PRCOUNT          |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    NSCOUNT / UPCOUNT          |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    ARCOUNT / ADCOUNT          |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where
 *
 * ID              A 16 bit identifier assigned by the program that
 *                 generates any kind of query.  This identifier is copied
 *                 the corresponding reply and can be used by the requester
 *                 to match up replies to outstanding queries.
 *
 * QR              A one bit field that specifies whether this message is a
 *                 query (0), or a response (1).
 *
 * OPCODE          A four bit field that specifies kind of query in this
 *                 message.  This value is set by the originator of a query
 *                 and copied into the response.  The values are: <see super::op_code>
 *
 * AA              Authoritative Answer - this bit is valid in responses,
 *                 and specifies that the responding name server is an
 *                 authority for the domain name in question section.
 *
 *                 Note that the contents of the answer section may have
 *                 multiple owner names because of aliases.  The AA bit
 *                 corresponds to the name which matches the query name, or
 *                 the first owner name in the answer section.
 *
 * TC              TrunCation - specifies that this message was truncated
 *                 due to length greater than that permitted on the
 *                 transmission channel.
 *
 * RD              Recursion Desired - this bit may be set in a query and
 *                 is copied into the response.  If RD is set, it directs
 *                 the name server to pursue the query recursively.
 *                 Recursive query support is optional.
 *
 * RA              Recursion Available - this be is set or cleared in a
 *                 response, and denotes whether recursive query support is
 *                 available in the name server.
 *
 * Z               Reserved for future use.  Must be zero in all queries
 *                 and responses.
 *
 * RCODE           Response code - this 4 bit field is set as part of
 *                 responses.  The values have the following
 *                 interpretation: <see super::response_code>
 *
 * QDCOUNT         an unsigned 16 bit integer specifying the number of
 *                 entries in the question section.
 *
 * ANCOUNT         an unsigned 16 bit integer specifying the number of
 *                 resource records in the answer section.
 *
 * NSCOUNT         an unsigned 16 bit integer specifying the number of name
 *                 server resource records in the authority records
 *                 section.
 *
 * ARCOUNT         an unsigned 16 bit integer specifying the number of
 *                 resource records in the additional records section.
 *
 * RFC 4035             DNSSEC Protocol Modifications            March 2005
 *
 * 3.1.6.  The AD and CD Bits in an Authoritative Response
 *
 *   The CD and AD bits are designed for use in communication between
 *   security-aware resolvers and security-aware recursive name servers.
 *   These bits are for the most part not relevant to query processing by
 *   security-aware authoritative name servers.
 *
 *   A security-aware name server does not perform signature validation
 *   for authoritative data during query processing, even when the CD bit
 *   is clear.  A security-aware name server SHOULD clear the CD bit when
 *   composing an authoritative response.
 *
 *   A security-aware name server MUST NOT set the AD bit in a response
 *   unless the name server considers all RRsets in the Answer and
 *   Authority sections of the response to be authentic.  A security-aware
 *   name server's local policy MAY consider data from an authoritative
 *   zone to be authentic without further validation.  However, the name
 *   server MUST NOT do so unless the name server obtained the
 *   authoritative zone via secure means (such as a secure zone transfer
 *   mechanism) and MUST NOT do so unless this behavior has been
 *   configured explicitly.
 *
 *   A security-aware name server that supports recursion MUST follow the
 *   rules for the CD and AD bits given in Section 3.2 when generating a
 *   response that involves data obtained via recursion.
 */
#[derive(Debug, PartialEq, PartialOrd)]
pub struct Header {
  id: u16, message_type: MessageType, op_code: OpCode,
  authoritative: bool, truncation: bool, recursion_desired: bool, recursion_available: bool,
  authentic_data: bool, checking_disabled: bool,
  response_code: u8 /* ideally u4 */,
  query_count: u16, answer_count: u16, name_server_count: u16, additional_count: u16,
}

#[derive(Debug, PartialEq, PartialOrd, Copy, Clone)]
pub enum MessageType {
  Query, Response
}

impl Header {
  // TODO: we should make id, message_type and op_code all required and non-editable
  /// A default Header, not very useful.
  pub fn new() -> Self {
    Header {
      id: 0,
      message_type: MessageType::Query,
      op_code: OpCode::Query,
      authoritative: false,
      truncation: false,
      recursion_desired: false,
      recursion_available: false,
      authentic_data: false,
      checking_disabled: false,
      response_code: 0,
      query_count: 0,
      answer_count: 0,
      name_server_count: 0,
      additional_count: 0,
    }
  }

  #[inline(always)]
  pub fn len() -> usize { 12 /* this is always 12 bytes */ }

  pub fn id(&mut self, id: u16) -> &mut Self { self.id = id; self }
  pub fn message_type(&mut self, message_type: MessageType) -> &mut Self { self.message_type = message_type; self }
  pub fn op_code(&mut self, op_code: OpCode) -> &mut Self { self.op_code = op_code; self }
  pub fn authoritative(&mut self, authoritative: bool) -> &mut Self { self.authoritative = authoritative; self }
  pub fn truncated(&mut self, truncated: bool) -> &mut Self { self.truncation = truncated; self }
  pub fn recursion_desired(&mut self, recursion_desired: bool) -> &mut Self { self.recursion_desired = recursion_desired; self }
  pub fn recursion_available(&mut self, recursion_available: bool) -> &mut Self {self.recursion_available = recursion_available; self }
  pub fn authentic_data(&mut self, authentic_data: bool) -> &mut Self {self.authentic_data = authentic_data; self}
  pub fn checking_disabled(&mut self, checking_disabled: bool) -> &mut Self {self.checking_disabled = checking_disabled; self}
  pub fn response_code(&mut self, response_code: ResponseCode) -> &mut Self { self.response_code = response_code.low(); self }
  pub fn query_count(&mut self, query_count: u16) -> &mut Self { self.query_count = query_count; self }
  pub fn answer_count(&mut self, answer_count: u16) -> &mut Self { self.answer_count = answer_count; self }
  pub fn name_server_count(&mut self, name_server_count: u16) -> &mut Self { self.name_server_count = name_server_count; self }
  pub fn additional_count(&mut self, additional_count: u16) -> &mut Self { self.additional_count = additional_count; self }

  pub fn get_id(&self) -> u16 { self.id }
  pub fn get_message_type(&self) -> MessageType { self.message_type }
  pub fn get_op_code(&self) -> OpCode { self.op_code }
  pub fn is_authoritative(&self) -> bool { self.authoritative }
  pub fn is_truncated(&self) -> bool { self.truncation }
  pub fn is_recursion_desired(&self) -> bool { self.recursion_desired }
  pub fn is_recursion_available(&self) -> bool {self.recursion_available }
  pub fn is_authentic_data(&self) -> bool {self.authentic_data}
  pub fn is_checking_disabled(&self) -> bool {self.checking_disabled}
  pub fn get_response_code(&self) -> u8 { self.response_code }

  /// for query this is the count of query records
  /// for updates this is the zone count (only 1 allowed)
  pub fn get_query_count(&self) -> u16 { self.query_count }

  /// for queries this is the answer section and record count
  /// for updates this is the prerequisite count
  pub fn get_answer_count(&self) -> u16 { self.answer_count }

  /// for queries this is the nameservers which are authorities for the SOA of the Record
  /// for updates this is the update record count
  pub fn get_name_server_count(&self) -> u16 { self.name_server_count }

  /// number of records in the additional section, same for queries and updates.
  pub fn get_additional_count(&self) -> u16 { self.additional_count }

  /// This is a specialized clone which clones all the fields but the counts
  ///  handy for setting the count fields before sending over the wire.
  pub fn clone(&self, query_count: u16, answer_count: u16, name_server_count: u16, additional_count: u16) -> Self {
    Header {
      query_count: query_count, answer_count: answer_count, name_server_count: name_server_count,
      additional_count: additional_count, .. *self
    }
  }
}

impl BinSerializable<Header> for Header {
  fn read(decoder: &mut BinDecoder) -> DecodeResult<Self> {
    let id = try!(decoder.read_u16());

    let q_opcd_a_t_r = try!(decoder.pop());
    // if the first bit is set
    let message_type = if (0x80 & q_opcd_a_t_r) == 0x80 { MessageType::Response } else { MessageType::Query };
    // the 4bit opcode, masked and then shifted right 3bits for the u8...
    let op_code: OpCode = ((0x78 & q_opcd_a_t_r) >> 3).into();
    let authoritative = (0x4 & q_opcd_a_t_r) == 0x4;
    let truncation = (0x2 & q_opcd_a_t_r) == 0x2;
    let recursion_desired = (0x1 & q_opcd_a_t_r) == 0x1;

    let r_z_ad_cd_rcod = try!(decoder.pop()); // fail fast...
    let recursion_available = (0b1000_0000 & r_z_ad_cd_rcod) == 0b1000_0000;
    let authentic_data = (0b0010_0000 & r_z_ad_cd_rcod) == 0b0010_0000;
    let checking_disabled = (0b0001_0000 & r_z_ad_cd_rcod) == 0b0001_0000;
    let response_code: u8 = 0x0F & r_z_ad_cd_rcod;

    let query_count = try!(decoder.read_u16());
    let answer_count = try!(decoder.read_u16());
    let name_server_count = try!(decoder.read_u16());
    let additional_count = try!(decoder.read_u16());

    // TODO: question, should this use the builder pattern instead? might be cleaner code, but
    //  this guarantees that the Header is fully instantiated with all values...
    Ok(Header { id: id, message_type: message_type, op_code: op_code, authoritative: authoritative,
             truncation: truncation, recursion_desired: recursion_desired,
             recursion_available: recursion_available,
             authentic_data: authentic_data, checking_disabled: checking_disabled,
             response_code: response_code,
             query_count: query_count, answer_count: answer_count,
             name_server_count: name_server_count, additional_count: additional_count })
  }

  fn emit(&self, encoder: &mut BinEncoder) -> EncodeResult {
    encoder.reserve(12); // the 12 bytes for the following fields;

    // Id
    try!(encoder.emit_u16(self.id));

    // IsQuery, OpCode, Authoritative, Truncation, RecursionDesired
    let mut q_opcd_a_t_r: u8 = if let MessageType::Response = self.message_type { 0x80 } else { 0x00 };
    q_opcd_a_t_r |= u8::from(self.op_code) << 3;
    q_opcd_a_t_r |= if self.authoritative { 0x4 } else { 0x0 };
    q_opcd_a_t_r |= if self.truncation { 0x2 } else { 0x0 };
    q_opcd_a_t_r |= if self.recursion_desired { 0x1 } else { 0x0 };
    try!(encoder.emit(q_opcd_a_t_r));

    // IsRecursionAvailable, Triple 0's, ResponseCode
    let mut r_z_ad_cd_rcod: u8 = if self.recursion_available { 0b1000_0000 } else { 0b0000_0000 };
    r_z_ad_cd_rcod |= if self.authentic_data { 0b0010_0000 } else { 0b0000_0000 };
    r_z_ad_cd_rcod |= if self.checking_disabled { 0b0001_0000 } else { 0b0000_0000 };
    r_z_ad_cd_rcod |= u8::from(self.response_code);
    try!(encoder.emit(r_z_ad_cd_rcod));

    try!(encoder.emit_u16(self.query_count));
    try!(encoder.emit_u16(self.answer_count));
    try!(encoder.emit_u16(self.name_server_count));
    try!(encoder.emit_u16(self.additional_count));

    Ok(())
  }
}

#[test]
fn test_parse() {
  let byte_vec = vec![
    0x01, 0x10,
    0xAA, 0x83, // 0b1010 1010 1000 0011
    0x88, 0x77,
    0x66, 0x55,
    0x44, 0x33,
    0x22, 0x11];

  let mut decoder = BinDecoder::new(&byte_vec);

  let expect = Header { id: 0x0110, message_type: MessageType::Response, op_code: OpCode::Update,
    authoritative: false, truncation: true, recursion_desired: false,
    recursion_available: true, authentic_data: false, checking_disabled: false, response_code: ResponseCode::NXDomain.low(),
    query_count: 0x8877, answer_count: 0x6655, name_server_count: 0x4433, additional_count: 0x2211};

  let got = Header::read(&mut decoder).unwrap();

  assert_eq!(got, expect);
}

#[test]
fn test_write() {
  let header = Header { id: 0x0110, message_type: MessageType::Response, op_code: OpCode::Update,
    authoritative: false, truncation: true, recursion_desired: false,
    recursion_available: true, authentic_data: false, checking_disabled: false, response_code: ResponseCode::NXDomain.low(),
    query_count: 0x8877, answer_count: 0x6655, name_server_count: 0x4433, additional_count: 0x2211};

  let expect: Vec<u8> = vec![0x01, 0x10,
                             0xAA, 0x83, // 0b1010 1010 1000 0011
                             0x88, 0x77,
                             0x66, 0x55,
                             0x44, 0x33,
                             0x22, 0x11];

  let mut bytes = Vec::with_capacity(512);
  {
    let mut encoder = BinEncoder::new(&mut bytes);
    header.emit(&mut encoder).unwrap();
  }

  assert_eq!(bytes, expect);
}
