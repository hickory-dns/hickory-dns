use std::convert::From;

use super::op_code::OpCode;
use super::response_code::ResponseCode;
use super::super::rr::util;

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
 *     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    QDCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    ANCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    NSCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    ARCOUNT                    |
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
 */
#[derive(Debug, PartialEq, PartialOrd)]
pub struct Header {
  id: u16, message_type: MessageType, op_code: OpCode,
  authoritative: bool, truncation: bool, recursion_desired: bool, recursion_available: bool,
  response_code: ResponseCode,
  query_count: u16, answer_count: u16, name_server_count: u16, additional_count: u16
}

#[derive(Debug, PartialEq, PartialOrd, Copy, Clone)]
pub enum MessageType {
  Query, Response
}

impl Header {
  pub fn parse(data: &mut Vec<u8>) -> Self {
    let id = util::parse_u16(data);

    let q_opcd_a_t_r = data.pop().unwrap(); // fail fast...
    // if the first bit is set
    let message_type = if ((0x80 & q_opcd_a_t_r) == 0x80) { MessageType::Response } else { MessageType::Query };
    // the 4bit opcode, masked and then shifted right 3bits for the u8...
    let op_code: OpCode = ((0x78 & q_opcd_a_t_r) >> 3).into();
    let authoritative = (0x4 & q_opcd_a_t_r) == 0x4;
    let truncation = (0x2 & q_opcd_a_t_r) == 0x2;
    let recursion_desired = (0x1 & q_opcd_a_t_r) == 0x1;

    let r_zzz_rcod = data.pop().unwrap(); // fail fast...
    let recursion_available = (0x80 & r_zzz_rcod) == 0x80;
    // TODO the > 16 codes in ResponseCode come from somewhere, (zzz?) need to better understand RFC
    let response_code: ResponseCode = (0x7 & r_zzz_rcod).into();
    let query_count = util::parse_u16(data);
    let answer_count = util::parse_u16(data);
    let name_server_count = util::parse_u16(data);
    let additional_count = util::parse_u16(data);

    // TODO: question, should this use the builder pattern instead? might be cleaner code, but
    //  this guarantees that the Header is
    Header { id: id, message_type: message_type, op_code: op_code, authoritative: authoritative,
             truncation: truncation, recursion_desired: recursion_desired,
             recursion_available: recursion_available, response_code: response_code,
             query_count: query_count, answer_count: answer_count,
             name_server_count: name_server_count, additional_count: additional_count }
  }

  pub fn write_to(&self, buf: &mut Vec<u8>) {
    buf.reserve(12); // the 12 bytes for the following fields;

    // Id
    util::write_u16_to(buf, self.id);

    // IsQuery, OpCode, Authoritative, Truncation, RecursionDesired
    let mut q_opcd_a_t_r: u8 = 0;
    q_opcd_a_t_r = if let MessageType::Response = self.message_type { 0x80 } else { 0x00 };
    q_opcd_a_t_r |= u8::from(self.op_code) << 3;
    q_opcd_a_t_r |= if self.authoritative { 0x4 } else { 0x0 };
    q_opcd_a_t_r |= if self.truncation { 0x2 } else { 0x0 };
    q_opcd_a_t_r |= if self.recursion_desired { 0x1 } else { 0x0 };
    buf.push(q_opcd_a_t_r);

    // IsRecursionAvailable, Triple 0's, ResponseCode
    let mut r_zzz_rcod: u8 = 0;
    r_zzz_rcod = if self.recursion_available { 0x80 } else { 0x00 };
    r_zzz_rcod |= u8::from(self.response_code);
    buf.push(r_zzz_rcod);

    util::write_u16_to(buf, self.query_count);
    util::write_u16_to(buf, self.answer_count);
    util::write_u16_to(buf, self.name_server_count);
    util::write_u16_to(buf, self.additional_count);
  }

  pub fn getId(&self) -> u16 { self.id }
  pub fn getMessageType(&self) -> MessageType { self.message_type }
  pub fn getOpCode(&self) -> OpCode { self.op_code }
  pub fn isAuthoritative(&self) -> bool { self.authoritative }
  pub fn isTruncated(&self) -> bool { self.truncation }
  pub fn isRecursionDesired(&self) -> bool { self.recursion_desired }
  pub fn isRecursionAvailable(&self) -> bool {self.recursion_available }
  pub fn getResponseCode(&self) -> ResponseCode { self.response_code }
  pub fn getQueryCount(&self) -> u16 { self.query_count }
  pub fn getAnswerCount(&self) -> u16 { self.answer_count }
  pub fn getNameServerCount(&self) -> u16 { self.name_server_count }
  pub fn getAdditionalCount(&self) -> u16 { self.additional_count }
}

#[test]
fn test_parse() {
  let mut data: Vec<u8> = vec![0x01, 0x10,
                               0xAA, 0x83, // 0b1010 1010 1000 0011
                               0x88, 0x77,
                               0x66, 0x55,
                               0x44, 0x33,
                               0x22, 0x11];

  data.reverse();

  let expect = Header { id: 0x0110, message_type: MessageType::Response, op_code: OpCode::Update,
    authoritative: false, truncation: true, recursion_desired: false,
    recursion_available: true, response_code: ResponseCode::NXDomain,
    query_count: 0x8877, answer_count: 0x6655, name_server_count: 0x4433, additional_count: 0x2211};

  let got = Header::parse(&mut data);

  assert_eq!(got, expect);
}

#[test]
fn test_write() {
  let header = Header { id: 0x0110, message_type: MessageType::Response, op_code: OpCode::Update,
    authoritative: false, truncation: true, recursion_desired: false,
    recursion_available: true, response_code: ResponseCode::NXDomain,
    query_count: 0x8877, answer_count: 0x6655, name_server_count: 0x4433, additional_count: 0x2211};

  let expect: Vec<u8> = vec![0x01, 0x10,
                             0xAA, 0x83, // 0b1010 1010 1000 0011
                             0x88, 0x77,
                             0x66, 0x55,
                             0x44, 0x33,
                             0x22, 0x11];

  let mut got: Vec<u8> = Vec::with_capacity(expect.len());
  header.write_to(&mut got);

  assert_eq!(got, expect);
}
