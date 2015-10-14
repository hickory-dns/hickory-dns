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

use super::header::{MessageType, Header};
use super::query::Query;
use ::rr::resource::Record;
use super::op_code::OpCode;
use super::response_code::ResponseCode;
use ::serialize::binary::*;
use ::error::*;


/*
 * RFC 1035        Domain Implementation and Specification    November 1987
 *
 * 4.1. Format
 *
 * All communications inside of the domain protocol are carried in a single
 * format called a message.  The top level format of message is divided
 * into 5 sections (some of which are empty in certain cases) shown below:
 *
 *     +--------------------------+
 *     |        Header            |
 *     +--------------------------+
 *     |  Question / Zone         | the question for the name server
 *     +--------------------------+
 *     |   Answer  / Prerequisite | RRs answering the question
 *     +--------------------------+
 *     | Authority / Update       | RRs pointing toward an authority
 *     +--------------------------+
 *     |      Additional          | RRs holding additional information
 *     +--------------------------+
 *
 * The header section is always present.  The header includes fields that
 * specify which of the remaining sections are present, and also specify
 * whether the message is a query or a response, a standard query or some
 * other opcode, etc.
 *
 * The names of the sections after the header are derived from their use in
 * standard queries.  The question section contains fields that describe a
 * question to a name server.  These fields are a query type (QTYPE), a
 * query class (QCLASS), and a query domain name (QNAME).  The last three
 * sections have the same format: a possibly empty list of concatenated
 * resource records (RRs).  The answer section contains RRs that answer the
 * question; the authority section contains RRs that point toward an
 * authoritative name server; the additional records section contains RRs
 * which relate to the query, but are not strictly answers for the
 * question.
 */

/// By default Message is a Query. Use the Message::as_update() to create and update, or
///  Message::new_update()
#[derive(Debug, PartialEq)]
pub struct Message {
  header: Header, queries: Vec<Query>, answers: Vec<Record>, name_servers: Vec<Record>, additionals: Vec<Record>
}

impl Message {
  pub fn new() -> Self {
    Message { header: Header::new(), queries: Vec::new(), answers: Vec::new(), name_servers: Vec::new(), additionals: Vec::new() }
  }

  pub fn id(&mut self, id: u16) -> &mut Self { self.header.id(id); self }
  pub fn message_type(&mut self, message_type: MessageType) -> &mut Self { self.header.message_type(message_type); self }
  pub fn op_code(&mut self, op_code: OpCode) -> &mut Self { self.header.op_code(op_code); self }
  pub fn authoritative(&mut self, authoritative: bool) -> &mut Self { self.header.authoritative(authoritative); self }
  pub fn truncated(&mut self, truncated: bool) -> &mut Self { self.header.truncated(truncated); self }
  pub fn recursion_desired(&mut self, recursion_desired: bool) -> &mut Self { self.header.recursion_desired(recursion_desired); self }
  pub fn recursion_available(&mut self, recursion_available: bool) -> &mut Self {self.header.recursion_available(recursion_available); self }
  pub fn response_code(&mut self, response_code: ResponseCode) -> &mut Self { self.header.response_code(response_code); self }
  pub fn add_query(&mut self, query: Query) -> &mut Self { self.queries.push(query); self }
  pub fn add_answer(&mut self, record: Record) -> &mut Self { self.answers.push(record); self }
  pub fn add_all_answers(&mut self, vector: &[Record]) -> &mut Self {
    for r in vector {
      // TODO: in order to get rid of this clone, we need an owned Message for decoding, and a
      //  reference Message for encoding.
      self.add_answer(r.clone());
    }
    self
  }
  pub fn add_name_server(&mut self, record: Record) -> &mut Self { self.name_servers.push(record); self }
  pub fn add_all_name_servers(&mut self, vector: &[Record]) -> &mut Self {
    for r in vector {
      // TODO: in order to get rid of this clone, we need an owned Message for decoding, and a
      //  reference Message for encoding.
      self.add_name_server(r.clone());
    }
    self
  }
  pub fn add_additional(&mut self, record: Record) -> &mut Self { self.additionals.push(record); self }

  pub fn get_id(&self) -> u16 { self.header.get_id() }
  pub fn get_message_type(&self) -> MessageType { self.header.get_message_type() }
  pub fn get_op_code(&self) -> OpCode { self.header.get_op_code() }
  pub fn is_authoritative(&self) -> bool { self.header.is_authoritative() }
  pub fn is_truncated(&self) -> bool { self.header.is_truncated() }
  pub fn is_recursion_desired(&self) -> bool { self.header.is_recursion_desired() }
  pub fn is_recursion_available(&self) -> bool { self.header.is_recursion_available() }
  pub fn get_response_code(&self) -> ResponseCode { self.header.get_response_code() }
  pub fn get_queries(&self) -> &[Query] { &self.queries }
  pub fn get_answers(&self) -> &[Record] { &self.answers }
  pub fn get_name_servers(&self) -> &[Record] { &self.name_servers }
  pub fn get_additional(&self) -> &[Record] { &self.additionals }


  /// this is necessary to match the counts in the header from the record sections
  ///  this happens implicitly on write_to, so no need to call before write_to
  pub fn update_counts(&mut self) -> &mut Self {
    self.header = self.update_header_counts();
    self
  }

  fn update_header_counts(&self) -> Header {
    assert!(self.queries.len() <= u16::max_value() as usize);
    assert!(self.answers.len() <= u16::max_value() as usize);
    assert!(self.name_servers.len() <= u16::max_value() as usize);
    assert!(self.additionals.len() <= u16::max_value() as usize);

    self.header.clone(
      self.queries.len() as u16,
      self.answers.len() as u16,
      self.name_servers.len() as u16,
      self.additionals.len() as u16)
  }

  fn read_records(decoder: &mut BinDecoder, count: usize) -> DecodeResult<Vec<Record>> {
    let mut records: Vec<Record> = Vec::with_capacity(count);
    for _ in 0 .. count {
       records.push(try!(Record::read(decoder)))
    }
    Ok(records)
  }

  fn emit_records(encoder: &mut BinEncoder, records: &Vec<Record>) -> EncodeResult {
    for r in records {
      try!(r.emit(encoder));
    }
    Ok(())
  }
}

pub trait UpdateMessage {
  fn add_zone(&mut self, query: Query);
  fn add_pre_requisite(&mut self, record: Record);
  fn add_all_pre_requisites(&mut self, vector: &[Record]);
  fn add_update(&mut self, record: Record);
  fn add_all_updates(&mut self, vector: &[Record]);
  fn add_additional(&mut self, record: Record);

  fn get_zones(&self) -> &[Query];
  fn get_pre_requisites(&self) -> &[Record];
  fn get_updates(&self) -> &[Record];
  fn get_additional(&self) -> &[Record];
}

/// to reduce errors in using the Message struct as an Update, this will do the call throughs
///   to properly do that.
impl UpdateMessage for Message {
  fn add_zone(&mut self, query: Query) { self.add_query(query); }
  fn add_pre_requisite(&mut self, record: Record) { self.add_answer(record); }
  fn add_all_pre_requisites(&mut self, vector: &[Record]) { self.add_all_answers(vector); }
  fn add_update(&mut self, record: Record) { self.add_name_server(record); }
  fn add_all_updates(&mut self, vector: &[Record]) { self.add_all_name_servers(vector); }
  fn add_additional(&mut self, record: Record) { self.add_additional(record); }

  fn get_zones(&self) -> &[Query] { self.get_queries() }
  fn get_pre_requisites(&self) -> &[Record] { self.get_answers() }
  fn get_updates(&self) -> &[Record] { self.get_name_servers() }
  fn get_additional(&self) -> &[Record] { self.get_additional() }
}

impl BinSerializable for Message {
  fn read(decoder: &mut BinDecoder) -> DecodeResult<Self> {
    let header = try!(Header::read(decoder));

    // get the questions
    let count = header.get_query_count() as usize;
    let mut queries = Vec::with_capacity(count);
    for _ in 0 .. count {
      queries.push(try!(Query::read(decoder)));
    }

    // get all counts before header moves
    let answer_count = header.get_answer_count() as usize;
    let name_server_count = header.get_name_server_count() as usize;
    let additional_count = header.get_additional_count() as usize;

    Ok(Message {
      header: header,
      queries: queries,
      answers: try!(Self::read_records(decoder, answer_count)),
      name_servers: try!(Self::read_records(decoder, name_server_count)),
      additionals: try!(Self::read_records(decoder, additional_count)),
    })
  }

  fn emit(&self, encoder: &mut BinEncoder) -> EncodeResult {
    // clone the header to set the counts lazily
    try!(self.update_header_counts().emit(encoder));

    for q in &self.queries {
      try!(q.emit(encoder));
    }

    try!(Self::emit_records(encoder, &self.answers));
    try!(Self::emit_records(encoder, &self.name_servers));
    try!(Self::emit_records(encoder, &self.additionals));
    Ok(())
  }
}

#[test]
fn test_emit_and_read_header() {
  let mut message = Message::new();
  message.id(10).message_type(MessageType::Response).op_code(OpCode::Update).
    authoritative(true).truncated(true).recursion_desired(true).recursion_available(true).
    response_code(ResponseCode::ServFail);

  test_emit_and_read(message);
}

#[test]
fn test_emit_and_read_query() {
  let mut message = Message::new();
  message.id(10).message_type(MessageType::Response).op_code(OpCode::Update).
    authoritative(true).truncated(true).recursion_desired(true).recursion_available(true).
    response_code(ResponseCode::ServFail).add_query(Query::new()).update_counts(); // we're not testing the query parsing, just message

  test_emit_and_read(message);
}

#[test]
fn test_emit_and_read_records() {
  let mut message = Message::new();
  message.id(10).message_type(MessageType::Response).op_code(OpCode::Update).
    authoritative(true).truncated(true).recursion_desired(true).recursion_available(true).
    response_code(ResponseCode::ServFail);

  message.add_answer(Record::new());
  message.add_name_server(Record::new());
  message.add_additional(Record::new());
  message.update_counts(); // needed for the comparison...

  test_emit_and_read(message);
}

#[cfg(test)]
fn test_emit_and_read(message: Message) {
  let mut encoder = BinEncoder::new();
  message.emit(&mut encoder).unwrap();

  let byte_vec = encoder.as_bytes();

  let mut decoder = BinDecoder::new(&byte_vec);
  let got = Message::read(&mut decoder).unwrap();

  assert_eq!(got, message);
}

#[test]
fn test_legit_message() {
  let buf: Vec<u8> = vec![
  0x10,0x00,0x81,0x80, // id = 4096, response, op=query, recursion_desired, recursion_available, no_error
  0x00,0x01,0x00,0x01, // 1 query, 1 answer,
  0x00,0x00,0x00,0x00, // 0 namesservers, 0 additional record

  0x03,b'w',b'w',b'w', // query --- www.example.com
  0x07,b'e',b'x',b'a', //
  b'm',b'p',b'l',b'e', //
  0x03,b'c',b'o',b'm', //
  0x00,                // 0 = endname
  0x00,0x01,0x00,0x01, // ReordType = A, Class = IN

  0xC0,0x0C,           // name pointer to www.example.com
  0x00,0x01,0x00,0x01, // RecordType = A, Class = IN
  0x00,0x00,0x00,0x02, // TTL = 2 seconds
  0x00,0x04,           // record length = 4 (ipv4 address)
  0x5D,0xB8,0xD8,0x22, // address = 93.184.216.34
  ];

  let mut decoder = BinDecoder::new(&buf);
  let message = Message::read(&mut decoder).unwrap();

  assert_eq!(message.get_id(), 4096);

  let mut encoder = BinEncoder::new();
  message.emit(&mut encoder).unwrap();

  let buf = encoder.as_bytes();
  let mut decoder = BinDecoder::new(&buf);
  let message = Message::read(&mut decoder).unwrap();

  assert_eq!(message.get_id(), 4096);
}
