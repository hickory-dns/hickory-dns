use super::header::{MessageType, Header};
use super::query::Query;
use super::super::rr::resource::Record;
use super::op_code::OpCode;
use super::response_code::ResponseCode;
use super::super::rr::domain::Name;

/*
 * RFC 1035        Domain Implementation and Specification    November 1987
 *
 * 4.1. Format
 *
 * All communications inside of the domain protocol are carried in a single
 * format called a message.  The top level format of message is divided
 * into 5 sections (some of which are empty in certain cases) shown below:
 *
 *     +---------------------+
 *     |        Header       |
 *     +---------------------+
 *     |       Question      | the question for the name server
 *     +---------------------+
 *     |        Answer       | RRs answering the question
 *     +---------------------+
 *     |      Authority      | RRs pointing toward an authority
 *     +---------------------+
 *     |      Additional     | RRs holding additional information
 *     +---------------------+
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
  pub fn add_name_server(&mut self, record: Record) -> &mut Self { self.name_servers.push(record); self }
  pub fn add_additional(&mut self, record: Record) -> &mut Self { self.additionals.push(record); self }

  pub fn get_id(&self) -> u16 { self.header.get_id() }
  pub fn get_message_type(&self) -> MessageType { self.header.get_message_type() }
  pub fn get_op_code(&self) -> OpCode { self.header.get_op_code() }
  pub fn is_authoritative(&self) -> bool { self.header.is_authoritative() }
  pub fn is_truncated(&self) -> bool { self.header.is_truncated() }
  pub fn is_recursion_desired(&self) -> bool { self.header.is_recursion_desired() }
  pub fn is_recursion_available(&self) -> bool { self.header.is_recursion_available() }
  pub fn get_response_code(&self) -> ResponseCode { self.header.get_response_code() }
  pub fn get_queries(&self) -> &Vec<Query> { &self.queries }
  pub fn get_answers(&self) -> &Vec<Record> { &self.answers }
  pub fn get_name_servers(&self) -> &Vec<Record> { &self.name_servers }
  pub fn get_additional(&self) -> &Vec<Record> { &self.additionals }


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

  pub fn parse(data: &mut Vec<u8>) -> Self {
    let header = Header::parse(data);

    // get the questions
    let count = header.get_query_count() as usize;
    let mut queries = Vec::with_capacity(count);
    for _ in 0 .. count {
      queries.push(Query::parse(data));
    }

    // get all counts before header moves
    let answer_count = header.get_answer_count() as usize;
    let name_server_count = header.get_name_server_count() as usize;
    let additional_count = header.get_additional_count() as usize;

    Message {
      header: header,
      queries: queries,
      answers: Self::parse_records(data, answer_count),
      name_servers: Self::parse_records(data, name_server_count),
      additionals: Self::parse_records(data, additional_count),
    }
  }

  fn parse_records(data: &mut Vec<u8>, count: usize) -> Vec<Record> {
    let mut records: Vec<Record> = Vec::with_capacity(count);
    for _ in 0 .. count {
       records.push(Record::parse(data))
    }
    records
  }

  pub fn write_to(&self, buf: &mut Vec<u8>) {
    // clone the header to set the counts lazily
    self.update_header_counts().write_to(buf);

    for q in &self.queries {
      q.write_to(buf);
    }

    Self::write_records(buf, &self.answers);
    Self::write_records(buf, &self.name_servers);
    Self::write_records(buf, &self.additionals);
  }

  fn write_records(buf: &mut Vec<u8>, records: &Vec<Record>) {
    for r in records {
      r.write_to(buf);
    }
  }
}

#[test]
fn test_write_and_parse_header() {
  let mut message = Message::new();
  message.id(10).message_type(MessageType::Response).op_code(OpCode::Update).
    authoritative(true).truncated(true).recursion_desired(true).recursion_available(true).
    response_code(ResponseCode::ServFail);

  let mut buf: Vec<u8> = Vec::new();
  message.write_to(&mut buf);

  buf.reverse();
  let got = Message::parse(&mut buf);

  assert_eq!(got, message);
}

#[test]
fn test_write_and_parse_query() {
  let mut message = Message::new();
  message.id(10).message_type(MessageType::Response).op_code(OpCode::Update).
    authoritative(true).truncated(true).recursion_desired(true).recursion_available(true).
    response_code(ResponseCode::ServFail).add_query(Query::new()).update_counts(); // we're not testing the query parsing, just message

  let mut buf: Vec<u8> = Vec::new();
  message.write_to(&mut buf);

  buf.reverse();
  let got = Message::parse(&mut buf);

  assert_eq!(got, message);
}

#[test]
fn test_write_and_parse_records() {
  let mut message = Message::new();
  message.id(10).message_type(MessageType::Response).op_code(OpCode::Update).
    authoritative(true).truncated(true).recursion_desired(true).recursion_available(true).
    response_code(ResponseCode::ServFail);

  message.add_answer(Record::new());
  //message.add_name_server(Record::new());
  //message.add_additional(Record::new());
  message.update_counts(); // needed for the comparison...

  let mut buf: Vec<u8> = Vec::new();
  message.write_to(&mut buf);

  buf.reverse();
  let got = Message::parse(&mut buf);

  assert_eq!(got, message);
}
