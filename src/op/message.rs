use super::header::Header;
use super::query::Query;
use super::super::rr::resource::Record;

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
pub struct Message {
  header: Header, queries: Vec<Query>, answers: Vec<Record>, name_servers: Vec<Record>, additionals: Vec<Record>
}

impl Message {
  pub fn parse(data: &mut Vec<u8>) -> Self {
    let header = Header::parse(data);

    // get the questions
    let count = header.getQueryCount() as usize;
    let mut queries = Vec::with_capacity(count);
    for _ in 0 .. count {
      queries.push(Query::parse(data));
    }

    // get all counts before header moves
    let answer_count = header.getAnswerCount() as usize;
    let name_server_count = header.getNameServerCount() as usize;
    let additional_count = header.getAdditionalCount() as usize;

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
    self.header.write_to(buf);

    assert_eq!(self.header.getQueryCount() as usize, self.queries.len());
    assert_eq!(self.header.getAnswerCount() as usize, self.answers.len());
    assert_eq!(self.header.getNameServerCount() as usize, self.name_servers.len());
    assert_eq!(self.header.getAdditionalCount() as usize, self.additionals.len());

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
