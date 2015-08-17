use super::header::Header;
use super::query::Query;

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
  header: Header, queries: Vec<Query>, /*answer: Answer, authority: domain::Name, additional: Additional*/
}

impl Message {
  pub fn parse(data: &mut Vec<u8>) -> Self {
    let header = Header::parse(data);

    // get the questions
    let count: usize = header.getQueryCount() as usize;
    let mut queries = Vec::with_capacity(count);
    for _ in 0 .. count {
      queries.push(Query::parse(data));
    }

    // get the answers
    // let count: usize = header.getAnswerCount() as usize;
    // let mut answers = Vec::with_capacity(count);
    // for _ in 0 .. count {
    //   answers.push(Answer)
    // }

    Message { header: header, queries: queries}
  }
}
