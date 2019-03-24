// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use proto::error::*;
use proto::op::message::EmitAndCount;
use proto::op::{message, Edns, Header, MessageType, OpCode, ResponseCode};
use trust_dns::rr::Record;
use trust_dns::serialize::binary::BinEncoder;

use authority::message_request::QueriesEmitAndCount;
use authority::Queries;

/// A EncodableMessage with borrowed data for Responses in the Server
#[derive(Debug)]
pub struct MessageResponse<
    'q,
    'a,
    A = Box<dyn Iterator<Item = &'a Record> + Send + 'a>,
    N = Box<dyn Iterator<Item = &'a Record> + Send + 'a>,
    S = Box<dyn Iterator<Item = &'a Record> + Send + 'a>,
> where
    A: Iterator<Item = &'a Record> + Send + 'a,
    N: Iterator<Item = &'a Record> + Send + 'a,
    S: Iterator<Item = &'a Record> + Send + 'a,
{
    header: Header,
    queries: Option<&'q Queries<'q>>,
    answers: A,
    name_servers: N,
    soa: S,
    additionals: Vec<&'a Record>,
    sig0: Vec<Record>,
    edns: Option<Edns>,
}

enum EmptyOrQueries<'q> {
    Empty,
    Queries(QueriesEmitAndCount<'q>),
}

impl<'q> From<Option<&'q Queries<'q>>> for EmptyOrQueries<'q> {
    fn from(option: Option<&'q Queries<'q>>) -> Self {
        option.map_or(EmptyOrQueries::Empty, |q| {
            EmptyOrQueries::Queries(q.as_emit_and_count())
        })
    }
}

impl<'q> EmitAndCount for EmptyOrQueries<'q> {
    fn emit(&mut self, encoder: &mut BinEncoder) -> ProtoResult<usize> {
        match self {
            EmptyOrQueries::Empty => Ok(0),
            EmptyOrQueries::Queries(q) => q.emit(encoder),
        }
    }
}

impl<'q, 'a, A, N, S> MessageResponse<'q, 'a, A, N, S>
where
    A: Iterator<Item = &'a Record> + Send + 'a,
    N: Iterator<Item = &'a Record> + Send + 'a,
    S: Iterator<Item = &'a Record> + Send + 'a,
{
    /// Returns the header of the message
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Set the EDNS options for the Response
    pub fn set_edns(&mut self, edns: Edns) -> &mut Self {
        self.edns = Some(edns);
        self
    }

    /// Consumes self, and emits to the encoder.
    pub fn destructive_emit(mut self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        // soa records are part of the nameserver section
        let mut name_servers = self.name_servers.chain(self.soa);

        message::emit_message_parts(
            &self.header,
            &mut EmptyOrQueries::from(self.queries),
            &mut self.answers,
            &mut name_servers,
            &mut self.additionals.iter().cloned(),
            self.edns.as_ref(),
            &self.sig0,
            encoder,
        )
    }
}

/// A builder for MessageResponses
pub struct MessageResponseBuilder<'q> {
    queries: Option<&'q Queries<'q>>,
    sig0: Option<Vec<Record>>,
    edns: Option<Edns>,
}

impl<'q> MessageResponseBuilder<'q> {
    /// Constructs a new Response
    ///
    /// # Arguments
    ///
    /// * `queries` - any optional set of Queries to associate with the Response
    pub fn new(queries: Option<&'q Queries<'q>>) -> MessageResponseBuilder<'q> {
        MessageResponseBuilder {
            queries,
            sig0: None,
            edns: None,
        }
    }

    /// Associate EDNS with the Response
    pub fn edns(&mut self, edns: Edns) -> &mut Self {
        self.edns = Some(edns);
        self
    }

    /// Constructs the new MessageResponse with associated Header
    ///
    /// # Arguments
    ///
    /// * `header` - set of [Header]s for the Message
    pub fn build<'a, A, N, S>(
        self,
        header: Header,
        answers: A,
        name_servers: N,
        soa: S,
    ) -> MessageResponse<'q, 'a, A::IntoIter, N::IntoIter, S::IntoIter>
    where
        A: IntoIterator<Item = &'a Record> + Send + 'a,
        A::IntoIter: Send,
        N: IntoIterator<Item = &'a Record> + Send + 'a,
        N::IntoIter: Send,
        S: IntoIterator<Item = &'a Record> + Send + 'a,
        S::IntoIter: Send,
    {
        MessageResponse {
            header,
            queries: self.queries,
            answers: answers.into_iter(),
            name_servers: name_servers.into_iter(),
            soa: soa.into_iter(),
            additionals: Default::default(),
            sig0: self.sig0.unwrap_or_default(),
            edns: self.edns,
        }
    }

    /// Construct a Response with no associated records
    pub fn build_no_records(self, header: Header) -> MessageResponse<'q, 'q> {
        MessageResponse {
            header,
            queries: self.queries,
            answers: Box::new(None.into_iter()),
            name_servers: Box::new(None.into_iter()),
            soa: Box::new(None.into_iter()),
            additionals: Default::default(),
            sig0: self.sig0.unwrap_or_default(),
            edns: self.edns,
        }
    }

    /// Constructs a new error MessageResponse with associated settings
    ///
    /// # Arguments
    ///
    /// * `id` - request id to which this is a response
    /// * `op_code` - operation for which this is a response
    /// * `response_code` - the type of error
    pub fn error_msg(
        self,
        id: u16,
        op_code: OpCode,
        response_code: ResponseCode,
    ) -> MessageResponse<'q, 'q> {
        let mut header = Header::default();
        header.set_message_type(MessageType::Response);
        header.set_id(id);
        header.set_response_code(response_code);
        header.set_op_code(op_code);

        MessageResponse {
            header,
            queries: self.queries,
            answers: Box::new(None.into_iter()),
            name_servers: Box::new(None.into_iter()),
            soa: Box::new(None.into_iter()),
            additionals: Default::default(),
            sig0: self.sig0.unwrap_or_default(),
            edns: self.edns,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::iter;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use proto::op::{Header, Message};
    use proto::rr::{DNSClass, Name, RData, Record};
    use proto::serialize::binary::BinEncoder;

    use super::*;

    #[test]
    fn test_truncation_ridiculous_number_answers() {
        let mut buf = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut buf);
            encoder.set_max_size(512);

            let answer = Record::new()
                .set_name(Name::from_str("www.example.com.").unwrap())
                .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 34)))
                .set_dns_class(DNSClass::NONE)
                .clone();

            let message = MessageResponse {
                header: Header::new(),
                queries: None,
                answers: iter::repeat(&answer),
                name_servers: iter::once(&answer),
                soa: iter::once(&answer),
                additionals: vec![],
                sig0: vec![],
                edns: None,
            };

            message
                .destructive_emit(&mut encoder)
                .expect("failed to encode");
        }

        let response = Message::from_vec(&buf).expect("failed to decode");
        assert!(response.header().truncated());
        assert!(response.answer_count() > 1);
        // should never have written the name server field...
        assert_eq!(response.name_server_count(), 0);
    }

    #[test]
    fn test_truncation_ridiculous_number_nameservers() {
        let mut buf = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut buf);
            encoder.set_max_size(512);

            let answer = Record::new()
                .set_name(Name::from_str("www.example.com.").unwrap())
                .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 34)))
                .set_dns_class(DNSClass::NONE)
                .clone();

            let message = MessageResponse {
                header: Header::new(),
                queries: None,
                answers: iter::empty(),
                name_servers: iter::repeat(&answer),
                soa: iter::repeat(&answer),
                additionals: vec![],
                sig0: vec![],
                edns: None,
            };

            message
                .destructive_emit(&mut encoder)
                .expect("failed to encode");
        }

        let response = Message::from_vec(&buf).expect("failed to decode");
        assert!(response.header().truncated());
        assert_eq!(response.answer_count(), 0);
        assert!(response.name_server_count() > 1);
    }
}
