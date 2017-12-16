// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use trust_dns_proto::error::*;
use trust_dns_proto::op::EncodableMessage;
use trust_dns::op::{Edns, Header, MessageType, OpCode, ResponseCode};
use trust_dns::rr::Record;
use trust_dns::serialize::binary::BinEncoder;

use authority::Queries;

/// A EncodableMessage with borrowed data for Responses in the Server
#[derive(Debug)]
pub struct MessageResponse<'q, 'a> {
    header: Header,
    queries: Option<&'q Queries<'q>>,
    answers: Vec<&'a Record>,
    name_servers: Vec<&'a Record>,
    additionals: Vec<&'a Record>,
    sig0: Vec<Record>,
    edns: Option<Edns>,
}

impl<'q, 'a> MessageResponse<'q, 'a> {
    /// Constructs a new Response
    ///
    /// # Arguments
    ///
    /// * `queries` - any optional set of Queries to associate with the Response
    pub fn new(queries: Option<&'q Queries<'q>>) -> MessageResponseBuilder<'q, 'a> {
        MessageResponseBuilder {
            queries,
            answers: None,
            name_servers: None,
            additionals: None,
            sig0: None,
            edns: None,
        }
    }

    /// Set the EDNS options for the Response
    pub fn set_edns(&mut self, edns: Edns) -> &mut Self {
        self.edns = Some(edns);
        self
    }
}

macro_rules! section {
    ($s:ident, $l:ident, $e:ident) => {
        fn $l(&self) -> usize {
            self.$s.len()
        }

        fn $e(&self, encoder: &mut BinEncoder) -> ProtoResult<()> {
            encoder.emit_all_refs(self.$s.iter())
        }
    }
}

impl<'q, 'a> EncodableMessage for MessageResponse<'q, 'a> {
    fn header(&self) -> &Header {
        &self.header
    }

    fn queries_len(&self) -> usize {
        self.queries.map(|s| s.len()).unwrap_or(0)
    }

    fn emit_queries(&self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        if let Some(queries) = self.queries {
            encoder.emit_vec(queries.as_bytes())
        } else {
            Ok(())
        }
    }

    section!(answers, answers_len, emit_answers);
    section!(name_servers, name_servers_len, emit_name_servers);
    section!(additionals, additionals_len, emit_additionals);

    fn edns(&self) -> Option<&Edns> {
        self.edns.as_ref()
    }

    fn sig0(&self) -> &[Record] {
        &self.sig0
    }
}

/// A builder for MessageResponses
pub struct MessageResponseBuilder<'q, 'a> {
    queries: Option<&'q Queries<'q>>,
    answers: Option<Vec<&'a Record>>,
    name_servers: Option<Vec<&'a Record>>,
    additionals: Option<Vec<&'a Record>>,
    sig0: Option<Vec<Record>>,
    edns: Option<Edns>,
}

impl<'q, 'a> MessageResponseBuilder<'q, 'a> {
    /// Associate a set of answers with the response, generally owned by either a cache or [`trust_dns_server::authorith::Authority`]
    pub fn answers(&mut self, records: Vec<&'a Record>) -> &mut Self {
        self.answers = Some(records);
        self
    }

    /// Associate a set of name_servers with the response, generally owned by either a cache or [`trust_dns_server::authorith::Authority`]
    pub fn name_servers(&mut self, records: Vec<&'a Record>) -> &mut Self {
        self.name_servers = Some(records);
        self
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
    pub fn build(self, header: Header) -> MessageResponse<'q, 'a> {
        MessageResponse {
            header,
            queries: self.queries,
            answers: self.answers.unwrap_or_default(),
            name_servers: self.name_servers.unwrap_or_default(),
            additionals: self.additionals.unwrap_or_default(),
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
    ) -> MessageResponse<'q, 'a> {
        let mut header = Header::default();
        header.set_message_type(MessageType::Response);
        header.set_id(id);
        header.set_response_code(response_code);
        header.set_op_code(op_code);

        MessageResponse {
            header,
            queries: self.queries,
            answers: self.answers.unwrap_or_default(),
            name_servers: self.name_servers.unwrap_or_default(),
            additionals: self.additionals.unwrap_or_default(),
            sig0: self.sig0.unwrap_or_default(),
            edns: self.edns,
        }
    }
}
