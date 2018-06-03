// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::iter::Chain;

use trust_dns::rr::Record;
use trust_dns::serialize::binary::{BinEncodable, BinEncoder, EncodeMode};
use trust_dns_proto::error::*;
use trust_dns_proto::op::{message, Edns, Header, MessageType, OpCode, ResponseCode};

use authority::{AuthLookup, LookupRecords, Queries};

/// A EncodableMessage with borrowed data for Responses in the Server
#[derive(Debug)]
pub struct MessageResponse<'q, 'a> {
    header: Header,
    queries: Option<&'q Queries<'q>>,
    answers: AuthLookup<'a, 'q>,
    name_servers: Chain<LookupRecords<'q, 'a>, LookupRecords<'q, 'a>>,
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

    /// Returns the header of the message
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Set the EDNS options for the Response
    pub fn set_edns(&mut self, edns: Edns) -> &mut Self {
        self.edns = Some(edns);
        self
    }

    fn emit_queries(&self, encoder: &mut BinEncoder) -> ProtoResult<usize> {
        if let Some(queries) = self.queries {
            encoder
                .emit_vec(queries.as_bytes())
                .map(|()| self.queries.map(|s| s.len()).unwrap_or(0))
        } else {
            Ok(0)
        }
    }

    fn edns(&self) -> Option<&Edns> {
        self.edns.as_ref()
    }

    fn sig0(&self) -> &[Record] {
        &self.sig0
    }

    /// Consumes self, and emits to the encoder.
    pub fn destructive_emit(mut self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        // clone the header to set the counts lazily
        // TODO: what should we do about sig0 on the server side? It should be deprecated in favor of TLS...
        let include_sig0: bool = encoder.mode() != EncodeMode::Signing;
        let place = encoder.place::<Header>()?;

        // TODO: this feels like the right place to verify the max packet size of the message,
        //  will need to update the header for trucation and the lengths if we send less than the
        //  full response.
        let query_count = self.emit_queries(encoder)?;
        // FIXME: need to do some on max records
        //  return offset of last emitted record.
        let answer_count = message::count_was_truncated(encoder.emit_iter(&mut self.answers))?;
        let nameserver_count =
            message::count_was_truncated(encoder.emit_iter(&mut self.name_servers))?;
        let mut additional_count =
            message::count_was_truncated(encoder.emit_all_refs(self.additionals.iter()))?;

        if let Some(edns) = self.edns() {
            // need to commit the error code
            Record::from(edns).emit(encoder)?;
            additional_count.0 += 1;
        }

        // FIXME: because this is destructive, we need to move message signing here... maybe it will work?

        // this is a little hacky, but if we are Verifying a signature, i.e. the original Message
        //  then the SIG0 records should not be encoded and the edns record (if it exists) is already
        //  part of the additionals section.
        if include_sig0 {
            additional_count.0 += encoder.emit_all(self.sig0().iter())?;
        }

        let counts = message::HeaderCounts {
            query_count,
            answer_count: answer_count.0,
            nameserver_count: nameserver_count.0,
            additional_count: additional_count.0,
        };
        let was_truncated = answer_count.1 || nameserver_count.1 || additional_count.1;

        place.replace(
            encoder,
            message::update_header_counts(&self.header, was_truncated, counts),
        )?;
        Ok(())
    }
}

/// A builder for MessageResponses
pub struct MessageResponseBuilder<'q, 'a> {
    queries: Option<&'q Queries<'q>>,
    answers: Option<AuthLookup<'a, 'q>>,
    name_servers: Option<Chain<LookupRecords<'q, 'a>, LookupRecords<'q, 'a>>>,
    additionals: Option<Vec<&'a Record>>,
    sig0: Option<Vec<Record>>,
    edns: Option<Edns>,
}

impl<'q, 'a> MessageResponseBuilder<'q, 'a> {
    /// Associate a set of answers with the response, generally owned by either a cache or [`trust_dns_server::authorith::Authority`]
    pub fn answers(&mut self, records: AuthLookup<'a, 'q>) -> &mut Self {
        self.answers = Some(records);
        self
    }

    /// Associate a set of name_servers with the response, generally owned by either a cache or [`trust_dns_server::authorith::Authority`]
    pub fn name_servers(
        &mut self,
        records: Chain<LookupRecords<'q, 'a>, LookupRecords<'q, 'a>>,
    ) -> &mut Self {
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
            name_servers: self
                .name_servers
                .unwrap_or_else(|| LookupRecords::NxDomain.chain(LookupRecords::NxDomain)),
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
            name_servers: self
                .name_servers
                .unwrap_or_else(|| LookupRecords::NxDomain.chain(LookupRecords::NxDomain)),
            additionals: self.additionals.unwrap_or_default(),
            sig0: self.sig0.unwrap_or_default(),
            edns: self.edns,
        }
    }
}
