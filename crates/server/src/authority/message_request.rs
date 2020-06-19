// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use proto::error::*;
use proto::op::message::EmitAndCount;
use proto::op::{message, Edns, Header, Message, MessageType, OpCode, ResponseCode};
use proto::rr::Record;
use proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};
use trust_dns_client::op::LowerQuery;

/// A Message which captures the data from an inbound request
#[derive(Debug, PartialEq)]
pub struct MessageRequest {
    header: Header,
    queries: Queries,
    answers: Vec<Record>,
    name_servers: Vec<Record>,
    additionals: Vec<Record>,
    sig0: Vec<Record>,
    edns: Option<Edns>,
}

impl MessageRequest {
    /// see `Header::id()`
    pub fn id(&self) -> u16 {
        self.header.id()
    }

    /// see `Header::message_type()`
    pub fn message_type(&self) -> MessageType {
        self.header.message_type()
    }

    /// see `Header::op_code()`
    pub fn op_code(&self) -> OpCode {
        self.header.op_code()
    }

    /// see `Header::authoritative()`
    pub fn authoritative(&self) -> bool {
        self.header.authoritative()
    }

    /// see `Header::truncated()`
    pub fn truncated(&self) -> bool {
        self.header.truncated()
    }

    /// see `Header::recursion_desired()`
    pub fn recursion_desired(&self) -> bool {
        self.header.recursion_desired()
    }

    /// see `Header::recursion_available()`
    pub fn recursion_available(&self) -> bool {
        self.header.recursion_available()
    }

    /// see `Header::authentic_data()`
    pub fn authentic_data(&self) -> bool {
        self.header.authentic_data()
    }

    /// see `Header::checking_disabled()`
    pub fn checking_disabled(&self) -> bool {
        self.header.checking_disabled()
    }

    /// # Return value
    ///
    /// The `ResponseCode`, if this is an EDNS message then this will join the section from the OPT
    ///  record to create the EDNS `ResponseCode`
    pub fn response_code(&self) -> ResponseCode {
        ResponseCode::from(
            self.edns.as_ref().map_or(0, Edns::rcode_high),
            self.header.response_code(),
        )
    }

    /// ```text
    /// Question        Carries the query name and other query parameters.
    /// ```
    pub fn queries(&self) -> &[LowerQuery] {
        &self.queries.queries
    }

    /// ```text
    /// Answer          Carries RRs which directly answer the query.
    /// ```
    pub fn answers(&self) -> &[Record] {
        &self.answers
    }

    /// ```text
    /// Authority       Carries RRs which describe other authoritative servers.
    ///                 May optionally carry the SOA RR for the authoritative
    ///                 data in the answer section.
    /// ```
    pub fn name_servers(&self) -> &[Record] {
        &self.name_servers
    }

    /// ```text
    /// Additional      Carries RRs which may be helpful in using the RRs in the
    ///                 other sections.
    /// ```
    pub fn additionals(&self) -> &[Record] {
        &self.additionals
    }

    /// [RFC 6891, EDNS(0) Extensions, April 2013](https://tools.ietf.org/html/rfc6891#section-6.1.1)
    ///
    /// ```text
    /// 6.1.1.  Basic Elements
    ///
    ///  An OPT pseudo-RR (sometimes called a meta-RR) MAY be added to the
    ///  additional data section of a request.
    ///
    ///  The OPT RR has RR type 41.
    ///
    ///  If an OPT record is present in a received request, compliant
    ///  responders MUST include an OPT record in their respective responses.
    ///
    ///  An OPT record does not carry any DNS data.  It is used only to
    ///  contain control information pertaining to the question-and-answer
    ///  sequence of a specific transaction.  OPT RRs MUST NOT be cached,
    ///  forwarded, or stored in or loaded from zone files.
    ///
    ///  The OPT RR MAY be placed anywhere within the additional data section.
    ///  When an OPT RR is included within any DNS message, it MUST be the
    ///  only OPT RR in that message.  If a query message with more than one
    ///  OPT RR is received, a FORMERR (RCODE=1) MUST be returned.  The
    ///  placement flexibility for the OPT RR does not override the need for
    ///  the TSIG or SIG(0) RRs to be the last in the additional section
    ///  whenever they are present.
    /// ```
    /// # Return value
    ///
    /// Returns the EDNS record if it was found in the additional section.
    pub fn edns(&self) -> Option<&Edns> {
        self.edns.as_ref()
    }

    /// Any SIG0 records for signed messages
    pub fn sig0(&self) -> &[Record] {
        &self.sig0
    }

    /// # Return value
    ///
    /// the max payload value as it's defined in the EDNS section.
    pub fn max_payload(&self) -> u16 {
        let max_size = self.edns.as_ref().map_or(512, Edns::max_payload);
        if max_size < 512 {
            512
        } else {
            max_size
        }
    }

    /// # Return value
    ///
    /// the version as defined in the EDNS record
    pub fn version(&self) -> u8 {
        self.edns.as_ref().map_or(0, Edns::version)
    }

    /// Returns the queries passed received from the client
    pub fn raw_queries(&self) -> &Queries {
        &self.queries
    }
}

impl<'q> BinDecodable<'q> for MessageRequest {
    // TODO: generify this with Message?
    /// Reads a MessageRequest from the decoder
    fn read(decoder: &mut BinDecoder<'q>) -> ProtoResult<Self> {
        let header = Header::read(decoder)?;

        // TODO: return just header, and in the case of the rest of message getting an error.
        //  this could improve error detection while decoding.

        // get the questions

        // get all counts before header moves
        let query_count = header.query_count() as usize;
        let answer_count = header.answer_count() as usize;
        let name_server_count = header.name_server_count() as usize;
        let additional_count = header.additional_count() as usize;

        let queries = Queries::read(decoder, query_count)?;
        let (answers, _, _) = Message::read_records(decoder, answer_count, false)?;
        let (name_servers, _, _) = Message::read_records(decoder, name_server_count, false)?;
        let (additionals, edns, sig0) = Message::read_records(decoder, additional_count, true)?;

        Ok(MessageRequest {
            header,
            queries,
            answers,
            name_servers,
            additionals,
            sig0,
            edns,
        })
    }
}

/// A set of Queries with the associated serialized data
#[derive(Debug, PartialEq)]
pub struct Queries {
    queries: Vec<LowerQuery>,
    original: Box<[u8]>,
}

impl Queries {
    fn read_queries(decoder: &mut BinDecoder, count: usize) -> ProtoResult<Vec<LowerQuery>> {
        let mut queries = Vec::with_capacity(count);
        for _ in 0..count {
            queries.push(LowerQuery::read(decoder)?);
        }
        Ok(queries)
    }

    /// Read queries from a decoder
    pub fn read(decoder: &mut BinDecoder, num_queries: usize) -> ProtoResult<Self> {
        let queries_start = decoder.index();
        let queries = Self::read_queries(decoder, num_queries)?;
        let original = decoder
            .slice_from(queries_start)?
            .to_vec()
            .into_boxed_slice();

        Ok(Queries { queries, original })
    }

    /// return the number of queries in the request
    pub fn len(&self) -> usize {
        self.queries.len()
    }

    /// Returns true if there are no queries
    pub fn is_empty(&self) -> bool {
        self.queries.is_empty()
    }

    /// returns the bytes as they were seen from the Client
    pub fn as_bytes(&self) -> &[u8] {
        self.original.as_ref()
    }

    pub(crate) fn as_emit_and_count(&self) -> QueriesEmitAndCount {
        QueriesEmitAndCount {
            length: self.queries.len(),
            original: self.original.as_ref(),
        }
    }
}

pub(crate) struct QueriesEmitAndCount<'q> {
    length: usize,
    original: &'q [u8],
}

impl<'q> EmitAndCount for QueriesEmitAndCount<'q> {
    fn emit(&mut self, encoder: &mut BinEncoder) -> ProtoResult<usize> {
        encoder.emit_vec(self.original)?;
        Ok(self.length)
    }
}

impl BinEncodable for MessageRequest {
    fn emit(&self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        message::emit_message_parts(
            &self.header,
            // we emit the queries, not the raw bytes, in order to guarantee canonical form
            //   in cases where that's necessary, like SIG0 validation
            &mut self.queries.queries.iter(),
            &mut self.answers.iter(),
            &mut self.name_servers.iter(),
            &mut self.additionals.iter(),
            self.edns.as_ref(),
            &self.sig0,
            encoder,
        )
    }
}

/// A type which represents an MessageRequest for dynamic Update.
pub trait UpdateRequest {
    /// Id of the Message
    fn id(&self) -> u16;

    /// Zones being updated, this should be the queries of a Message
    fn zones(&self) -> &[LowerQuery];

    /// Prerequisites map to the answers of a Message
    fn prerequisites(&self) -> &[Record];

    /// Records to update map to the name_servers of a Message
    fn updates(&self) -> &[Record];

    /// Additional records
    fn additionals(&self) -> &[Record];

    /// SIG0 records for verifying the Message
    fn sig0(&self) -> &[Record];
}

impl UpdateRequest for MessageRequest {
    fn id(&self) -> u16 {
        MessageRequest::id(self)
    }

    fn zones(&self) -> &[LowerQuery] {
        self.queries()
    }

    fn prerequisites(&self) -> &[Record] {
        self.answers()
    }

    fn updates(&self) -> &[Record] {
        self.name_servers()
    }

    fn additionals(&self) -> &[Record] {
        self.additionals()
    }

    fn sig0(&self) -> &[Record] {
        self.sig0()
    }
}
