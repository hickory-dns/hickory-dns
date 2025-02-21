// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::proto::{
    ProtoError, ProtoErrorKind,
    op::{
        Edns, Header, LowerQuery, Message, MessageType, OpCode, ResponseCode,
        message::{self, EmitAndCount},
    },
    rr::Record,
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};

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
    /// Return the request header
    pub fn header(&self) -> &Header {
        &self.header
    }

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
        self.header.response_code()
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
        if max_size < 512 { 512 } else { max_size }
    }

    /// # Return value
    ///
    /// the version as defined in the EDNS record
    pub fn version(&self) -> u8 {
        self.edns.as_ref().map_or(0, Edns::version)
    }

    /// Returns the original queries received from the client
    pub(crate) fn raw_queries(&self) -> &Queries {
        &self.queries
    }
}

impl<'q> BinDecodable<'q> for MessageRequest {
    // TODO: generify this with Message?
    /// Reads a MessageRequest from the decoder
    fn read(decoder: &mut BinDecoder<'q>) -> Result<Self, ProtoError> {
        let mut header = Header::read(decoder)?;

        let mut try_parse_rest = move || {
            // get all counts before header moves
            let query_count = header.query_count() as usize;
            let answer_count = header.answer_count() as usize;
            let name_server_count = header.name_server_count() as usize;
            let additional_count = header.additional_count() as usize;

            let queries = Queries::read(decoder, query_count)?;
            let (answers, _, _) = Message::read_records(decoder, answer_count, false)?;
            let (name_servers, _, _) = Message::read_records(decoder, name_server_count, false)?;
            let (additionals, edns, sig0) = Message::read_records(decoder, additional_count, true)?;

            // need to grab error code from EDNS (which might have a higher value)
            if let Some(edns) = &edns {
                let high_response_code = edns.rcode_high();
                header.merge_response_code(high_response_code);
            }

            Ok(Self {
                header,
                queries,
                answers,
                name_servers,
                additionals,
                sig0,
                edns,
            })
        };

        match try_parse_rest() {
            Ok(message) => Ok(message),
            Err(e) => Err(ProtoErrorKind::FormError {
                header,
                error: Box::new(e),
            }
            .into()),
        }
    }
}

/// A set of Queries with the associated serialized data
#[derive(Debug, PartialEq, Eq)]
pub struct Queries {
    queries: Vec<LowerQuery>,
    original: Box<[u8]>,
}

impl Queries {
    fn read_queries(
        decoder: &mut BinDecoder<'_>,
        count: usize,
    ) -> Result<Vec<LowerQuery>, ProtoError> {
        let mut queries = Vec::with_capacity(count);
        for _ in 0..count {
            queries.push(LowerQuery::read(decoder)?);
        }
        Ok(queries)
    }

    /// Read queries from a decoder
    pub fn read(decoder: &mut BinDecoder<'_>, num_queries: usize) -> Result<Self, ProtoError> {
        let queries_start = decoder.index();
        let queries = Self::read_queries(decoder, num_queries)?;
        let original = decoder
            .slice_from(queries_start)?
            .to_vec()
            .into_boxed_slice();

        Ok(Self { queries, original })
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

    pub(crate) fn as_emit_and_count(&self) -> QueriesEmitAndCount<'_> {
        QueriesEmitAndCount {
            length: self.queries.len(),
            // We don't generally support more than one query, but this will at least give us one
            // cache entry.
            first_query: self.queries.first(),
            cached_serialized: self.original.as_ref(),
        }
    }

    /// Validate that this set of Queries contains exactly one Query, and return a reference to the
    /// `LowerQuery` if so.
    pub(crate) fn try_as_query(&self) -> Result<&LowerQuery, ProtoError> {
        let count = self.queries.len();
        if count != 1 {
            return Err(ProtoErrorKind::BadQueryCount(count).into());
        }
        Ok(&self.queries[0])
    }

    /// Construct an empty set of queries
    pub(crate) fn empty() -> Self {
        Self {
            queries: Vec::new(),
            original: (*b"").into(),
        }
    }
}

pub(crate) struct QueriesEmitAndCount<'q> {
    /// Number of queries in this segment
    length: usize,
    /// Use the first query, if it exists, to pre-populate the string compression cache
    first_query: Option<&'q LowerQuery>,
    /// The cached rendering of the original (wire-format) queries
    cached_serialized: &'q [u8],
}

impl EmitAndCount for QueriesEmitAndCount<'_> {
    fn emit(&mut self, encoder: &mut BinEncoder<'_>) -> Result<usize, ProtoError> {
        let original_offset = encoder.offset();
        encoder.emit_vec(self.cached_serialized)?;
        if !encoder.is_canonical_names() && self.first_query.is_some() {
            encoder.store_label_pointer(
                original_offset,
                original_offset + self.cached_serialized.len(),
            )
        }
        Ok(self.length)
    }
}

impl BinEncodable for MessageRequest {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> Result<(), ProtoError> {
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
        )?;

        Ok(())
    }
}

/// A type which represents an MessageRequest for dynamic Update.
pub trait UpdateRequest {
    /// Id of the Message
    fn id(&self) -> u16;

    /// Zone being updated, this should be the query of a Message
    fn zone(&self) -> Result<&LowerQuery, ProtoError>;

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
        Self::id(self)
    }

    fn zone(&self) -> Result<&LowerQuery, ProtoError> {
        // RFC 2136 says "the Zone Section is allowed to contain exactly one record."
        self.raw_queries().try_as_query()
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
