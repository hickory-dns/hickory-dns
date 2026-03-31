// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use alloc::{boxed::Box, vec::Vec};

use super::{Edns, EmitAndCount, Header, LowerQuery, Message, Metadata, emit_message_parts};
use crate::{
    error::ProtoError,
    rr::{Record, rdata::TSIG},
    serialize::binary::{
        BinDecodable, BinDecoder, BinEncodable, BinEncoder, DecodeError, NameEncoding,
    },
};

/// A Message which captures the data from an inbound request
#[derive(Debug, PartialEq)]
pub struct MessageRequest {
    /// Metadata from the message header
    pub metadata: Metadata,
    /// Query name and other query parameters
    pub queries: Queries,
    /// Records which directly answer the query
    pub answers: Vec<Record>,
    /// Records with describe other authoritative servers
    ///
    /// May optionally carry the SOA record for the authoritative data in the answer section.
    pub authorities: Vec<Record>,
    /// Records which may be helpful in using the records in the other sections
    pub additionals: Vec<Record>,
    /// TSIG signature for the message, if any
    pub signature: Option<Box<Record<TSIG>>>,
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
    ///  forwarded, or stored in or loaded from Zone Files.
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
    /// Optionally returns a reference to EDNS OPT pseudo-RR
    pub edns: Option<Edns>,
}

impl MessageRequest {
    // TODO: generify this with Message?
    /// Reads a MessageRequest from the decoder
    pub fn read(decoder: &mut BinDecoder<'_>, header: Header) -> Result<Self, DecodeError> {
        let Header {
            mut metadata,
            counts,
        } = header;
        let queries = Queries::read(decoder, counts.queries as usize)?;
        let (answers, _, _) =
            Message::read_records(decoder, counts.answers as usize, false, metadata.op_code)?;
        let (authorities, _, _) = Message::read_records(
            decoder,
            counts.authorities as usize,
            false,
            metadata.op_code,
        )?;
        let (additionals, edns, signature) =
            Message::read_records(decoder, counts.additionals as usize, true, metadata.op_code)?;

        // need to grab error code from EDNS (which might have a higher value)
        if let Some(edns) = &edns {
            let high_response_code = edns.rcode_high();
            metadata.merge_response_code(high_response_code);
        }

        Ok(Self {
            metadata,
            queries,
            answers,
            authorities,
            additionals,
            signature,
            edns,
        })
    }

    /// Construct a mock MessageRequest for testing purposes
    ///
    /// The unspecified fields are left empty.
    #[cfg(any(test, feature = "testing"))]
    pub fn mock(metadata: Metadata, query: impl Into<LowerQuery>) -> Self {
        Self {
            metadata,
            queries: Queries::new(vec![query.into()]),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            signature: None,
            edns: None,
        }
    }

    /// # Return value
    ///
    /// the max payload value as it's defined in the EDNS OPT pseudo-RR.
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
}

impl BinEncodable for MessageRequest {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> Result<(), ProtoError> {
        emit_message_parts(
            &self.metadata,
            // we emit the queries, not the raw bytes, in order to guarantee canonical form
            //   in cases where that's necessary, like SIG0 validation
            &mut self.queries.queries.iter(),
            &mut self.answers.iter(),
            &mut self.authorities.iter(),
            &mut self.additionals.iter(),
            self.edns.as_ref(),
            self.signature.as_deref(),
            encoder,
        )?;

        Ok(())
    }
}

/// A set of Queries with the associated serialized data
#[derive(Debug, PartialEq, Eq)]
pub struct Queries {
    queries: Vec<LowerQuery>,
    original: Box<[u8]>,
}

impl Queries {
    /// Read queries from a decoder
    pub fn read(decoder: &mut BinDecoder<'_>, num_queries: usize) -> Result<Self, DecodeError> {
        let queries_start = decoder.index();
        let mut queries = Vec::with_capacity(num_queries);
        for _ in 0..num_queries {
            queries.push(LowerQuery::read(decoder)?);
        }

        let original = decoder
            .slice_from(queries_start)?
            .to_vec()
            .into_boxed_slice();

        Ok(Self { queries, original })
    }

    /// Construct a mock Queries object for a given query for testing purposes
    #[cfg(any(test, feature = "testing"))]
    pub fn new(query: Vec<LowerQuery>) -> Self {
        let mut encoded = Vec::new();
        let mut encoder = BinEncoder::new(&mut encoded);
        for q in query.iter() {
            q.emit(&mut encoder).unwrap();
        }
        Self {
            queries: query,
            original: encoded.into_boxed_slice(),
        }
    }

    /// Construct an empty set of queries
    pub fn empty() -> Self {
        Self {
            queries: Vec::new(),
            original: (*b"").into(),
        }
    }

    /// Helper for encoding the queries in a MessageRequest.
    pub fn as_emit_and_count(&self) -> impl EmitAndCount + '_ {
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
    pub fn try_as_query(&self) -> Result<&LowerQuery, DecodeError> {
        let count = self.queries.len();
        if count != 1 {
            return Err(DecodeError::BadQueryCount(count));
        }
        Ok(&self.queries[0])
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

    /// Returns the queries from the request
    pub fn queries(&self) -> &[LowerQuery] {
        &self.queries
    }
}

/// A helper struct to emit the queries in a [`MessageRequest`].
struct QueriesEmitAndCount<'q> {
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
        if matches!(encoder.name_encoding(), NameEncoding::Compressed) && self.first_query.is_some()
        {
            encoder.store_label_pointer(
                original_offset,
                original_offset + self.cached_serialized.len(),
            )
        }
        Ok(self.length)
    }
}

/// A type which represents an MessageRequest for dynamic Update.
pub trait UpdateRequest {
    /// Id of the Message
    fn id(&self) -> u16;

    /// Zone being updated, this should be the query of a Message
    fn zone(&self) -> Result<&LowerQuery, DecodeError>;

    /// Prerequisites map to the Answer section of a Message
    fn prerequisites(&self) -> &[Record];

    /// Records to update map to the Authority section of a Message
    fn updates(&self) -> &[Record];

    /// Additional records
    fn additionals(&self) -> &[Record];

    /// Signature for verifying the Message
    fn signature(&self) -> Option<&Record<TSIG>>;
}

impl UpdateRequest for MessageRequest {
    fn id(&self) -> u16 {
        self.metadata.id
    }

    fn zone(&self) -> Result<&LowerQuery, DecodeError> {
        // RFC 2136 says "the Zone Section is allowed to contain exactly one record."
        self.queries.try_as_query()
    }

    fn prerequisites(&self) -> &[Record] {
        &self.answers
    }

    fn updates(&self) -> &[Record] {
        &self.authorities
    }

    fn additionals(&self) -> &[Record] {
        &self.additionals
    }

    fn signature(&self) -> Option<&Record<TSIG>> {
        self.signature.as_deref()
    }
}
