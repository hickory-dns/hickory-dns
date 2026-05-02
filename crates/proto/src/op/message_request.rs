// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use alloc::{boxed::Box, vec::Vec};
use core::ops::Deref;

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
        let queries = Queries::read(decoder, header.counts.queries as usize)?;
        Self::read_with_queries(decoder, queries, header)
    }

    /// Reads a MessageRequest from the decoder, after the [`Queries`] have already been read.
    pub fn read_with_queries(
        decoder: &mut BinDecoder<'_>,
        queries: Queries,
        header: Header,
    ) -> Result<Self, DecodeError> {
        let Header {
            mut metadata,
            counts,
        } = header;
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
            queries: Queries::new(query.into()),
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
            &mut [&self.queries.inner].into_iter(),
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Queries {
    /// The parsed query data
    inner: LowerQuery,
    original: Box<[u8]>,
}

impl Queries {
    /// Read queries from a decoder
    pub fn read(decoder: &mut BinDecoder<'_>, num_queries: usize) -> Result<Self, DecodeError> {
        if num_queries != 1 {
            // In the DNS, QDCOUNT Is (Usually) One
            // <https://www.rfc-editor.org/rfc/rfc9619.html>
            return Err(DecodeError::BadQueryCount(num_queries));
        }

        let queries_start = decoder.index();
        let inner = LowerQuery::read(decoder)?;
        let original = decoder
            .slice_from(queries_start)?
            .to_vec()
            .into_boxed_slice();

        Ok(Self { inner, original })
    }

    /// Construct a mock Queries object for a given query for testing purposes
    #[cfg(any(test, feature = "testing"))]
    pub fn new(inner: LowerQuery) -> Self {
        let mut encoded = Vec::new();
        let mut encoder = BinEncoder::new(&mut encoded);
        inner.emit(&mut encoder).unwrap();

        Self {
            inner,
            original: encoded.into_boxed_slice(),
        }
    }

    /// Helper for encoding the queries in a MessageRequest.
    pub fn as_emit_and_count(&self) -> QueriesEmitAndCount<'_> {
        QueriesEmitAndCount::Some(&self.original)
    }

    /// returns the bytes as they were seen from the Client
    pub fn as_bytes(&self) -> &[u8] {
        self.original.as_ref()
    }
}

impl Deref for Queries {
    type Target = LowerQuery;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// A helper struct to emit the queries in a [`MessageRequest`].
pub enum QueriesEmitAndCount<'q> {
    /// Original query encoding
    Some(&'q [u8]),
    /// No queries to emit
    None,
}

impl EmitAndCount for QueriesEmitAndCount<'_> {
    fn emit(&mut self, encoder: &mut BinEncoder<'_>) -> Result<usize, ProtoError> {
        let QueriesEmitAndCount::Some(original) = self else {
            return Ok(0);
        };

        let original_offset = encoder.offset();
        encoder.emit_slice(original)?;
        if matches!(encoder.name_encoding, NameEncoding::Compressed) {
            encoder.store_label_pointer(original_offset, original_offset + original.len())
        }
        Ok(1)
    }
}
