// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[cfg(feature = "testing")]
use crate::proto::op::Query;
#[cfg(any(test, feature = "testing"))]
use crate::proto::serialize::binary::BinEncodable;
use crate::{
    proto::{
        ProtoError,
        op::{EmitAndCount, LowerQuery},
        rr::{Record, rdata::TSIG},
        serialize::binary::{BinDecodable, BinDecoder, BinEncoder, DecodeError, NameEncoding},
    },
    zone_handler::LookupError,
};

/// A set of Queries with the associated serialized data
#[derive(Debug, PartialEq, Eq)]
pub struct Queries {
    queries: Vec<LowerQuery>,
    original: Box<[u8]>,
}

impl Queries {
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

    /// return the number of queries in the request
    pub fn len(&self) -> usize {
        self.queries.len()
    }

    /// Returns true if there are no queries
    pub fn is_empty(&self) -> bool {
        self.queries.is_empty()
    }

    /// Returns the queries from the request
    pub fn queries(&self) -> &[LowerQuery] {
        &self.queries
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
    pub(crate) fn try_as_query(&self) -> Result<&LowerQuery, LookupError> {
        let count = self.queries.len();
        if count != 1 {
            return Err(LookupError::BadQueryCount(count));
        }
        Ok(&self.queries[0])
    }

    /// Construct `Queries` from a slice of `Query`, encoding them to cache the wire bytes
    #[cfg(feature = "testing")]
    pub fn from_queries(queries: &[Query]) -> Self {
        let lower: Vec<LowerQuery> = queries.iter().cloned().map(LowerQuery::from).collect();
        let mut encoded = Vec::new();
        let mut encoder = BinEncoder::new(&mut encoded);
        for q in queries {
            q.emit(&mut encoder).unwrap();
        }
        Self {
            queries: lower,
            original: encoded.into_boxed_slice(),
        }
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

/// A type which represents a Request for dynamic Update.
pub trait UpdateRequest {
    /// Id of the Message
    fn id(&self) -> u16;

    /// Zone being updated, this should be the query of a Message
    fn zone(&self) -> Result<&LowerQuery, LookupError>;

    /// Prerequisites map to the Answer section of a Message
    fn prerequisites(&self) -> &[Record];

    /// Records to update map to the Authority section of a Message
    fn updates(&self) -> &[Record];

    /// Additional records
    fn additionals(&self) -> &[Record];

    /// Signature for verifying the Message
    fn signature(&self) -> Option<&Record<TSIG>>;
}
