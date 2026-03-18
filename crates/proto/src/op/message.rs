// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Basic protocol message for DNS

use alloc::{boxed::Box, fmt, vec::Vec};
use core::{iter, mem, ops::Deref};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "__dnssec")]
use tracing::debug;
use tracing::warn;

#[cfg(feature = "__dnssec")]
use crate::dnssec::{DnssecIter, rdata::DNSSECRData};
#[cfg(any(feature = "std", feature = "no-std-rand"))]
use crate::random;
#[cfg(feature = "__dnssec")]
use crate::rr::{TSigVerifier, TSigner};
use crate::{
    error::{ProtoError, ProtoResult},
    op::{Edns, Header, HeaderCounts, MessageType, Metadata, OpCode, Query, ResponseCode},
    rr::{RData, Record, RecordType, rdata::TSIG},
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder, DecodeError},
};

/// The basic request and response data structure, used for all DNS protocols.
///
/// [RFC 1035, DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987](https://tools.ietf.org/html/rfc1035)
///
/// ```text
/// 4.1. Format
///
/// All communications inside of the domain protocol are carried in a single
/// format called a message.  The top level format of message is divided
/// into 5 sections (some of which are empty in certain cases) shown below:
///
///     +--------------------------+
///     |        Header            |
///     +--------------------------+
///     |  Question / Zone         | the question for the name server
///     +--------------------------+
///     |   Answer  / Prerequisite | RRs answering the question
///     +--------------------------+
///     | Authority / Update       | RRs pointing toward an authority
///     +--------------------------+
///     |      Additional          | RRs holding additional information
///     +--------------------------+
///
/// The header section is always present.  The header includes fields that
/// specify which of the remaining sections are present, and also specify
/// whether the message is a query or a response, a standard query or some
/// other opcode, etc.
///
/// The names of the sections after the header are derived from their use in
/// standard queries.  The question section contains fields that describe a
/// question to a name server.  These fields are a query type (QTYPE), a
/// query class (QCLASS), and a query domain name (QNAME).  The last three
/// sections have the same format: a possibly empty list of concatenated
/// resource records (RRs).  The answer section contains RRs that answer the
/// question; the authority section contains RRs that point toward an
/// authoritative name server; the additional records section contains RRs
/// which relate to the query, but are not strictly answers for the
/// question.
/// ```
///
/// By default Message is a Query. Use the Message::as_update() to create and update, or
///  Message::new_update()
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Message {
    /// Metadata from the message header
    pub metadata: Metadata,
    /// Query name and other query parameters
    pub queries: Vec<Query>,
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

impl Message {
    /// Returns a new "empty" Message
    #[cfg(any(feature = "std", feature = "no-std-rand"))]
    pub fn query() -> Self {
        Self::new(random(), MessageType::Query, OpCode::Query)
    }

    /// Returns a Message constructed with error details to return to a client
    ///
    /// # Arguments
    ///
    /// * `id` - message id should match the request message id
    /// * `op_code` - operation of the request
    /// * `response_code` - the error code for the response
    pub fn error_msg(id: u16, op_code: OpCode, response_code: ResponseCode) -> Self {
        let mut message = Self::response(id, op_code);
        message.metadata.set_response_code(response_code);
        message
    }

    /// Returns a new `Message` with `MessageType::Response` and the given header contents
    pub fn response(id: u16, op_code: OpCode) -> Self {
        Self::new(id, MessageType::Response, op_code)
    }

    /// Create a new [`Message`] with the given header contents
    pub fn new(id: u16, message_type: MessageType, op_code: OpCode) -> Self {
        Self {
            metadata: Metadata::new(id, message_type, op_code),
            queries: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            signature: None,
            edns: None,
        }
    }

    /// Truncates a Message, this blindly removes all response fields and sets truncated to `true`
    pub fn truncate(&self) -> Self {
        // copy header
        let mut metadata = self.metadata;
        metadata.set_truncated(true);

        let mut msg = Self::new(0, MessageType::Query, OpCode::Query);
        msg.metadata = metadata;

        // drops additional/answer/nameservers/signature
        // adds query/OPT
        msg.add_queries(self.queries.iter().cloned());
        if let Some(edns) = self.edns.clone() {
            msg.set_edns(edns);
        }

        // TODO, perhaps just quickly add a few response records here? that we know would fit?
        msg
    }

    /// Strip DNSSEC records per RFC 4035 section 3.2.1
    ///
    /// Removes DNSSEC records that don't match the query type from all sections
    /// when the DNSSEC OK bit is not set in the original query.
    ///
    /// Uses the first query in the message to determine the query type.
    /// If there are no queries, returns the message unchanged.
    ///
    /// The query_has_dnssec_ok is a required parameter because the
    /// dnssec_ok bit in the query might be different from the bit
    /// in the response. See discussion in
    /// [#3340](https://github.com/hickory-dns/hickory-dns/issues/3340)
    pub fn maybe_strip_dnssec_records(mut self, query_has_dnssec_ok: bool) -> Self {
        if query_has_dnssec_ok {
            return self;
        }

        let Some(query_type) = self.queries.first().map(|q| q.query_type()) else {
            return self; // No query, return unchanged
        };

        let predicate = |record: &Record| {
            let record_type = record.record_type();
            record_type == query_type || !record_type.is_dnssec()
        };

        self.answers.retain(predicate);
        self.authorities.retain(predicate);
        self.additionals.retain(predicate);

        self
    }

    /// Add a query to the Message, either the query response from the server, or the request Query.
    pub fn add_query(&mut self, query: Query) -> &mut Self {
        self.queries.push(query);
        self
    }

    /// Adds an iterator over a set of Queries to be added to the message
    pub fn add_queries<Q, I>(&mut self, queries: Q) -> &mut Self
    where
        Q: IntoIterator<Item = Query, IntoIter = I>,
        I: Iterator<Item = Query>,
    {
        for query in queries {
            self.add_query(query);
        }

        self
    }

    /// Add a record to the Answer section.
    pub fn add_answer(&mut self, record: Record) -> &mut Self {
        self.answers.push(record);
        self
    }

    /// Add all the records from the iterator to the Answer section of the message.
    pub fn add_answers<R, I>(&mut self, records: R) -> &mut Self
    where
        R: IntoIterator<Item = Record, IntoIter = I>,
        I: Iterator<Item = Record>,
    {
        for record in records {
            self.add_answer(record);
        }

        self
    }

    /// Sets the Answer section to the specified set of records.
    ///
    /// # Panics
    ///
    /// Will panic if the Answer section is already non-empty.
    pub fn insert_answers(&mut self, records: Vec<Record>) {
        assert!(self.answers.is_empty());
        self.answers = records;
    }

    /// Add a record to the Authority section.
    pub fn add_authority(&mut self, record: Record) -> &mut Self {
        self.authorities.push(record);
        self
    }

    /// Add all the records from the Iterator to the Authority section of the message.
    pub fn add_authorities<R, I>(&mut self, records: R) -> &mut Self
    where
        R: IntoIterator<Item = Record, IntoIter = I>,
        I: Iterator<Item = Record>,
    {
        for record in records {
            self.add_authority(record);
        }

        self
    }

    /// Sets the Authority section to the specified set of records.
    ///
    /// # Panics
    ///
    /// Will panic if the Authority section is already non-empty.
    pub fn insert_authorities(&mut self, records: Vec<Record>) {
        assert!(self.authorities.is_empty());
        self.authorities = records;
    }

    /// Add a record to the Additional section.
    pub fn add_additional(&mut self, record: Record) -> &mut Self {
        self.additionals.push(record);
        self
    }

    /// Add all the records from the iterator to the Additional section of the message.
    pub fn add_additionals<R, I>(&mut self, records: R) -> &mut Self
    where
        R: IntoIterator<Item = Record, IntoIter = I>,
        I: Iterator<Item = Record>,
    {
        for record in records {
            self.add_additional(record);
        }

        self
    }

    /// Sets the Additional to the specified set of records.
    ///
    /// # Panics
    ///
    /// Will panic if additional records are already associated to the message.
    pub fn insert_additionals(&mut self, records: Vec<Record>) {
        assert!(self.additionals.is_empty());
        self.additionals = records;
    }

    /// Add the EDNS OPT pseudo-RR to the Message
    pub fn set_edns(&mut self, edns: Edns) -> &mut Self {
        self.edns = Some(edns);
        self
    }

    /// Set the TSIG signature record for the message.
    ///
    /// This must be used only after all records have been associated. Generally this will be
    /// handled by the client and not need to be used directly
    #[cfg(feature = "__dnssec")]
    pub fn set_signature(&mut self, sig: Box<Record<TSIG>>) -> &mut Self {
        self.signature = Some(sig);
        self
    }

    /// Returns a clone of the `Message` with the message type set to `Response`.
    pub fn to_response(&self) -> Self {
        let mut metadata = self.metadata;
        metadata.set_message_type(MessageType::Response);
        Self {
            metadata,
            queries: self.queries.clone(),
            answers: self.answers.clone(),
            authorities: self.authorities.clone(),
            additionals: self.additionals.clone(),
            signature: self.signature.clone(),
            edns: self.edns.clone(),
        }
    }

    /// Returns a borrowed iterator of the answer records wrapped in a dnssec Proven type
    #[cfg(feature = "__dnssec")]
    pub fn dnssec_answers(&self) -> DnssecIter<'_> {
        DnssecIter::new(&self.answers)
    }

    /// Consume the message, returning an iterator over records from all sections
    pub fn take_all_sections(&mut self) -> impl Iterator<Item = Record> {
        let (answers, authorities, additionals) = (
            mem::take(&mut self.answers),
            mem::take(&mut self.authorities),
            mem::take(&mut self.additionals),
        );
        answers.into_iter().chain(authorities).chain(additionals)
    }

    /// All sections chained
    pub fn all_sections(&self) -> impl Iterator<Item = &Record> {
        self.answers
            .iter()
            .chain(self.authorities.iter())
            .chain(self.additionals.iter())
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

    /// # Return value
    ///
    /// the signature over the message, if any
    pub fn signature(&self) -> Option<&Record<TSIG>> {
        self.signature.as_deref()
    }

    /// Remove signatures from the Message
    pub fn take_signature(&mut self) -> Option<Box<Record<TSIG>>> {
        self.signature.take()
    }

    /// Attempts to read the specified number of `Query`s
    pub fn read_queries(decoder: &mut BinDecoder<'_>, count: usize) -> ProtoResult<Vec<Query>> {
        let mut queries = Vec::with_capacity(count);
        for _ in 0..count {
            queries.push(Query::read(decoder)?);
        }
        Ok(queries)
    }

    /// Attempts to read the specified number of records
    ///
    /// # Returns
    ///
    /// This returns a tuple of first standard Records, then a possibly associated Edns, and then
    /// finally a `Record<TSIG>` if applicable.
    ///
    /// A `Record<TSIG>` record is only valid when found in the additional data section.
    /// Further, it must always be the last record in that section. It is not possible to have
    /// multiple TSIG records.
    ///
    /// RFC 8945 §5.1 says:
    ///  "This TSIG record MUST be the only TSIG RR in the message and MUST be the last record in
    ///   the additional data section."
    #[cfg_attr(not(feature = "__dnssec"), allow(unused_mut))]
    #[expect(clippy::type_complexity)]
    pub fn read_records(
        decoder: &mut BinDecoder<'_>,
        count: usize,
        is_additional: bool,
    ) -> Result<(Vec<Record>, Option<Edns>, Option<Box<Record<TSIG>>>), DecodeError> {
        let mut records: Vec<Record> = Vec::with_capacity(count);
        let mut edns: Option<Edns> = None;
        let mut sig = None;

        for _ in 0..count {
            let record = Record::read(decoder)?;

            // There must be no additional records after a TSIG/SIG(0) record.
            if sig.is_some() {
                return Err(DecodeError::RecordAfterSig);
            }

            // OPT, SIG and TSIG records are only allowed in the additional section.
            if !is_additional
                && matches!(
                    record.record_type(),
                    RecordType::OPT | RecordType::SIG | RecordType::TSIG
                )
            {
                return Err(DecodeError::RecordNotInAdditionalSection(
                    record.record_type(),
                ));
            } else if !is_additional {
                records.push(record);
                continue;
            }

            match record.data() {
                #[cfg(feature = "__dnssec")]
                RData::DNSSEC(DNSSECRData::SIG(_)) => {
                    warn!(
                        "message was SIG(0) signed, but support for SIG(0) message authentication was removed from hickory-dns"
                    );
                    records.push(record);
                }
                #[cfg(feature = "__dnssec")]
                RData::TSIG(_) => {
                    sig = Some(Box::new(
                        record
                            .map(|data| match data {
                                RData::TSIG(tsig) => Some(tsig),
                                _ => None,
                            })
                            .unwrap(/* match arm ensures correct type */),
                    ))
                }
                RData::Update0(RecordType::OPT) | RData::OPT(_) => {
                    if edns.is_some() {
                        return Err(DecodeError::DuplicateEdns);
                    }
                    edns = Some((&record).into());
                }
                _ => {
                    records.push(record);
                }
            }
        }

        Ok((records, edns, sig))
    }

    /// Decodes a message from the buffer.
    pub fn from_vec(buffer: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = BinDecoder::new(buffer);
        Self::read(&mut decoder)
    }

    /// Encodes the Message into a buffer
    pub fn to_vec(&self) -> Result<Vec<u8>, ProtoError> {
        // TODO: this feels like the right place to verify the max packet size of the message,
        //  will need to update the header for truncation and the lengths if we send less than the
        //  full response. This needs to conform with the EDNS settings of the server...
        let mut buffer = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut buffer);
            self.emit(&mut encoder)?;
        }

        Ok(buffer)
    }

    /// Finalize the message prior to sending.
    ///
    /// Subsequent to calling this, the Message should not change.
    #[cfg(feature = "__dnssec")]
    pub fn finalize(
        &mut self,
        finalizer: &TSigner,
        inception_time: u64,
    ) -> ProtoResult<Option<TSigVerifier>> {
        debug!("finalizing message: {:?}", self);

        let (signature, verifier) = finalizer.sign_message(self, inception_time)?;
        self.set_signature(signature);

        Ok(verifier)
    }
}

impl Deref for Message {
    type Target = Metadata;

    fn deref(&self) -> &Self::Target {
        &self.metadata
    }
}

/// Returns the count written and a boolean if it was truncated
fn count_was_truncated(result: ProtoResult<usize>) -> ProtoResult<(u16, bool)> {
    let (count, truncated) = match result {
        Ok(count) => (count, false),
        Err(ProtoError::NotAllRecordsWritten { count }) => (count, true),
        Err(e) => return Err(e),
    };

    match u16::try_from(count) {
        Ok(count) => Ok((count, truncated)),
        Err(_) => Err(ProtoError::Message(
            "too many records to fit in header count",
        )),
    }
}

/// A trait that defines types which can be emitted as a set, with the associated count returned.
pub trait EmitAndCount {
    /// Emit self to the encoder and return the count of items
    fn emit(&mut self, encoder: &mut BinEncoder<'_>) -> ProtoResult<usize>;
}

impl<'e, I: Iterator<Item = &'e E>, E: 'e + BinEncodable> EmitAndCount for I {
    fn emit(&mut self, encoder: &mut BinEncoder<'_>) -> ProtoResult<usize> {
        encoder.emit_all(self)
    }
}

/// Emits the different sections of a message properly
///
/// # Return
///
/// In the case of a successful emit, the final header (updated counts, etc) is returned for help with logging, etc.
#[allow(clippy::too_many_arguments)]
pub fn emit_message_parts<Q, A, N, D>(
    metadata: &Metadata,
    queries: &mut Q,
    answers: &mut A,
    authorities: &mut N,
    additionals: &mut D,
    edns: Option<&Edns>,
    signature: Option<&Record<TSIG>>,
    encoder: &mut BinEncoder<'_>,
) -> ProtoResult<Header>
where
    Q: EmitAndCount,
    A: EmitAndCount,
    N: EmitAndCount,
    D: EmitAndCount,
{
    let place = encoder.place::<Header>()?;

    let query_count = queries.emit(encoder)?;
    // TODO: need to do something on max records
    //  return offset of last emitted record.
    let answer_count = count_was_truncated(answers.emit(encoder))?;
    let authority_count = count_was_truncated(authorities.emit(encoder))?;
    let mut additional_count = count_was_truncated(additionals.emit(encoder))?;

    if let Some(mut edns) = edns.cloned() {
        // need to commit the error code
        edns.set_rcode_high(metadata.response_code().high());

        let count = count_was_truncated(encoder.emit_all(iter::once(&Record::from(&edns))))?;
        additional_count.0 += count.0;
        additional_count.1 |= count.1;
    } else if metadata.response_code().high() > 0 {
        warn!(
            "response code: {} for request: {} requires EDNS but none available",
            metadata.response_code(),
            metadata.id()
        );
    }

    // this is a little hacky, but if we are Verifying a signature, i.e. the original Message
    //  then the TSIG record should not be encoded and the edns record (if it exists) is
    //  already part of the additionals section.
    let count = match signature {
        Some(rec) => count_was_truncated(encoder.emit_all(iter::once(rec)))?,
        None => (0, false),
    };
    additional_count.0 += count.0;
    additional_count.1 |= count.1;

    let counts = HeaderCounts {
        query_count: match u16::try_from(query_count) {
            Ok(count) => count,
            Err(_) => {
                return Err(ProtoError::Message(
                    "too many queries to fit in header count",
                ));
            }
        },
        answer_count: answer_count.0,
        authority_count: authority_count.0,
        additional_count: additional_count.0,
    };

    let mut final_metadata = *metadata;
    final_metadata.set_truncated(
        metadata.truncated() || answer_count.1 || authority_count.1 || additional_count.1,
    );

    let header = Header {
        metadata: final_metadata,
        counts,
    };

    place.replace(encoder, header)?;
    Ok(header)
}

impl BinEncodable for Message {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        emit_message_parts(
            &self.metadata,
            &mut self.queries.iter(),
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

impl<'r> BinDecodable<'r> for Message {
    fn read(decoder: &mut BinDecoder<'r>) -> Result<Self, DecodeError> {
        let Header {
            mut metadata,
            counts,
        } = Header::read(decoder)?;

        // TODO: return just header, and in the case of the rest of message getting an error.
        //  this could improve error detection while decoding.

        // get the questions
        let count = counts.query_count as usize;
        let mut queries = Vec::with_capacity(count);
        for _ in 0..count {
            queries.push(Query::read(decoder)?);
        }

        let (answers, _, _) = Self::read_records(decoder, counts.answer_count as usize, false)?;
        let (authorities, _, _) =
            Self::read_records(decoder, counts.authority_count as usize, false)?;
        let (additionals, edns, signature) =
            Self::read_records(decoder, counts.additional_count as usize, true)?;

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
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let write_query = |slice, f: &mut fmt::Formatter<'_>| -> Result<(), fmt::Error> {
            for d in slice {
                writeln!(f, ";; {d}")?;
            }

            Ok(())
        };

        let write_slice = |slice, f: &mut fmt::Formatter<'_>| -> Result<(), fmt::Error> {
            for d in slice {
                writeln!(f, "{d}")?;
            }

            Ok(())
        };

        writeln!(f, "; header {header}", header = self.metadata)?;

        if let Some(edns) = &self.edns {
            writeln!(f, "; edns {edns}")?;
        }

        writeln!(f, "; query")?;
        write_query(&self.queries, f)?;

        if self.metadata.message_type() == MessageType::Response
            || self.metadata.op_code() == OpCode::Update
        {
            writeln!(f, "; answers {}", self.answers.len())?;
            write_slice(&self.answers, f)?;
            writeln!(f, "; authorities {}", self.authorities.len())?;
            write_slice(&self.authorities, f)?;
            writeln!(f, "; additionals {}", self.additionals.len())?;
            write_slice(&self.additionals, f)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::rr::rdata::A;
    #[cfg(feature = "std")]
    use crate::rr::rdata::OPT;
    #[cfg(feature = "std")]
    use crate::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
    #[cfg(feature = "__dnssec")]
    use crate::rr::rdata::{TSIG, tsig::TsigAlgorithm};
    use crate::rr::{Name, RData};
    #[cfg(feature = "std")]
    use crate::std::net::IpAddr;
    #[cfg(feature = "std")]
    use crate::std::string::ToString;

    #[test]
    fn test_emit_and_read_header() {
        let mut message = Message::response(10, OpCode::Update);
        message
            .metadata
            .set_authoritative(true)
            .set_truncated(false)
            .set_recursion_desired(true)
            .set_recursion_available(true)
            .set_response_code(ResponseCode::ServFail);

        test_emit_and_read(message);
    }

    #[test]
    fn test_emit_and_read_query() {
        let mut message = Message::response(10, OpCode::Update);
        message
            .metadata
            .set_authoritative(true)
            .set_truncated(true)
            .set_recursion_desired(true)
            .set_recursion_available(true)
            .set_response_code(ResponseCode::ServFail);
        message.add_query(Query::new());

        test_emit_and_read(message);
    }

    #[test]
    fn test_emit_and_read_records() {
        let mut message = Message::response(10, OpCode::Update);
        message
            .metadata
            .set_authoritative(true)
            .set_truncated(true)
            .set_recursion_desired(true)
            .set_recursion_available(true)
            .set_authentic_data(true)
            .set_checking_disabled(true)
            .set_response_code(ResponseCode::ServFail);

        message.add_answer(Record::stub());
        message.add_authority(Record::stub());
        message.add_additional(Record::stub());

        test_emit_and_read(message);
    }

    #[cfg(test)]
    fn test_emit_and_read(message: Message) {
        let mut byte_vec: Vec<u8> = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut byte_vec);
            message.emit(&mut encoder).unwrap();
        }

        let mut decoder = BinDecoder::new(&byte_vec);
        let got = Message::read(&mut decoder).unwrap();

        assert_eq!(got, message);
    }

    #[test]
    fn test_header_counts_correction_after_emit_read() {
        let mut message = Message::response(10, OpCode::Update);
        message
            .metadata
            .set_authoritative(true)
            .set_truncated(true)
            .set_recursion_desired(true)
            .set_recursion_available(true)
            .set_authentic_data(true)
            .set_checking_disabled(true)
            .set_response_code(ResponseCode::ServFail);

        message.add_answer(Record::stub());
        message.add_authority(Record::stub());
        message.add_additional(Record::stub());

        let got = get_message_after_emitting_and_reading(message);
        assert_eq!(got.queries.len(), 0);
        assert_eq!(got.answers.len(), 1);
        assert_eq!(got.authorities.len(), 1);
        assert_eq!(got.additionals.len(), 1);
    }

    #[cfg(test)]
    fn get_message_after_emitting_and_reading(message: Message) -> Message {
        let mut byte_vec: Vec<u8> = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut byte_vec);
            message.emit(&mut encoder).unwrap();
        }

        let mut decoder = BinDecoder::new(&byte_vec);

        Message::read(&mut decoder).unwrap()
    }

    #[test]
    fn test_legit_message() {
        #[rustfmt::skip]
        let buf: Vec<u8> = vec![
            0x10, 0x00, 0x81,
            0x80, // id = 4096, response, op=query, recursion_desired, recursion_available, no_error
            0x00, 0x01, 0x00, 0x01, // 1 query, 1 answer,
            0x00, 0x00, 0x00, 0x00, // 0 nameservers, 0 additional record
            0x03, b'w', b'w', b'w', // query --- www.example.com
            0x07, b'e', b'x', b'a', //
            b'm', b'p', b'l', b'e', //
            0x03, b'c', b'o', b'm', //
            0x00,                   // 0 = endname
            0x00, 0x01, 0x00, 0x01, // RecordType = A, Class = IN
            0xC0, 0x0C,             // name pointer to www.example.com
            0x00, 0x01, 0x00, 0x01, // RecordType = A, Class = IN
            0x00, 0x00, 0x00, 0x02, // TTL = 2 seconds
            0x00, 0x04,             // record length = 4 (ipv4 address)
            0x5D, 0xB8, 0xD7, 0x0E, // address = 93.184.215.14
        ];

        let mut decoder = BinDecoder::new(&buf);
        let message = Message::read(&mut decoder).unwrap();

        assert_eq!(message.id(), 4_096);

        let mut buf: Vec<u8> = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut buf);
            message.emit(&mut encoder).unwrap();
        }

        let mut decoder = BinDecoder::new(&buf);
        let message = Message::read(&mut decoder).unwrap();

        assert_eq!(message.id(), 4_096);
    }

    #[test]
    fn rdata_zero_roundtrip() {
        let buf = &[
            160, 160, 0, 13, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0,
        ];

        assert!(Message::from_bytes(buf).is_err());
    }

    #[test]
    fn nsec_deserialization() {
        const CRASHING_MESSAGE: &[u8] = &[
            0, 0, 132, 0, 0, 0, 0, 1, 0, 0, 0, 1, 36, 49, 101, 48, 101, 101, 51, 100, 51, 45, 100,
            52, 50, 52, 45, 52, 102, 55, 56, 45, 57, 101, 52, 99, 45, 99, 51, 56, 51, 51, 55, 55,
            56, 48, 102, 50, 98, 5, 108, 111, 99, 97, 108, 0, 0, 1, 128, 1, 0, 0, 0, 120, 0, 4,
            192, 168, 1, 17, 36, 49, 101, 48, 101, 101, 51, 100, 51, 45, 100, 52, 50, 52, 45, 52,
            102, 55, 56, 45, 57, 101, 52, 99, 45, 99, 51, 56, 51, 51, 55, 55, 56, 48, 102, 50, 98,
            5, 108, 111, 99, 97, 108, 0, 0, 47, 128, 1, 0, 0, 0, 120, 0, 5, 192, 70, 0, 1, 64,
        ];

        Message::from_vec(CRASHING_MESSAGE).expect("failed to parse message");
    }

    #[test]
    fn prior_to_pointer() {
        const MESSAGE: &[u8] = include_bytes!("../../tests/test-data/fuzz-prior-to-pointer.rdata");
        let message = Message::from_bytes(MESSAGE).expect("failed to parse message");
        let encoded = message.to_bytes().unwrap();
        Message::from_bytes(&encoded).expect("failed to parse encoded message");
    }

    #[test]
    fn test_read_records_unsigned() {
        let records = vec![
            Record::from_rdata(
                Name::from_labels(vec!["example", "com"]).unwrap(),
                300,
                RData::A(A::new(127, 0, 0, 1)),
            ),
            Record::from_rdata(
                Name::from_labels(vec!["www", "example", "com"]).unwrap(),
                300,
                RData::A(A::new(127, 0, 0, 1)),
            ),
        ];
        let result = encode_and_read_records(records.clone(), false);
        let (output_records, edns, signature) = result.unwrap();
        assert_eq!(output_records.len(), records.len());
        assert!(edns.is_none());
        assert!(signature.is_none());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_read_records_edns() {
        let records = vec![
            Record::from_rdata(
                Name::from_labels(vec!["example", "com"]).unwrap(),
                300,
                RData::A(A::new(127, 0, 0, 1)),
            ),
            Record::from_rdata(
                Name::new(),
                0,
                RData::OPT(OPT::new(vec![(
                    EdnsCode::Subnet,
                    EdnsOption::Subnet(ClientSubnet::new(IpAddr::from([127, 0, 0, 1]), 0, 24)),
                )])),
            ),
        ];
        let result = encode_and_read_records(records, true);
        let (output_records, edns, signature) = result.unwrap();
        assert_eq!(output_records.len(), 1); // Only the A record, OPT becomes EDNS
        assert!(edns.is_some());
        assert!(signature.is_none());
    }

    #[cfg(feature = "__dnssec")]
    #[test]
    fn test_read_records_tsig() {
        let records = vec![
            Record::from_rdata(
                Name::from_labels(vec!["example", "com"]).unwrap(),
                300,
                RData::A(A::new(127, 0, 0, 1)),
            ),
            Record::from_rdata(
                Name::from_labels(vec!["tsig", "example", "com"]).unwrap(),
                0,
                fake_tsig(),
            ),
        ];
        let result = encode_and_read_records(records, true);
        let (output_records, edns, signature) = result.unwrap();
        assert_eq!(output_records.len(), 1); // Only the A record, TSIG becomes signature
        assert!(edns.is_none());
        assert!(signature.is_some());
    }

    #[cfg(all(feature = "std", feature = "__dnssec"))]
    #[test]
    fn test_read_records_edns_tsig() {
        let records = vec![
            Record::from_rdata(
                Name::from_labels(vec!["example", "com"]).unwrap(),
                300,
                RData::A(A::new(127, 0, 0, 1)),
            ),
            Record::from_rdata(
                Name::new(),
                0,
                RData::OPT(OPT::new(vec![(
                    EdnsCode::Subnet,
                    EdnsOption::Subnet(ClientSubnet::new(IpAddr::from([127, 0, 0, 1]), 0, 24)),
                )])),
            ),
            Record::from_rdata(
                Name::from_labels(vec!["tsig", "example", "com"]).unwrap(),
                0,
                fake_tsig(),
            ),
        ];

        let result = encode_and_read_records(records, true);
        assert!(result.is_ok());
        let (output_records, edns, signature) = result.unwrap();
        assert_eq!(output_records.len(), 1); // Only the A record
        assert!(edns.is_some());
        assert!(signature.is_some());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_read_records_unsigned_multiple_edns() {
        let opt_record = Record::from_rdata(
            Name::new(),
            0,
            RData::OPT(OPT::new(vec![(
                EdnsCode::Subnet,
                EdnsOption::Subnet(ClientSubnet::new(IpAddr::from([127, 0, 0, 1]), 0, 24)),
            )])),
        );
        let error = encode_and_read_records(
            vec![
                opt_record.clone(),
                Record::from_rdata(
                    Name::from_labels(vec!["example", "com"]).unwrap(),
                    300,
                    RData::A(A::new(127, 0, 0, 1)),
                ),
                opt_record.clone(),
            ],
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("more than one EDNS record"));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_read_records_opt_not_additional() {
        let opt_record = Record::from_rdata(
            Name::new(),
            0,
            RData::OPT(OPT::new(vec![(
                EdnsCode::Subnet,
                EdnsOption::Subnet(ClientSubnet::new(IpAddr::from([127, 0, 0, 1]), 0, 24)),
            )])),
        );
        let err = encode_and_read_records(
            vec![
                opt_record.clone(),
                Record::from_rdata(
                    Name::from_labels(vec!["example", "com"]).unwrap(),
                    300,
                    RData::A(A::new(127, 0, 0, 1)),
                ),
            ],
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("record type OPT only allowed in additional")
        );
    }

    #[cfg(all(feature = "std", feature = "__dnssec"))]
    #[test]
    fn test_read_records_signed_multiple_edns() {
        let opt_record = Record::from_rdata(
            Name::new(),
            0,
            RData::OPT(OPT::new(vec![(
                EdnsCode::Subnet,
                EdnsOption::Subnet(ClientSubnet::new(IpAddr::from([127, 0, 0, 1]), 0, 24)),
            )])),
        );
        let error = encode_and_read_records(
            vec![
                opt_record.clone(),
                Record::from_rdata(
                    Name::from_labels(vec!["example", "com"]).unwrap(),
                    300,
                    RData::A(A::new(127, 0, 0, 1)),
                ),
                opt_record.clone(),
                Record::from_rdata(
                    Name::from_labels(vec!["tsig", "example", "com"]).unwrap(),
                    0,
                    fake_tsig(),
                ),
            ],
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("more than one EDNS record"));
    }

    #[cfg(all(feature = "std", feature = "__dnssec"))]
    #[test]
    fn test_read_records_tsig_not_additional() {
        let err = encode_and_read_records(
            vec![
                Record::from_rdata(
                    Name::from_labels(vec!["example", "com"]).unwrap(),
                    300,
                    RData::A(A::new(127, 0, 0, 1)),
                ),
                Record::from_rdata(
                    Name::from_labels(vec!["tsig", "example", "com"]).unwrap(),
                    0,
                    fake_tsig(),
                ),
            ],
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("record type TSIG only allowed in additional")
        );
    }

    #[cfg(all(feature = "std", feature = "__dnssec"))]
    #[test]
    fn test_read_records_tsig_not_last() {
        let a_record = Record::from_rdata(
            Name::from_labels(vec!["example", "com"]).unwrap(),
            300,
            RData::A(A::new(127, 0, 0, 1)),
        );
        let error = encode_and_read_records(
            vec![
                a_record.clone(),
                Record::from_rdata(
                    Name::from_labels(vec!["tsig", "example", "com"]).unwrap(),
                    0,
                    fake_tsig(),
                ),
                a_record.clone(),
            ],
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("record after TSIG or SIG(0)"));
    }

    #[cfg(all(feature = "std", feature = "__dnssec"))]
    #[test]
    fn test_read_records_sig0_not_last() {
        let a_record = Record::from_rdata(
            Name::from_labels(vec!["example", "com"]).unwrap(),
            300,
            RData::A(A::new(127, 0, 0, 1)),
        );
        let error = encode_and_read_records(
            vec![
                a_record.clone(),
                Record::from_rdata(
                    Name::from_labels(vec!["sig0", "example", "com"]).unwrap(),
                    0,
                    fake_tsig(),
                ),
                a_record.clone(),
            ],
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("record after TSIG or SIG(0)"));
    }

    #[cfg(all(feature = "std", feature = "__dnssec"))]
    #[test]
    fn test_read_records_multiple_tsig() {
        let tsig_record = Record::from_rdata(
            Name::from_labels(vec!["tsig", "example", "com"]).unwrap(),
            0,
            fake_tsig(),
        );
        let error = encode_and_read_records(
            vec![
                Record::from_rdata(
                    Name::from_labels(vec!["example", "com"]).unwrap(),
                    300,
                    RData::A(A::new(127, 0, 0, 1)),
                ),
                tsig_record.clone(),
                tsig_record.clone(),
            ],
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("record after TSIG or SIG(0)"));
    }

    #[cfg(all(feature = "std", feature = "__dnssec"))]
    #[test]
    fn test_read_records_multiple_sig0() {
        let sig0_record = Record::from_rdata(
            Name::from_labels(vec!["sig0", "example", "com"]).unwrap(),
            0,
            fake_tsig(),
        );
        let error = encode_and_read_records(
            vec![
                Record::from_rdata(
                    Name::from_labels(vec!["example", "com"]).unwrap(),
                    300,
                    RData::A(A::new(127, 0, 0, 1)),
                ),
                sig0_record.clone(),
                sig0_record.clone(),
            ],
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("record after TSIG or SIG(0)"));
    }

    #[expect(clippy::type_complexity)]
    fn encode_and_read_records(
        records: Vec<Record>,
        is_additional: bool,
    ) -> ProtoResult<(Vec<Record>, Option<Edns>, Option<Box<Record<TSIG>>>)> {
        let mut bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut bytes);
        encoder.emit_all(records.iter())?;
        Ok(Message::read_records(
            &mut BinDecoder::new(&bytes),
            records.len(),
            is_additional,
        )?)
    }

    #[cfg(feature = "__dnssec")]
    fn fake_tsig() -> RData {
        RData::TSIG(TSIG::new(
            TsigAlgorithm::HmacSha256,
            0,
            0,
            vec![],
            0,
            None,
            vec![],
        ))
    }
}
