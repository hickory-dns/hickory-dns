/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Basic protocol message for DNS

use std::sync::Arc;
use std::mem;

use error::*;
use rr::{Record, RecordType};
use serialize::binary::{BinDecoder, BinEncoder, BinSerializable, EncodeMode};
use super::{Edns, Header, MessageType, OpCode, Query, ResponseCode};

#[cfg(feature = "dnssec")]
use rr::dnssec::rdata::DNSSECRecordType;

/// The basic request and response datastructure, used for all DNS protocols.
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
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Message {
    header: Header,
    queries: Vec<Query>,
    answers: Vec<Record>,
    name_servers: Vec<Record>,
    additionals: Vec<Record>,
    sig0: Vec<Record>,
    edns: Option<Edns>,
}

impl Message {
    /// Returns a new "empty" Message
    pub fn new() -> Self {
        Message {
            header: Header::new(),
            queries: Vec::new(),
            answers: Vec::new(),
            name_servers: Vec::new(),
            additionals: Vec::new(),
            sig0: Vec::new(),
            edns: None,
        }
    }

    /// Returns a Message constructed with error details to return to a client
    ///
    /// # Arguments
    ///
    /// * `id` - message id should match the request message id
    /// * `op_code` - operation of the request
    /// * `response_code` - the error code for the response
    pub fn error_msg(id: u16, op_code: OpCode, response_code: ResponseCode) -> Message {
        let mut message: Message = Message::new();
        message.set_message_type(MessageType::Response);
        message.set_id(id);
        message.set_response_code(response_code);
        message.set_op_code(op_code);

        message
    }

    /// Truncates a Message, this blindly removes all response fields and sets trucation to `true`
    pub fn truncate(&self) -> Self {
        let mut truncated: Message = Message::new();
        truncated.set_id(self.id());
        truncated.set_message_type(self.message_type());
        truncated.set_op_code(self.op_code());
        truncated.set_authoritative(self.authoritative());
        truncated.set_truncated(true);
        truncated.set_recursion_desired(self.recursion_desired());
        truncated.set_recursion_available(self.recursion_available());
        truncated.set_response_code(self.response_code());
        if self.edns().is_some() {
            truncated.set_edns(self.edns().unwrap().clone());
        }

        // TODO, perhaps just quickly add a few response records here? that we know would fit?
        truncated
    }

    /// see `Header::set_id`
    pub fn set_id(&mut self, id: u16) -> &mut Self {
        self.header.set_id(id);
        self
    }

    /// see `Header::set_message_type`
    pub fn set_message_type(&mut self, message_type: MessageType) -> &mut Self {
        self.header.set_message_type(message_type);
        self
    }

    /// see `Header::set_op_code`
    pub fn set_op_code(&mut self, op_code: OpCode) -> &mut Self {
        self.header.set_op_code(op_code);
        self
    }

    /// see `Header::set_authoritative`
    pub fn set_authoritative(&mut self, authoritative: bool) -> &mut Self {
        self.header.set_authoritative(authoritative);
        self
    }

    /// see `Header::set_truncated`
    pub fn set_truncated(&mut self, truncated: bool) -> &mut Self {
        self.header.set_truncated(truncated);
        self
    }

    /// see `Header::set_recursion_desired`
    pub fn set_recursion_desired(&mut self, recursion_desired: bool) -> &mut Self {
        self.header.set_recursion_desired(recursion_desired);
        self
    }

    /// see `Header::set_recursion_available`
    pub fn set_recursion_available(&mut self, recursion_available: bool) -> &mut Self {
        self.header.set_recursion_available(recursion_available);
        self
    }

    /// see `Header::set_authentic_data`
    pub fn set_authentic_data(&mut self, authentic_data: bool) -> &mut Self {
        self.header.set_authentic_data(authentic_data);
        self
    }

    /// see `Header::set_checking_disabled`
    pub fn set_checking_disabled(&mut self, checking_disabled: bool) -> &mut Self {
        self.header.set_checking_disabled(checking_disabled);
        self
    }

    /// see `Header::set_response_code`
    pub fn set_response_code(&mut self, response_code: ResponseCode) -> &mut Self {
        self.header.set_response_code(response_code);
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

    /// Add an answer to the Message
    pub fn add_answer(&mut self, record: Record) -> &mut Self {
        self.answers.push(record);
        self
    }

    /// Add all the records from the iterator to the answers section of the Message
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

    /// Sets the answers to the specified set of Records.
    ///
    /// # Panics
    ///
    /// Will panic if answer records are already associated to the message.
    pub fn insert_answers(&mut self, records: Vec<Record>) {
        assert!(self.answers.is_empty());
        self.answers = records;
    }

    /// Add a name server record to the Message
    pub fn add_name_server(&mut self, record: Record) -> &mut Self {
        self.name_servers.push(record);
        self
    }

    /// Add all the records in the Iterator to the name server section of the message
    pub fn add_name_servers<R, I>(&mut self, records: R) -> &mut Self
    where
        R: IntoIterator<Item = Record, IntoIter = I>,
        I: Iterator<Item = Record>,
    {
        for record in records {
            self.add_name_server(record);
        }

        self
    }

    /// Sets the name_servers to the specified set of Records.
    ///
    /// # Panics
    ///
    /// Will panic if name_servers records are already associated to the message.
    pub fn insert_name_servers(&mut self, records: Vec<Record>) {
        assert!(self.name_servers.is_empty());
        self.name_servers = records;
    }

    /// A an addtional Record to the message
    pub fn add_additional(&mut self, record: Record) -> &mut Self {
        self.additionals.push(record);
        self
    }

    /// Sets the additional to the specified set of Records.
    ///
    /// # Panics
    ///
    /// Will panic if additional records are already associated to the message.
    pub fn insert_additionals(&mut self, records: Vec<Record>) {
        assert!(self.additionals.is_empty());
        self.additionals = records;
    }

    /// Add the EDNS section the the Message
    pub fn set_edns(&mut self, edns: Edns) -> &mut Self {
        self.edns = Some(edns);
        self
    }

    /// Add a SIG0 record, i.e. sign this message
    ///
    /// This must be don't only after all records have been associated. Generally this will be handled by the client and not need to be used directly
    #[cfg(feature = "dnssec")]
    pub fn add_sig0(&mut self, record: Record) -> &mut Self {
        assert_eq!(RecordType::DNSSEC(DNSSECRecordType::SIG), record.rr_type());
        self.sig0.push(record);
        self
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
        ResponseCode::from(
            self.edns.as_ref().map_or(0, |e| e.rcode_high()),
            self.header.response_code(),
        )
    }

    /// ```text
    /// Question        Carries the query name and other query parameters.
    /// ```
    pub fn queries(&self) -> &[Query] {
        &self.queries
    }

    /// ```text
    /// Answer          Carries RRs which directly answer the query.
    /// ```
    pub fn answers(&self) -> &[Record] {
        &self.answers
    }

    /// Removes all the answers from the Message
    pub fn take_answers(&mut self) -> Vec<Record> {
        mem::replace(&mut self.answers, vec![])
    }

    /// ```text
    /// Authority       Carries RRs which describe other authoritative servers.
    ///                 May optionally carry the SOA RR for the authoritative
    ///                 data in the answer section.
    /// ```
    pub fn name_servers(&self) -> &[Record] {
        &self.name_servers
    }

    /// Remove the name servers from the Message
    pub fn take_name_servers(&mut self) -> Vec<Record> {
        mem::replace(&mut self.name_servers, vec![])
    }

    /// ```text
    /// Additional      Carries RRs which may be helpful in using the RRs in the
    ///                 other sections.
    /// ```
    pub fn additionals(&self) -> &[Record] {
        &self.additionals
    }

    /// Remove the additional Records from the Message
    pub fn take_additionals(&mut self) -> Vec<Record> {
        mem::replace(&mut self.additionals, vec![])
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
    ///  forwarded, or stored in or loaded from master files.
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

    /// If edns is_none, this will create a new default Edns.
    pub fn edns_mut(&mut self) -> &mut Edns {
        if self.edns.is_none() {
            self.edns = Some(Edns::new());
        }

        self.edns.as_mut().unwrap()
    }

    /// # Return value
    ///
    /// the max payload value as it's defined in the EDNS section.
    pub fn max_payload(&self) -> u16 {
        let max_size = self.edns.as_ref().map_or(512, |e| e.max_payload());
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
        self.edns.as_ref().map_or(0, |e| e.version())
    }

    /// [RFC 2535, Domain Name System Security Extensions, March 1999](https://tools.ietf.org/html/rfc2535#section-4)
    ///
    /// ```text
    /// A DNS request may be optionally signed by including one or more SIGs
    ///  at the end of the query. Such SIGs are identified by having a "type
    ///  covered" field of zero. They sign the preceding DNS request message
    ///  including DNS header but not including the IP header or any request
    ///  SIGs at the end and before the request RR counts have been adjusted
    ///  for the inclusions of any request SIG(s).
    /// ```
    ///
    /// # Return value
    ///
    /// The sig0, i.e. signed record, for verifying the sending and package integrity
    pub fn sig0(&self) -> &[Record] {
        &self.sig0
    }

    // TODO only necessary in tests, should it be removed?
    /// this is necessary to match the counts in the header from the record sections
    ///  this happens implicitly on write_to, so no need to call before write_to
    #[cfg(test)]
    pub fn update_counts(&mut self) -> &mut Self {
        self.header = self.update_header_counts(true);
        self
    }

    fn update_header_counts(&self, include_sig0: bool) -> Header {
        assert!(self.queries.len() <= u16::max_value() as usize);
        assert!(self.answers.len() <= u16::max_value() as usize);
        assert!(self.name_servers.len() <= u16::max_value() as usize);
        assert!(self.additionals.len() + self.sig0.len() <= u16::max_value() as usize);

        let mut additional_count = self.additionals.len();

        if self.edns.is_some() {
            additional_count += 1
        }
        if include_sig0 {
            additional_count += self.sig0.len()
        };

        self.header.clone(
            self.queries.len() as u16,
            self.answers.len() as u16,
            self.name_servers.len() as u16,
            additional_count as u16,
        )
    }

    #[cfg_attr(not(feature = "dnssec"), allow(unused_mut))]
    fn read_records(
        decoder: &mut BinDecoder,
        count: usize,
        is_additional: bool,
    ) -> ProtoResult<(Vec<Record>, Option<Edns>, Vec<Record>)> {
        let mut records: Vec<Record> = Vec::with_capacity(count);
        let mut edns: Option<Edns> = None;
        let mut sig0s: Vec<Record> = Vec::with_capacity(if is_additional { 1 } else { 0 });

        // sig0 must be last, once this is set, disable.
        let mut saw_sig0 = false;
        for _ in 0..count {
            let record = Record::read(decoder)?;

            if !is_additional {
                if saw_sig0 {
                    return Err(
                        ProtoErrorKind::Message("sig0 must be final resource record").into(),
                    );
                } // SIG0 must be last
                records.push(record)
            } else {
                match record.rr_type() {
                    #[cfg(feature = "dnssec")]
                    RecordType::DNSSEC(DNSSECRecordType::SIG) => {
                        saw_sig0 = true;
                        sig0s.push(record);
                    }
                    RecordType::OPT => {
                        if saw_sig0 {
                            return Err(
                                ProtoErrorKind::Message(
                                    "sig0 must be final resource \
                                     record",
                                ).into(),
                            );
                        } // SIG0 must be last
                        if edns.is_some() {
                            return Err(
                                ProtoErrorKind::Message(
                                    "more than one edns record \
                                     present",
                                ).into(),
                            );
                        }
                        edns = Some((&record).into());
                    }
                    _ => {
                        if saw_sig0 {
                            return Err(
                                ProtoErrorKind::Message(
                                    "sig0 must be final resource \
                                     record",
                                ).into(),
                            );
                        } // SIG0 must be last
                        records.push(record);
                    }
                }
            }
        }

        Ok((records, edns, sig0s))
    }

    fn emit_records(encoder: &mut BinEncoder, records: &[Record]) -> ProtoResult<()> {
        for r in records {
            r.emit(encoder)?;
        }
        Ok(())
    }

    /// Decodes a message from the buffer.
    pub fn from_vec(buffer: &[u8]) -> ProtoResult<Message> {
        let mut decoder = BinDecoder::new(buffer);
        Message::read(&mut decoder)
    }

    /// Encodes the Message into a buffer
    pub fn to_vec(&self) -> Result<Vec<u8>, ProtoError> {
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
    pub fn finalize<MF: MessageFinalizer>(
        &mut self,
        finalizer: &MF,
        inception_time: u32,
    ) -> ProtoResult<()> {
        debug!("finalizing message: {:?}", self);
        let finals: Vec<Record> = finalizer.finalize_message(self, inception_time)?;

        // append all records to message
        for fin in finals {
            match fin.rr_type() {
                // SIG0's are special, and come at the very end of the message
                #[cfg(feature = "dnssec")]
                RecordType::DNSSEC(DNSSECRecordType::SIG) => self.add_sig0(fin),
                _ => self.add_additional(fin),
            };
        }

        Ok(())
    }
}

/// A trait for performing final ammendments to a Message before it is sent.
///
/// An example of this is a SIG0 signer, which needs the final form of the message,
///  but then needs to attach additional data to the body of the message.
pub trait MessageFinalizer {
    /// The message taken in should be processed and then return [`Record`]s which should be
    ///  appended to the additional section of the message.
    ///
    /// # Arguments
    ///
    /// * `message` - messge to process
    /// * `current_time` - the current time as specified by the system, it's not recommended to read the current time as that makes testing complicated.
    ///
    /// # Return
    ///
    /// A vector to append to the additionals section of the message, sorted in the order as they should appear in the message.
    fn finalize_message(&self, message: &Message, current_time: u32) -> ProtoResult<Vec<Record>>;
}

/// A MessageFinalizer which does nothing
///
/// *WARNING* This should only be used in None context, it will panic in all cases where finalize is called.
pub struct NoopMessageFinalizer;

impl NoopMessageFinalizer {
    /// Always returns None
    pub fn new() -> Option<Arc<Self>> {
        None
    }
}

impl MessageFinalizer for NoopMessageFinalizer {
    fn finalize_message(&self, _: &Message, _: u32) -> ProtoResult<Vec<Record>> {
        panic!("Misused NoopMessageFinalizer, None should be used instead")
    }
}

impl BinSerializable<Message> for Message {
    fn read(decoder: &mut BinDecoder) -> ProtoResult<Self> {
        let header = Header::read(decoder)?;

        // TODO/FIXME: return just header, and in the case of the rest of message getting an error.
        //  this could improve error detection while decoding.

        // get the questions
        let count = header.query_count() as usize;
        let mut queries = Vec::with_capacity(count);
        for _ in 0..count {
            queries.push(Query::read(decoder)?);
        }

        // get all counts before header moves
        let answer_count = header.answer_count() as usize;
        let name_server_count = header.name_server_count() as usize;
        let additional_count = header.additional_count() as usize;

        let (answers, _, _) = Self::read_records(decoder, answer_count, false)?;
        let (name_servers, _, _) = Self::read_records(decoder, name_server_count, false)?;
        let (additionals, edns, sig0) = Self::read_records(decoder, additional_count, true)?;

        Ok(Message {
            header: header,
            queries: queries,
            answers: answers,
            name_servers: name_servers,
            additionals: additionals,
            sig0: sig0,
            edns: edns,
        })
    }

    fn emit(&self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        // clone the header to set the counts lazily
        let include_sig0: bool = encoder.mode() != EncodeMode::Signing;
        self.update_header_counts(include_sig0).emit(encoder)?;

        for q in &self.queries {
            q.emit(encoder)?;
        }

        // TODO this feels like the right place to verify the max packet size of the message,
        //  will need to update the header for trucation and the lengths if we send less than the
        //  full response.
        Self::emit_records(encoder, &self.answers)?;
        Self::emit_records(encoder, &self.name_servers)?;
        Self::emit_records(encoder, &self.additionals)?;

        if let Some(edns) = self.edns() {
            // need to commit the error code
            Record::from(edns).emit(encoder)?;
        }

        // this is a little hacky, but if we are Verifying a signature, i.e. the original Message
        //  then the SIG0 records should not be encoded and the edns record (if it exists) is already
        //  part of the additionals section.
        if include_sig0 {
            Self::emit_records(encoder, &self.sig0)?;
        }
        Ok(())
    }
}

#[test]
fn test_emit_and_read_header() {
    let mut message = Message::new();
    message
        .set_id(10)
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Update)
        .set_authoritative(true)
        .set_truncated(true)
        .set_recursion_desired(true)
        .set_recursion_available(true)
        .set_response_code(ResponseCode::ServFail);

    test_emit_and_read(message);
}

#[test]
fn test_emit_and_read_query() {
    let mut message = Message::new();
    message
        .set_id(10)
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Update)
        .set_authoritative(true)
        .set_truncated(true)
        .set_recursion_desired(true)
        .set_recursion_available(true)
        .set_response_code(ResponseCode::ServFail)
        .add_query(Query::new())
        .update_counts(); // we're not testing the query parsing, just message

    test_emit_and_read(message);
}

#[test]
fn test_emit_and_read_records() {
    let mut message = Message::new();
    message
        .set_id(10)
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Update)
        .set_authoritative(true)
        .set_truncated(true)
        .set_recursion_desired(true)
        .set_recursion_available(true)
        .set_authentic_data(true)
        .set_checking_disabled(true)
        .set_response_code(ResponseCode::ServFail);

    message.add_answer(Record::new());
    message.add_name_server(Record::new());
    message.add_additional(Record::new());
    message.update_counts(); // needed for the comparison...

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
#[cfg_attr(rustfmt, rustfmt_skip)]
fn test_legit_message() {
    let buf: Vec<u8> = vec![
  0x10,0x00,0x81,0x80, // id = 4096, response, op=query, recursion_desired, recursion_available, no_error
  0x00,0x01,0x00,0x01, // 1 query, 1 answer,
  0x00,0x00,0x00,0x00, // 0 namesservers, 0 additional record

  0x03,b'w',b'w',b'w', // query --- www.example.com
  0x07,b'e',b'x',b'a', //
  b'm',b'p',b'l',b'e', //
  0x03,b'c',b'o',b'm', //
  0x00,                // 0 = endname
  0x00,0x01,0x00,0x01, // ReordType = A, Class = IN

  0xC0,0x0C,           // name pointer to www.example.com
  0x00,0x01,0x00,0x01, // RecordType = A, Class = IN
  0x00,0x00,0x00,0x02, // TTL = 2 seconds
  0x00,0x04,           // record length = 4 (ipv4 address)
  0x5D,0xB8,0xD8,0x22, // address = 93.184.216.34
  ];

    let mut decoder = BinDecoder::new(&buf);
    let message = Message::read(&mut decoder).unwrap();

    assert_eq!(message.id(), 4096);

    let mut buf: Vec<u8> = Vec::with_capacity(512);
    {
        let mut encoder = BinEncoder::new(&mut buf);
        message.emit(&mut encoder).unwrap();
    }

    let mut decoder = BinDecoder::new(&buf);
    let message = Message::read(&mut decoder).unwrap();

    assert_eq!(message.id(), 4096);
}
