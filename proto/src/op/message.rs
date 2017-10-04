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

use std::fmt::Debug;
use std::mem;

use error::*;
use rr::{Record, RecordType};
#[cfg(feature = "openssl")]
use rr::{DNSClass, Name, RData};
#[cfg(feature = "openssl")]
use rr::rdata::SIG;
use rr::dnssec::Signer;
use serialize::binary::{BinEncoder, BinDecoder, BinSerializable, EncodeMode};
use super::{MessageType, Header, Query, Edns, OpCode, ResponseCode};

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
#[derive(Clone, Debug, PartialEq)]
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

    /// Adds a slice of Queries to the message
    #[deprecated = "will be removed post 0.9.x"]
    pub fn add_all_queries(&mut self, queries: &[Query]) -> &mut Self {
        for q in queries {
            // TODO: the clone here should really be performed (or not) by the caller
            self.add_query(q.clone());
        }
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

    /// Add an entire set of Answers
    #[deprecated = "will be removed post 0.9.x"]
    pub fn add_all_answers(&mut self, vector: &[&Record]) -> &mut Self {
        for &r in vector {
            // TODO: in order to get rid of this clone, we need an owned Message for decoding, and a
            //  reference Message for encoding.
            self.add_answer(r.clone());
        }
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

    /// Adds a set of name server records to the message
    #[deprecated = "will be removed post 0.9.x"]
    pub fn add_all_name_servers(&mut self, vector: &[&Record]) -> &mut Self {
        for &r in vector {
            // TODO: in order to get rid of this clone, we need an owned Message for decoding, and a
            //  reference Message for encoding.
            self.add_name_server(r.clone());
        }
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
    pub fn add_sig0(&mut self, record: Record) -> &mut Self {
        assert_eq!(RecordType::SIG, record.rr_type());
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
        if max_size < 512 { 512 } else { max_size }
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
    fn sig0(&self) -> &[Record] {
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

    fn read_records(
        decoder: &mut BinDecoder,
        count: usize,
        is_additional: bool,
    ) -> DecodeResult<(Vec<Record>, Option<Edns>, Vec<Record>)> {
        let mut records: Vec<Record> = Vec::with_capacity(count);
        let mut edns: Option<Edns> = None;
        let mut sig0s: Vec<Record> = Vec::with_capacity(if is_additional { 1 } else { 0 });

        // sig0 must be last, once this is set, disable.
        let mut saw_sig0 = false;
        for _ in 0..count {
            let record = try!(Record::read(decoder));

            if !is_additional {
                if saw_sig0 {
                    return Err(
                        DecodeErrorKind::Message("sig0 must be final resource record").into(),
                    );
                } // SIG0 must be last
                records.push(record)
            } else {
                match record.rr_type() {
                    RecordType::SIG => {
                        saw_sig0 = true;
                        sig0s.push(record);
                    }
                    RecordType::OPT => {
                        if saw_sig0 {
                            return Err(
                                DecodeErrorKind::Message(
                                    "sig0 must be final resource \
                                                                 record",
                                ).into(),
                            );
                        } // SIG0 must be last
                        if edns.is_some() {
                            return Err(
                                DecodeErrorKind::Message(
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
                                DecodeErrorKind::Message(
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

    fn emit_records(encoder: &mut BinEncoder, records: &Vec<Record>) -> EncodeResult {
        for r in records {
            try!(r.emit(encoder));
        }
        Ok(())
    }

    /// Decodes a message from the buffer.
    pub fn from_vec(buffer: &[u8]) -> DecodeResult<Message> {
        let mut decoder = BinDecoder::new(buffer);
        Message::read(&mut decoder)
    }

    /// Encodes the Message into a buffer
    pub fn to_vec(&self) -> Result<Vec<u8>, EncodeError> {
        let mut buffer = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut buffer);
            try!(self.emit(&mut encoder));
        }

        Ok(buffer)
    }

    /// Sign the message, i.e. add a SIG0 record to this Message.
    ///
    /// Subsequent to calling this, the Message should not change.
    #[cfg(feature = "openssl")]
    pub fn sign(&mut self, signer: &Signer, inception_time: u32) -> DnsSecResult<()> {
        debug!("signing message: {:?}", self);
        let key_tag: u16 = try!(signer.calculate_key_tag());

        // this is based on RFCs 2535, 2931 and 3007

        // 'For all SIG(0) RRs, the owner name, class, TTL, and original TTL, are
        //  meaningless.' - 2931
        let mut sig0 = Record::new();

        // The TTL fields SHOULD be zero
        sig0.set_ttl(0);

        // The CLASS field SHOULD be ANY
        sig0.set_dns_class(DNSClass::ANY);

        // The owner name SHOULD be root (a single zero octet).
        sig0.set_name(Name::root());
        let num_labels = sig0.name().num_labels();

        let expiration_time: u32 = inception_time + (5 * 60); // +5 minutes in seconds

        sig0.set_rr_type(RecordType::SIG);
        let pre_sig0 = SIG::new(
            // type covered in SIG(0) is 0 which is what makes this SIG0 vs a standard SIG
            RecordType::NULL,
            signer.algorithm(),
            num_labels,
            // see above, original_ttl is meaningless, The TTL fields SHOULD be zero
            0,
            // recommended time is +5 minutes from now, to prevent timing attacks, 2 is probably good
            expiration_time,
            // current time, this should be UTC
            // unsigned numbers of seconds since the start of 1 January 1970, GMT
            inception_time,
            key_tag,
            // can probably get rid of this clone if the owndership is correct
            signer.signer_name().clone(),
            Vec::new(),
        );
        let signature: Vec<u8> = try!(signer.sign_message(self, &pre_sig0));
        sig0.set_rdata(RData::SIG(pre_sig0.set_sig(signature)));

        debug!("sig0: {:?}", sig0);

        self.add_sig0(sig0);
        Ok(())
    }

    /// Always returns an error; enable OpenSSL for signing support
    #[cfg(not(feature = "openssl"))]
    pub fn sign(&mut self, _: &Signer, _: u32) -> DnsSecResult<()> {
        Err(
            DnsSecErrorKind::Message("openssl feature not enabled").into(),
        )
    }
}

/// To reduce errors in using the Message struct as an Update, this will do the call throughs
///   to properly do that.
///
/// Generally rather than constructin this by hand, see the update methods on `Client`
pub trait UpdateMessage: Debug {
    /// see `Header::id`
    fn id(&self) -> u16;

    /// Adds the zone section, i.e. name.example.com would be example.com
    fn add_zone(&mut self, query: Query);

    /// Add the pre-requisite records
    ///
    /// These must exist, or not, for the Update request to go through.
    fn add_pre_requisite(&mut self, record: Record);

    /// Add all pre-requisites to the UpdateMessage
    #[deprecated = "will be removed post 0.9.x"]
    fn add_all_pre_requisites(&mut self, vector: &[&Record]);

    /// Add all the Records from the Iterator to the pre-reqisites section
    fn add_pre_requisites<R, I>(&mut self, records: R)
    where
        R: IntoIterator<Item = Record, IntoIter = I>,
        I: Iterator<Item = Record>;

    /// Add the Record to be updated
    fn add_update(&mut self, record: Record);

    /// Add the set of Records to be updated
    #[deprecated = "will be removed post 0.9.x"]
    fn add_all_updates(&mut self, vector: &[&Record]);

    /// Add the Records from the Iterator to the updates section
    fn add_updates<R, I>(&mut self, records: R)
    where
        R: IntoIterator<Item = Record, IntoIter = I>,
        I: Iterator<Item = Record>;

    /// Add Records to the additional Section of hte UpdateMessage
    fn add_additional(&mut self, record: Record);

    /// Returns the Zones to be updated, generally should only be one.
    fn zones(&self) -> &[Query];

    /// Returns the pre-requisites
    fn prerequisites(&self) -> &[Record];

    /// Returns the records to be updated
    fn updates(&self) -> &[Record];

    /// Returns the additonal records
    fn additionals(&self) -> &[Record];

    /// This is used to authenticate update messages.
    ///
    /// see `Message::sig0()` for more information.
    fn sig0(&self) -> &[Record];

    /// Signs the UpdateMessage, used to validate the authenticity and authorization of UpdateMessage
    fn sign(&mut self, signer: &Signer, inception_time: u32) -> DnsSecResult<()>;
}

/// to reduce errors in using the Message struct as an Update, this will do the call throughs
///   to properly do that.
impl UpdateMessage for Message {
    fn id(&self) -> u16 {
        self.id()
    }
    fn add_zone(&mut self, query: Query) {
        self.add_query(query);
    }
    fn add_pre_requisite(&mut self, record: Record) {
        self.add_answer(record);
    }
    fn add_all_pre_requisites(&mut self, vector: &[&Record]) {
        self.add_answers(vector.into_iter().map(|r| (*r).clone()));
    }
    fn add_pre_requisites<R, I>(&mut self, records: R)
    where
        R: IntoIterator<Item = Record, IntoIter = I>,
        I: Iterator<Item = Record>,
    {
        self.add_answers(records);
    }
    fn add_update(&mut self, record: Record) {
        self.add_name_server(record);
    }
    fn add_all_updates(&mut self, vector: &[&Record]) {
        self.add_name_servers(vector.into_iter().map(|r| (*r).clone()));
    }
    fn add_updates<R, I>(&mut self, records: R)
    where
        R: IntoIterator<Item = Record, IntoIter = I>,
        I: Iterator<Item = Record>,
    {
        self.add_name_servers(records);
    }
    fn add_additional(&mut self, record: Record) {
        self.add_additional(record);
    }

    fn zones(&self) -> &[Query] {
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

    // TODO: where's the 'right' spot for this function

    fn sign(&mut self, signer: &Signer, inception_time: u32) -> DnsSecResult<()> {
        Message::sign(self, signer, inception_time)
    }
}

impl BinSerializable<Message> for Message {
    fn read(decoder: &mut BinDecoder) -> DecodeResult<Self> {
        let header = try!(Header::read(decoder));

        // TODO/FIXME: return just header, and in the case of the rest of message getting an error.
        //  this could improve error detection while decoding.

        // get the questions
        let count = header.query_count() as usize;
        let mut queries = Vec::with_capacity(count);
        for _ in 0..count {
            queries.push(try!(Query::read(decoder)));
        }

        // get all counts before header moves
        let answer_count = header.answer_count() as usize;
        let name_server_count = header.name_server_count() as usize;
        let additional_count = header.additional_count() as usize;

        let (answers, _, _) = try!(Self::read_records(decoder, answer_count, false));
        let (name_servers, _, _) = try!(Self::read_records(decoder, name_server_count, false));
        let (additionals, edns, sig0) = try!(Self::read_records(decoder, additional_count, true));

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

    fn emit(&self, encoder: &mut BinEncoder) -> EncodeResult {
        // clone the header to set the counts lazily
        let include_sig0: bool = encoder.mode() != EncodeMode::Signing;
        try!(self.update_header_counts(include_sig0).emit(encoder));

        for q in &self.queries {
            try!(q.emit(encoder));
        }

        // TODO this feels like the right place to verify the max packet size of the message,
        //  will need to update the header for trucation and the lengths if we send less than the
        //  full response.
        try!(Self::emit_records(encoder, &self.answers));
        try!(Self::emit_records(encoder, &self.name_servers));
        try!(Self::emit_records(encoder, &self.additionals));

        if let Some(edns) = self.edns() {
            // need to commit the error code
            try!(Record::from(edns).emit(encoder));
        }

        // this is a little hacky, but if we are Verifying a signature, i.e. the original Message
        //  then the SIG0 records should not be encoded and the edns record (if it exists) is already
        //  part of the additionals section.
        if include_sig0 {
            try!(Self::emit_records(encoder, &self.sig0));
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
