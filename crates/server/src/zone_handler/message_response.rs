// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use tracing::{debug, error};

use crate::{
    net::xfer::Protocol,
    proto::{
        ProtoError,
        op::{
            Edns, Header, HeaderCounts, MessageRequest, MessageType, Metadata, OpCode, Queries,
            QueriesEmitAndCount, ResponseCode, emit_message_parts,
        },
        rr::{RData, Record, rdata::TSIG},
        serialize::binary::{BinEncodable, BinEncoder},
    },
    server::ResponseInfo,
};

/// A [`crate::proto::serialize::binary::BinEncodable`] message with borrowed data for
/// Responses in the Server
///
/// This can be constructed via [`MessageResponseBuilder`].
#[derive(Debug)]
pub struct MessageResponse<'q, 'a, Answers, Authorities, Soa, Additionals>
where
    Answers: Iterator<Item = &'a Record> + Send + 'a,
    Authorities: Iterator<Item = &'a Record> + Send + 'a,
    Soa: Iterator<Item = &'a Record> + Send + 'a,
    Additionals: Iterator<Item = &'a Record> + Send + 'a,
{
    metadata: Metadata,
    queries: Option<&'q Queries>,
    answers: Answers,
    authorities: Authorities,
    soa: Soa,
    additionals: Additionals,
    signature: Option<Box<Record<TSIG>>>,
    edns: Option<&'q Edns>,
}

impl<'q, 'a, A, N, S, D> MessageResponse<'q, 'a, A, N, S, D>
where
    A: Iterator<Item = &'a Record> + Send + 'a,
    N: Iterator<Item = &'a Record> + Send + 'a,
    S: Iterator<Item = &'a Record> + Send + 'a,
    D: Iterator<Item = &'a Record> + Send + 'a,
{
    /// Returns the header of the message
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Get a mutable reference to the header
    pub fn metadata_mut(&mut self) -> &mut Metadata {
        &mut self.metadata
    }

    /// Set the EDNS options for the Response
    pub fn set_edns(&mut self, edns: &'q Edns) -> &mut Self {
        self.edns = Some(edns);
        self
    }

    /// Gets a reference to the EDNS options for the Response.
    pub fn edns(&self) -> Option<&'q Edns> {
        self.edns
    }

    /// Set the message signature
    pub fn set_signature(&mut self, signature: Box<Record<TSIG>>) {
        self.signature = Some(signature);
    }

    pub(crate) fn encode(self, protocol: Protocol) -> Result<(ResponseInfo, Vec<u8>), ProtoError> {
        let id = self.metadata.id;
        debug!(
            id,
            response_code = %self.metadata.response_code,
            "encoding response"
        );

        let mut bytes = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut bytes);
        encoder.set_max_size(match protocol {
            Protocol::Udp => match &self.edns {
                Some(edns) => edns.max_payload(),
                // No EDNS, so the requestor advertised no buffer and RFC 1035 section 4.2.1
                // restricts the message to 512 bytes
                None => 512,
            },
            _ => u16::MAX,
        });

        let error = match self.destructive_emit(&mut encoder) {
            Ok(info) => return Ok((info, bytes)),
            Err(error) => error,
        };

        error!(%error, "error encoding message");
        bytes.clear();
        let mut encoder = BinEncoder::new(&mut bytes);
        encoder.set_max_size(512);

        let mut metadata = Metadata::new(id, MessageType::Response, OpCode::Query);
        metadata.response_code = ResponseCode::ServFail;
        let header = Header {
            metadata,
            counts: HeaderCounts::default(),
        };

        header.emit(&mut encoder)?;
        Ok((ResponseInfo::from(header), bytes))
    }

    /// Consumes self, and emits to the encoder.
    pub fn destructive_emit(
        mut self,
        encoder: &mut BinEncoder<'_>,
    ) -> Result<ResponseInfo, ProtoError> {
        // Note down the TTLs for the Cache-Control header as we iterate over records
        let mut min_answer_ttl = None;
        let mut soa_ttl = None;

        let mut answers = self.answers.inspect(|record| {
            min_answer_ttl = Some(match min_answer_ttl {
                Some(ttl) => record.ttl.min(ttl),
                None => record.ttl,
            });
        });

        // soa records are part of the authority section
        let mut authorities = self.authorities.chain(self.soa).inspect(|record| {
            if soa_ttl.is_none() {
                if let RData::SOA(soa) = &record.data {
                    soa_ttl = Some(record.ttl.min(soa.minimum));
                }
            }
        });

        let header = emit_message_parts(
            &self.metadata,
            &mut match self.queries {
                Some(queries) => queries.as_emit_and_count(),
                None => QueriesEmitAndCount::None,
            },
            &mut answers,
            &mut authorities,
            &mut self.additionals,
            self.edns,
            self.signature.as_deref(),
            encoder,
        )?;

        // the TTLs are ours to read again once the two closures above are gone
        drop((answers, authorities));

        Ok(ResponseInfo::new(
            header,
            cache_ttl(&header.metadata, min_answer_ttl, soa_ttl),
        ))
    }
}

/// Returns the TTL this response may be cached for, if it is cacheable.
///
/// The TTL is derived according to DoH RFC 8484 section 5.1 and RFC 2308 section 5
/// `None` means the response is non cacheable, because it is a non-query opcode,
/// a rcode that is neither NoError nor NXDomain, or is a negative answer with no SOA.
fn cache_ttl(
    metadata: &Metadata,
    min_answer_ttl: Option<u32>,
    soa_ttl: Option<u32>,
) -> Option<u32> {
    let OpCode::Query = metadata.op_code else {
        return None;
    };

    match metadata.response_code {
        ResponseCode::NoError => min_answer_ttl.or(soa_ttl),
        ResponseCode::NXDomain => soa_ttl,
        _ => None,
    }
}

/// A builder for MessageResponses
pub struct MessageResponseBuilder<'q> {
    queries: Option<&'q Queries>,
    signature: Option<Box<Record<TSIG>>>,
    edns: Option<&'q Edns>,
}

impl<'q> MessageResponseBuilder<'q> {
    /// Constructs a new response builder
    ///
    /// # Arguments
    ///
    /// * `message` - original request message to associate with the response
    ///
    /// # Example
    ///
    /// ```rust
    /// use hickory_proto::{op::ResponseCode, rr::Record};
    /// use hickory_server::{
    ///     server::Request,
    ///     zone_handler::{MessageResponse, MessageResponseBuilder},
    /// };
    ///
    /// fn handle_request<'q>(request: &'q Request) -> MessageResponse<
    ///     'q,
    ///     'static,
    ///     impl Iterator<Item = &'static Record> + Send + 'static,
    ///     impl Iterator<Item = &'static Record> + Send + 'static,
    ///     impl Iterator<Item = &'static Record> + Send + 'static,
    ///     impl Iterator<Item = &'static Record> + Send + 'static,
    /// > {
    ///     MessageResponseBuilder::from_message_request(request)
    ///         .error_msg(&request.metadata, ResponseCode::ServFail)
    /// }
    /// ```
    pub fn from_message_request(message: &'q MessageRequest) -> Self {
        Self::new(&message.queries, None)
    }

    /// Constructs a new response builder
    ///
    /// # Arguments
    ///
    /// * `queries` - queries (from the Request) to associate with the Response
    /// * `edns` - Optional Edns data to associate with the Response
    pub fn new(queries: &'q Queries, edns: Option<&'q Edns>) -> Self {
        MessageResponseBuilder {
            queries: Some(queries),
            signature: None,
            edns,
        }
    }

    /// Constructs a new response builder for a request with no queries
    ///
    /// # Arguments
    ///
    /// * `edns` - Optional Edns data to associate with the Response
    pub fn no_queries(edns: Option<&'q Edns>) -> Self {
        MessageResponseBuilder {
            queries: None,
            signature: None,
            edns,
        }
    }

    /// Associate EDNS with the Response
    pub fn edns(&mut self, edns: &'q Edns) -> &mut Self {
        self.edns = Some(edns);
        self
    }

    /// Constructs the new MessageResponse with associated data
    pub fn build<'a, A, N, S, D>(
        self,
        metadata: Metadata,
        answers: A,
        authorities: N,
        soa: S,
        additionals: D,
    ) -> MessageResponse<'q, 'a, A::IntoIter, N::IntoIter, S::IntoIter, D::IntoIter>
    where
        A: IntoIterator<Item = &'a Record> + Send + 'a,
        A::IntoIter: Send,
        N: IntoIterator<Item = &'a Record> + Send + 'a,
        N::IntoIter: Send,
        S: IntoIterator<Item = &'a Record> + Send + 'a,
        S::IntoIter: Send,
        D: IntoIterator<Item = &'a Record> + Send + 'a,
        D::IntoIter: Send,
    {
        MessageResponse {
            metadata,
            queries: self.queries,
            answers: answers.into_iter(),
            authorities: authorities.into_iter(),
            soa: soa.into_iter(),
            additionals: additionals.into_iter(),
            signature: self.signature,
            edns: self.edns,
        }
    }

    /// Construct a Response with no associated records
    pub fn build_no_records<'a>(
        self,
        metadata: Metadata,
    ) -> MessageResponse<
        'q,
        'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
    > {
        MessageResponse {
            metadata,
            queries: self.queries,
            answers: Box::new(None.into_iter()),
            authorities: Box::new(None.into_iter()),
            soa: Box::new(None.into_iter()),
            additionals: Box::new(None.into_iter()),
            signature: self.signature,
            edns: self.edns,
        }
    }

    /// Constructs a new error MessageResponse with associated header and response code
    pub fn error_msg<'a>(
        self,
        request_meta: &Metadata,
        response_code: ResponseCode,
    ) -> MessageResponse<
        'q,
        'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
    > {
        let mut metadata = Metadata::response_from_request(request_meta);
        metadata.response_code = response_code;

        MessageResponse {
            metadata,
            queries: self.queries,
            answers: Box::new(None.into_iter()),
            authorities: Box::new(None.into_iter()),
            soa: Box::new(None.into_iter()),
            additionals: Box::new(None.into_iter()),
            signature: self.signature,
            edns: self.edns,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::iter;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use crate::proto::op::{Header, Message, MessageType, Metadata, OpCode, Query};
    use crate::proto::rr::rdata::SOA;
    use crate::proto::rr::{DNSClass, Name, RData, Record};
    use crate::proto::serialize::binary::{BinDecodable, BinDecoder, BinEncoder};

    use super::*;

    #[test]
    fn test_truncation_ridiculous_number_answers() {
        let mut buf = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut buf);
            encoder.set_max_size(512);

            let mut answer = Record::from_rdata(
                Name::from_str("www.example.com.").unwrap(),
                0,
                RData::A(Ipv4Addr::new(93, 184, 215, 14).into()),
            );
            answer.dns_class = DNSClass::NONE;

            let request = MessageRequest::mock(
                Metadata::new(10, MessageType::Query, OpCode::Query),
                Query::root(),
            );

            let response = MessageResponseBuilder::from_message_request(&request).build(
                Metadata::new(10, MessageType::Response, OpCode::Query),
                iter::repeat(&answer),
                iter::repeat(&answer),
                iter::repeat(&answer),
                iter::repeat(&answer),
            );

            response
                .destructive_emit(&mut encoder)
                .expect("failed to encode");
        }

        let response = Message::from_vec(&buf).expect("failed to decode");
        assert!(response.metadata.truncation);
        assert!(response.answers.len() > 1);
        // should never have written the authority section...
        assert_eq!(response.authorities.len(), 0);
    }

    #[test]
    fn test_truncation_ridiculous_number_nameservers() {
        let mut buf = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut buf);
            encoder.set_max_size(512);

            let mut answer = Record::from_rdata(
                Name::from_str("www.example.com.").unwrap(),
                0,
                RData::A(Ipv4Addr::new(93, 184, 215, 14).into()),
            );
            answer.dns_class = DNSClass::NONE;

            let request = MessageRequest::mock(
                Metadata::new(10, MessageType::Query, OpCode::Query),
                Query::root(),
            );

            let response = MessageResponseBuilder::from_message_request(&request).build(
                Metadata::new(10, MessageType::Response, OpCode::Query),
                [],
                iter::repeat(&answer),
                iter::repeat(&answer),
                iter::repeat(&answer),
            );

            response
                .destructive_emit(&mut encoder)
                .expect("failed to encode");
        }

        let response = Message::from_vec(&buf).expect("failed to decode");
        assert!(response.metadata.truncation);
        assert_eq!(response.answers.len(), 0);
        assert!(response.authorities.len() > 1);
    }

    /// A response with no OPT record answers a request that had none, so RFC 1035 section 4.2.1
    /// applies and the message may not exceed 512 bytes.
    #[test]
    fn test_non_edns_udp_response_is_bounded_at_512() {
        let answer = Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            0,
            RData::A(Ipv4Addr::new(93, 184, 215, 14).into()),
        );

        let request = MessageRequest::mock(
            Metadata::new(10, MessageType::Query, OpCode::Query),
            Query::root(),
        );
        assert_eq!(request.max_payload(), 512);

        let response = MessageResponseBuilder::from_message_request(&request).build(
            Metadata::new(10, MessageType::Response, OpCode::Query),
            iter::repeat(&answer),
            [],
            [],
            [],
        );

        let (_info, buf) = response.encode(Protocol::Udp).expect("failed to encode");
        assert!(buf.len() <= 512, "response was {} bytes", buf.len());

        let response = Message::from_vec(&buf).expect("failed to decode");
        assert!(response.metadata.truncation);
        assert!(response.answers.len() > 1);
    }

    /// RFC 6891 section 7 requires the OPT record to be present even when the response is
    /// truncated, so answers have to give way to it rather than the other way around.
    #[test]
    fn test_opt_record_is_kept_when_truncating() {
        let answer = Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            0,
            RData::A(Ipv4Addr::new(93, 184, 215, 14).into()),
        );

        let mut edns = Edns::new();
        edns.set_max_payload(512);

        let request = MessageRequest::mock(
            Metadata::new(10, MessageType::Query, OpCode::Query),
            Query::root(),
        );
        let mut response = MessageResponseBuilder::from_message_request(&request).build(
            Metadata::new(10, MessageType::Response, OpCode::Query),
            iter::repeat(&answer),
            [],
            [],
            [],
        );
        response.set_edns(&edns);

        let (_info, buf) = response.encode(Protocol::Udp).expect("failed to encode");
        assert!(buf.len() <= 512, "response was {} bytes", buf.len());

        let response = Message::from_vec(&buf).expect("failed to decode");
        assert!(response.metadata.truncation);
        assert!(response.answers.len() > 1);
        assert!(response.edns.is_some(), "OPT record was dropped");
    }

    // https://github.com/hickory-dns/hickory-dns/issues/2210
    // If a client sends this DNS request to the hickory 0.24.0 DNS server:
    //
    // 08 00 00 00 00 01 00 00 00 00 00 00 c0 00 00 00 00 00 00 00 00 00 00
    // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    // 00 00
    //
    // i.e.:
    // 08 00 ID
    // 00 00 flags
    // 00 01 QDCOUNT
    // 00 00 ANCOUNT
    // 00 00 NSCOUNT
    // 00 00 ARCOUNT
    // c0 00 QNAME
    // 00 00 QTYPE
    // 00 00 QCLASS
    //
    // hickory-dns fails the 2nd assert here while building the reply message
    // (really while remembering names for pointers):
    //
    // pub fn slice_of(&self, start: usize, end: usize) -> &[u8] {
    //     assert!(start < self.offset);
    //     assert!(end <= self.buffer.len());
    //     &self.buffer.buffer()[start..end]
    // }
    // The name is eight bytes long, but the current message size (after the
    // current offset of 12) is only six, because QueriesEmitAndCount::emit()
    // stored just the six bytes of the original encoded query:
    //
    //     encoder.emit_vec(self.cached_serialized)?;
    #[test]
    fn bad_length_of_named_pointers() {
        let mut buf = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut buf);

        let data: &[u8] = &[
            0x08u8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let mut decoder = BinDecoder::new(data);
        let header = Header::read(&mut decoder).unwrap();
        let msg = MessageRequest::read(&mut decoder, header).unwrap();

        eprintln!("query: {:?}", *msg.queries);

        MessageResponseBuilder::new(&msg.queries, None)
            .build_no_records(Metadata::response_from_request(&msg.metadata))
            .destructive_emit(&mut encoder)
            .unwrap();
    }

    #[test]
    fn cache_ttl_positive_takes_smallest_answer_ttl() {
        // The smallest value sits in the middle, so this distinguishes a true minimum
        // from simply taking the first or last answer.
        let answers = [answer(300), answer(100), answer(200)];

        assert_eq!(
            encode_and_get_cache_ttl(response(ResponseCode::NoError), &answers, &[]),
            Some(100)
        );
    }

    #[test]
    fn cache_ttl_nodata_falls_back_to_soa_record_ttl() {
        // NODATA: NoError with an empty answer section. Here the SOA's own TTL is the
        // lesser of the two values.
        assert_eq!(
            encode_and_get_cache_ttl(response(ResponseCode::NoError), &[], &[soa(200, 500)]),
            Some(200)
        );
    }

    #[test]
    fn cache_ttl_nodata_falls_back_to_soa_minimum() {
        // Same as above with the two SOA values swapped, pinning down that the rule is a
        // minimum of both fields rather than either one alone.
        assert_eq!(
            encode_and_get_cache_ttl(response(ResponseCode::NoError), &[], &[soa(500, 200)]),
            Some(200)
        );
    }

    #[test]
    fn cache_ttl_nxdomain_ignores_answers_and_uses_soa() {
        // A Name Error may still carry answers: the CNAMEs followed before reaching the
        // name that does not exist. The response code must win over their TTLs.
        assert_eq!(
            encode_and_get_cache_ttl(
                response(ResponseCode::NXDomain),
                &[answer(900)],
                &[soa(300, 600)]
            ),
            Some(300)
        );
    }

    #[test]
    fn cache_ttl_negative_without_soa_is_uncacheable() {
        assert_eq!(
            encode_and_get_cache_ttl(response(ResponseCode::NoError), &[], &[]),
            None
        );
    }

    #[test]
    fn cache_ttl_error_response_is_uncacheable() {
        // An SOA is present, so this fails if the response code is not checked.
        assert_eq!(
            encode_and_get_cache_ttl(response(ResponseCode::ServFail), &[], &[soa(300, 600)]),
            None
        );
    }

    #[test]
    fn cache_ttl_non_query_opcode_is_uncacheable() {
        // Answers are present, so this fails if the opcode is not checked. An UPDATE is
        // neither safe nor idempotent and must never be cached.
        let metadata = Metadata::new(0, MessageType::Response, OpCode::Update);

        assert_eq!(
            encode_and_get_cache_ttl(metadata, &[answer(100)], &[]),
            None
        );
    }

    /// Builds a response out of the given sections, writes it out, and reports back how long
    /// it may be cached for.
    fn encode_and_get_cache_ttl(
        metadata: Metadata,
        answers: &[Record],
        authorities: &[Record],
    ) -> Option<u32> {
        let request = MessageRequest::mock(
            Metadata::new(metadata.id, MessageType::Query, metadata.op_code),
            Query::root(),
        );

        let (info, _bytes) = MessageResponseBuilder::from_message_request(&request)
            .build(metadata, answers, authorities, [], [])
            .encode(Protocol::Tcp)
            .expect("failed to encode");

        info.cache_ttl()
    }

    /// An answer-section record with the given TTL. The name and address are irrelevant.
    fn answer(ttl: u32) -> Record {
        Record::from_rdata(Name::root(), ttl, RData::A(Ipv4Addr::LOCALHOST.into()))
    }

    /// An authority-section SOA whose record TTL and MINIMUM field are set independently,
    /// so tests can tell which of the two RFC 2308 section 5 takes the minimum of.
    fn soa(record_ttl: u32, minimum: u32) -> Record {
        Record::from_rdata(
            Name::root(),
            record_ttl,
            RData::SOA(SOA::new(Name::root(), Name::root(), 1, 0, 0, 0, minimum)),
        )
    }

    fn response(response_code: ResponseCode) -> Metadata {
        let mut metadata = Metadata::new(0, MessageType::Response, OpCode::Query);
        metadata.response_code = response_code;
        metadata
    }
}
