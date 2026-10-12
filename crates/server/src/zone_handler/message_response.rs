// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[cfg(feature = "__dnssec")]
use std::iter;

use tracing::{debug, error};

#[cfg(feature = "__dnssec")]
use crate::proto::rr::TSigResponseContext;
use crate::{
    net::xfer::Protocol,
    proto::{
        ProtoError,
        op::{
            Edns, Header, HeaderCounts, MessageRequest, MessageType, Metadata, OpCode, Queries,
            QueriesEmitAndCount, ResponseCode, emit_message_parts,
        },
        rr::{Record, rdata::TSIG},
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
    #[cfg(feature = "__dnssec")]
    signer: Option<TSigResponseContext>,
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

    /// Set an already built TSIG record to emit with the response
    ///
    /// The record is emitted as it stands, so it only matches the bytes on the wire when the
    /// response does not have to shed records. [`Self::set_signer`] signs what is actually sent.
    pub fn set_signature(&mut self, signature: Box<Record<TSIG>>) {
        self.signature = Some(signature);
    }

    /// Set the TSIG signer for the response
    ///
    /// The MAC covers the encoded message, and which records survive the transport's size limit
    /// is not known until the message has been encoded, so the signing happens during
    /// [`Self::encode`] rather than ahead of it.
    #[cfg(feature = "__dnssec")]
    pub fn set_signer(&mut self, signer: TSigResponseContext) {
        self.signer = Some(signer);
    }

    /// Encodes the response for `protocol`.
    ///
    /// Applies the message size limit for `protocol`, and signs the result if a signer was set
    /// with [`Self::set_signer`].
    pub fn encode(self, protocol: Protocol) -> Result<(ResponseInfo, Vec<u8>), ProtoError> {
        let id = self.metadata.id;
        debug!(
            id,
            response_code = %self.metadata.response_code,
            "encoding response"
        );

        let max_size = match protocol {
            Protocol::Udp => match &self.edns {
                Some(edns) => edns.max_payload(),
                // No EDNS, so the requestor advertised no buffer and RFC 1035 section 4.2.1
                // restricts the message to 512 bytes
                None => 512,
            },
            _ => u16::MAX,
        };

        let mut bytes = Vec::with_capacity(512);
        let error = match self.emit_and_sign(&mut bytes, max_size) {
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

    /// Emits the response into `bytes`, applying `max_size`.
    #[cfg(not(feature = "__dnssec"))]
    fn emit_and_sign(self, bytes: &mut Vec<u8>, max_size: u16) -> Result<ResponseInfo, ProtoError> {
        let mut encoder = BinEncoder::new(bytes);
        encoder.set_max_size(max_size);
        self.destructive_emit(&mut encoder)
    }

    /// Emits the response into `bytes`, followed by the TSIG record signing it if a signer is set.
    ///
    /// RFC 8945 section 5.3: "If addition of the TSIG record will cause the message to be
    /// truncated, the server MUST alter the response so that a TSIG can be included. This response
    /// contains only the question and a TSIG record, has the TC bit set, and has an RCODE of 0
    /// (NOERROR)." Shedding records from a response that has already been signed is not an option,
    /// since the MAC covers the message that was signed and the client checks it against the
    /// message it received.
    #[cfg(feature = "__dnssec")]
    fn emit_and_sign(
        mut self,
        bytes: &mut Vec<u8>,
        max_size: u16,
    ) -> Result<ResponseInfo, ProtoError> {
        let Some(signer) = self.signer.take() else {
            let mut encoder = BinEncoder::new(bytes);
            encoder.set_max_size(max_size);
            return self.destructive_emit(&mut encoder);
        };

        let metadata = self.metadata;
        let queries = self.queries;
        let edns = self.edns;

        // The signer appends a TSIG record of its own, so the message it signs must not carry
        // one already.
        self.signature = None;

        let header = {
            let mut encoder = BinEncoder::new(bytes);
            encoder.set_max_size(max_size);
            self.emit_parts(&mut encoder)?
        };

        // The records fit. They still have to leave room for the TSIG record after them, and how
        // much that needs is only known once the record has been built.
        if !header.truncation {
            if let Some(header) = signer.clone().sign_and_append(bytes, max_size, header)? {
                return Ok(ResponseInfo::from(header));
            }
        }

        let mut metadata = metadata;
        metadata.truncation = true;
        metadata.response_code = ResponseCode::NoError;

        bytes.clear();
        let header = {
            let mut encoder = BinEncoder::new(bytes);
            encoder.set_max_size(max_size);
            emit_message_parts(
                &metadata,
                &mut match queries {
                    Some(queries) => queries.as_emit_and_count(),
                    None => QueriesEmitAndCount::None,
                },
                &mut iter::empty::<&Record>(),
                &mut iter::empty::<&Record>(),
                &mut iter::empty::<&Record>(),
                edns,
                None,
                &mut encoder,
            )?
        };

        match signer.sign_and_append(bytes, max_size, header)? {
            Some(header) => Ok(ResponseInfo::from(header)),
            None => Err(ProtoError::from(
                "no room for a TSIG record in a response holding only the question",
            )),
        }
    }

    /// Consumes self, and emits to the encoder.
    pub fn destructive_emit(
        self,
        encoder: &mut BinEncoder<'_>,
    ) -> Result<ResponseInfo, ProtoError> {
        Ok(ResponseInfo::from(self.emit_parts(encoder)?))
    }

    /// Emits the header, question and record sections, without any TSIG record.
    fn emit_parts(mut self, encoder: &mut BinEncoder<'_>) -> Result<Header, ProtoError> {
        // soa records are part of the authority section
        let mut authorities = self.authorities.chain(self.soa);

        emit_message_parts(
            &self.metadata,
            &mut match self.queries {
                Some(queries) => queries.as_emit_and_count(),
                None => QueriesEmitAndCount::None,
            },
            &mut self.answers,
            &mut authorities,
            &mut self.additionals,
            self.edns,
            self.signature.as_deref(),
            encoder,
        )
    }
}

/// A builder for MessageResponses
pub struct MessageResponseBuilder<'q> {
    queries: Option<&'q Queries>,
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
            signature: None,
            #[cfg(feature = "__dnssec")]
            signer: None,
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
            signature: None,
            #[cfg(feature = "__dnssec")]
            signer: None,
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
            signature: None,
            #[cfg(feature = "__dnssec")]
            signer: None,
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
    use crate::proto::rr::{DNSClass, Name, RData, Record};
    #[cfg(feature = "__dnssec")]
    use crate::proto::rr::{TSigner, rdata::tsig::TsigAlgorithm};
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

    /// A signed response that fits keeps its records and carries a verifiable TSIG record.
    #[cfg(feature = "__dnssec")]
    #[test]
    fn test_signed_response_that_fits() {
        let answer = Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            0,
            RData::A(Ipv4Addr::new(93, 184, 215, 14).into()),
        );

        let request = MessageRequest::mock(
            Metadata::new(10, MessageType::Query, OpCode::Query),
            Query::root(),
        );
        let mut response = MessageResponseBuilder::from_message_request(&request).build(
            Metadata::new(10, MessageType::Response, OpCode::Query),
            iter::once(&answer),
            [],
            [],
            [],
        );

        let (signer, request_mac) = test_signer();
        response.set_signer(TSigResponseContext::new(
            10,
            TEST_TIME,
            signer.clone(),
            request_mac.clone(),
            None,
        ));

        let (_info, buf) = response.encode(Protocol::Udp).expect("failed to encode");

        let decoded = Message::from_vec(&buf).expect("failed to decode");
        assert!(!decoded.metadata.truncation);
        assert_eq!(decoded.answers.len(), 1);
        signer
            .verify_message_byte(&buf, Some(&request_mac), true)
            .expect("signature did not verify");
    }

    /// RFC 8945 section 5.3: a signed response that cannot hold its records alongside the TSIG
    /// record is replaced by one holding only the question, with TC set and RCODE NOERROR. The
    /// MAC has to cover what is actually sent, so records cannot be shed after signing.
    #[cfg(feature = "__dnssec")]
    #[test]
    fn test_signed_response_that_does_not_fit() {
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

        let (signer, request_mac) = test_signer();
        response.set_signer(TSigResponseContext::new(
            10,
            TEST_TIME,
            signer.clone(),
            request_mac.clone(),
            None,
        ));

        let (_info, buf) = response.encode(Protocol::Udp).expect("failed to encode");
        assert!(buf.len() <= 512, "response was {} bytes", buf.len());

        let decoded = Message::from_vec(&buf).expect("failed to decode");
        assert!(decoded.metadata.truncation);
        assert_eq!(decoded.metadata.response_code, ResponseCode::NoError);
        assert_eq!(decoded.queries.len(), 1);
        assert!(decoded.answers.is_empty());
        assert!(decoded.signature.is_some(), "TSIG record was dropped");
        signer
            .verify_message_byte(&buf, Some(&request_mac), true)
            .expect("signature did not verify");
    }

    /// A pre-built signature set with [`MessageResponse::set_signature`] is still emitted by
    /// [`MessageResponse::destructive_emit`], so callers of the older pair keep the behaviour they
    /// had. The MAC in such a record only matches the bytes sent while the response does not have
    /// to shed any, which is what [`MessageResponse::set_signer`] exists for.
    #[cfg(feature = "__dnssec")]
    #[test]
    fn test_prebuilt_signature_is_still_emitted() {
        let answer = Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            0,
            RData::A(Ipv4Addr::new(93, 184, 215, 14).into()),
        );

        let request = MessageRequest::mock(
            Metadata::new(10, MessageType::Query, OpCode::Query),
            Query::root(),
        );
        let mut response = MessageResponseBuilder::from_message_request(&request).build(
            Metadata::new(10, MessageType::Response, OpCode::Query),
            iter::once(&answer),
            [],
            [],
            [],
        );

        let (signer, request_mac) = test_signer();
        let signature = TSigResponseContext::new(10, TEST_TIME, signer, request_mac, None)
            .sign(b"an earlier encoding of the response")
            .expect("failed to sign");
        response.set_signature(signature);

        let mut buf = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut buf);
        response
            .destructive_emit(&mut encoder)
            .expect("failed to emit");

        let decoded = Message::from_vec(&buf).expect("failed to decode");
        assert_eq!(decoded.answers.len(), 1);
        assert!(decoded.signature.is_some(), "TSIG record was dropped");
    }

    #[cfg(feature = "__dnssec")]
    const TEST_TIME: u64 = 1_755_000_000;

    #[cfg(feature = "__dnssec")]
    fn test_signer() -> (TSigner, Vec<u8>) {
        let signer = TSigner::new(
            vec![0; 32],
            TsigAlgorithm::HmacSha256,
            Name::from_str("key.example.com.").unwrap(),
            300,
        )
        .unwrap();
        let request_mac = signer.sign(b"request").unwrap();
        (signer, request_mac)
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
}
