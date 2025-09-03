// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::{
    proto::{
        ProtoError,
        op::{Edns, Header, MessageSignature, ResponseCode, emit_message_parts},
        rr::Record,
        serialize::binary::BinEncoder,
    },
    server::ResponseInfo,
    zone_handler::{Queries, message_request::MessageRequest},
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
    header: Header,
    queries: &'q Queries,
    answers: Answers,
    authorities: Authorities,
    soa: Soa,
    additionals: Additionals,
    signature: MessageSignature,
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
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Get a mutable reference to the header
    pub fn header_mut(&mut self) -> &mut Header {
        &mut self.header
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
    pub fn set_signature(&mut self, signature: MessageSignature) {
        self.signature = signature;
    }

    /// Consumes self, and emits to the encoder.
    pub fn destructive_emit(
        mut self,
        encoder: &mut BinEncoder<'_>,
    ) -> Result<ResponseInfo, ProtoError> {
        // soa records are part of the authority section
        let mut authorities = self.authorities.chain(self.soa);

        emit_message_parts(
            &self.header,
            &mut self.queries.as_emit_and_count(),
            &mut self.answers,
            &mut authorities,
            &mut self.additionals,
            self.edns,
            &self.signature,
            encoder,
        )
        .map(Into::into)
    }
}

/// A builder for MessageResponses
pub struct MessageResponseBuilder<'q> {
    queries: &'q Queries,
    signature: MessageSignature,
    edns: Option<&'q Edns>,
}

impl<'q> MessageResponseBuilder<'q> {
    /// Constructs a new response builder
    ///
    /// # Arguments
    ///
    /// * `queries` - queries (from the Request) to associate with the Response
    /// * `edns` - Optional Edns data to associate with the Response
    pub fn new(queries: &'q Queries, edns: Option<&'q Edns>) -> Self {
        MessageResponseBuilder {
            queries,
            signature: MessageSignature::default(),
            edns,
        }
    }

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
    ///         .error_msg(request.header(), ResponseCode::ServFail)
    /// }
    /// ```
    pub fn from_message_request(message: &'q MessageRequest) -> Self {
        Self::new(message.raw_queries(), None)
    }

    /// Associate EDNS with the Response
    pub fn edns(&mut self, edns: &'q Edns) -> &mut Self {
        self.edns = Some(edns);
        self
    }

    /// Constructs the new MessageResponse with associated data
    pub fn build<'a, A, N, S, D>(
        self,
        header: Header,
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
            header,
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
        header: Header,
    ) -> MessageResponse<
        'q,
        'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
    > {
        MessageResponse {
            header,
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
        request_header: &Header,
        response_code: ResponseCode,
    ) -> MessageResponse<
        'q,
        'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
    > {
        let mut header = Header::response_from_request(request_header);
        header.set_response_code(response_code);

        MessageResponse {
            header,
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

    use crate::proto::op::{Header, Message, MessageType, OpCode};
    use crate::proto::rr::{DNSClass, Name, RData, Record};
    use crate::proto::serialize::binary::BinEncoder;

    use super::*;

    #[test]
    fn test_truncation_ridiculous_number_answers() {
        let mut buf = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut buf);
            encoder.set_max_size(512);

            let answer = Record::from_rdata(
                Name::from_str("www.example.com.").unwrap(),
                0,
                RData::A(Ipv4Addr::new(93, 184, 215, 14).into()),
            )
            .set_dns_class(DNSClass::NONE)
            .clone();

            let message = MessageResponse {
                header: Header::new(10, MessageType::Response, OpCode::Query),
                queries: &Queries::empty(),
                answers: iter::repeat(&answer),
                authorities: iter::once(&answer),
                soa: iter::once(&answer),
                additionals: iter::once(&answer),
                signature: MessageSignature::default(),
                edns: None,
            };

            message
                .destructive_emit(&mut encoder)
                .expect("failed to encode");
        }

        let response = Message::from_vec(&buf).expect("failed to decode");
        assert!(response.header().truncated());
        assert!(response.answer_count() > 1);
        // should never have written the authority section...
        assert_eq!(response.authority_count(), 0);
    }

    #[test]
    fn test_truncation_ridiculous_number_nameservers() {
        let mut buf = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut buf);
            encoder.set_max_size(512);

            let answer = Record::from_rdata(
                Name::from_str("www.example.com.").unwrap(),
                0,
                RData::A(Ipv4Addr::new(93, 184, 215, 14).into()),
            )
            .set_dns_class(DNSClass::NONE)
            .clone();

            let message = MessageResponse {
                header: Header::new(10, MessageType::Response, OpCode::Query),
                queries: &Queries::empty(),
                answers: iter::empty(),
                authorities: iter::repeat(&answer),
                soa: iter::repeat(&answer),
                additionals: iter::repeat(&answer),
                signature: MessageSignature::default(),
                edns: None,
            };

            message
                .destructive_emit(&mut encoder)
                .expect("failed to encode");
        }

        let response = Message::from_vec(&buf).expect("failed to decode");
        assert!(response.header().truncated());
        assert_eq!(response.answer_count(), 0);
        assert!(response.authority_count() > 1);
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
        use hickory_proto::serialize::binary::BinDecodable;

        let mut buf = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut buf);

        let data: &[u8] = &[
            0x08u8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let msg = MessageRequest::from_bytes(data).unwrap();

        eprintln!("queries: {:?}", msg.queries());

        MessageResponseBuilder::new(msg.raw_queries(), None)
            .build_no_records(Header::response_from_request(msg.header()))
            .destructive_emit(&mut encoder)
            .unwrap();
    }
}
