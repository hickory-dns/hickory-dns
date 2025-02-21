// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::{
    authority::{Queries, message_request::MessageRequest},
    proto::{
        ProtoError,
        op::{Edns, Header, ResponseCode, message},
        rr::Record,
        serialize::binary::BinEncoder,
    },
    server::ResponseInfo,
};

/// A EncodableMessage with borrowed data for Responses in the Server
#[derive(Debug)]
pub struct MessageResponse<'q, 'a, Answers, NameServers, Soa, Additionals>
where
    Answers: Iterator<Item = &'a Record> + Send + 'a,
    NameServers: Iterator<Item = &'a Record> + Send + 'a,
    Soa: Iterator<Item = &'a Record> + Send + 'a,
    Additionals: Iterator<Item = &'a Record> + Send + 'a,
{
    header: Header,
    queries: &'q Queries,
    answers: Answers,
    name_servers: NameServers,
    soa: Soa,
    additionals: Additionals,
    sig0: Vec<Record>,
    edns: Option<Edns>,
}

impl<'a, A, N, S, D> MessageResponse<'_, 'a, A, N, S, D>
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
    pub fn set_edns(&mut self, edns: Edns) -> &mut Self {
        self.edns = Some(edns);
        self
    }

    /// Gets a reference to the EDNS options for the Response.
    pub fn get_edns(&self) -> &Option<Edns> {
        &self.edns
    }

    /// Consumes self, and emits to the encoder.
    pub fn destructive_emit(
        mut self,
        encoder: &mut BinEncoder<'_>,
    ) -> Result<ResponseInfo, ProtoError> {
        // soa records are part of the nameserver section
        let mut name_servers = self.name_servers.chain(self.soa);

        message::emit_message_parts(
            &self.header,
            &mut self.queries.as_emit_and_count(),
            &mut self.answers,
            &mut name_servers,
            &mut self.additionals,
            self.edns.as_ref(),
            &self.sig0,
            encoder,
        )
        .map(Into::into)
    }
}

/// A builder for MessageResponses
pub struct MessageResponseBuilder<'q> {
    queries: &'q Queries,
    sig0: Option<Vec<Record>>,
    edns: Option<Edns>,
}

impl<'q> MessageResponseBuilder<'q> {
    /// Constructs a new response builder
    ///
    /// # Arguments
    ///
    /// * `queries` - queries (from the Request) to associate with the Response
    pub(crate) fn new(queries: &'q Queries) -> Self {
        MessageResponseBuilder {
            queries,
            sig0: None,
            edns: None,
        }
    }

    /// Constructs a new response builder
    ///
    /// # Arguments
    ///
    /// * `message` - original request message to associate with the response
    pub fn from_message_request(message: &'q MessageRequest) -> Self {
        Self::new(message.raw_queries())
    }

    /// Associate EDNS with the Response
    pub fn edns(&mut self, edns: Edns) -> &mut Self {
        self.edns = Some(edns);
        self
    }

    /// Constructs the new MessageResponse with associated Header
    ///
    /// # Arguments
    ///
    /// * `header` - set of [Header]s for the Message
    pub fn build<'a, A, N, S, D>(
        self,
        header: Header,
        answers: A,
        name_servers: N,
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
            name_servers: name_servers.into_iter(),
            soa: soa.into_iter(),
            additionals: additionals.into_iter(),
            sig0: self.sig0.unwrap_or_default(),
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
            name_servers: Box::new(None.into_iter()),
            soa: Box::new(None.into_iter()),
            additionals: Box::new(None.into_iter()),
            sig0: self.sig0.unwrap_or_default(),
            edns: self.edns,
        }
    }

    /// Constructs a new error MessageResponse with associated settings
    ///
    /// # Arguments
    ///
    /// * `id` - request id to which this is a response
    /// * `op_code` - operation for which this is a response
    /// * `response_code` - the type of error
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
            name_servers: Box::new(None.into_iter()),
            soa: Box::new(None.into_iter()),
            additionals: Box::new(None.into_iter()),
            sig0: self.sig0.unwrap_or_default(),
            edns: self.edns,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::iter;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use crate::proto::op::{Header, Message};
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
                header: Header::new(),
                queries: &Queries::empty(),
                answers: iter::repeat(&answer),
                name_servers: iter::once(&answer),
                soa: iter::once(&answer),
                additionals: iter::once(&answer),
                sig0: vec![],
                edns: None,
            };

            message
                .destructive_emit(&mut encoder)
                .expect("failed to encode");
        }

        let response = Message::from_vec(&buf).expect("failed to decode");
        assert!(response.header().truncated());
        assert!(response.answer_count() > 1);
        // should never have written the name server field...
        assert_eq!(response.name_server_count(), 0);
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
                header: Header::new(),
                queries: &Queries::empty(),
                answers: iter::empty(),
                name_servers: iter::repeat(&answer),
                soa: iter::repeat(&answer),
                additionals: iter::repeat(&answer),
                sig0: vec![],
                edns: None,
            };

            message
                .destructive_emit(&mut encoder)
                .expect("failed to encode");
        }

        let response = Message::from_vec(&buf).expect("failed to decode");
        assert!(response.header().truncated());
        assert_eq!(response.answer_count(), 0);
        assert!(response.name_server_count() > 1);
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

        MessageResponseBuilder::new(msg.raw_queries())
            .build_no_records(Header::response_from_request(msg.header()))
            .destructive_emit(&mut encoder)
            .unwrap();
    }
}
