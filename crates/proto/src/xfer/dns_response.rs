// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `DnsResponse` wraps a `Message` and any associated connection details

use alloc::vec::Vec;
use core::{
    convert::TryFrom,
    ops::{Deref, DerefMut},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    error::ProtoError,
    op::Message,
    rr::{RecordType, rdata::SOA, resource::RecordRef},
};

// TODO: this needs to have the IP addr of the remote system...
// TODO: see https://github.com/hickory-dns/hickory-dns/issues/383 for removing vec of messages and instead returning a Stream
/// A DNS response object
///
/// For Most DNS requests, only one response is expected, the exception is a multicast request.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct DnsResponse {
    message: Message,
    buffer: Vec<u8>,
}

// TODO: when `impl Trait` lands in stable, remove this, and expose FlatMap over answers, et al.
impl DnsResponse {
    /// Constructs a new DnsResponse with a buffer synthesized from the message
    pub fn from_message(message: Message) -> Result<Self, ProtoError> {
        Ok(Self {
            buffer: message.to_vec()?,
            message,
        })
    }

    /// Constructs a new DnsResponse by parsing a message from a buffer.
    ///
    /// Returns an error if the response message cannot be decoded.
    pub fn from_buffer(buffer: Vec<u8>) -> Result<Self, ProtoError> {
        let message = Message::from_vec(&buffer)?;
        Ok(Self { message, buffer })
    }

    /// Retrieves the SOA from the response. This will only exist if it was an authoritative response.
    pub fn soa(&self) -> Option<RecordRef<'_, SOA>> {
        self.authorities()
            .iter()
            .find_map(|record| RecordRef::try_from(record).ok())
    }

    /// Looks in the authority section for an SOA record from the response, and returns the negative_ttl, None if not available.
    ///
    /// ```text
    /// [RFC 2308](https://tools.ietf.org/html/rfc2308#section-5) DNS NCACHE March 1998
    ///
    /// 5 - Caching Negative Answers
    ///
    ///   Like normal answers negative answers have a time to live (TTL).  As
    ///   there is no record in the answer section to which this TTL can be
    ///   applied, the TTL must be carried by another method.  This is done by
    ///   including the SOA record from the zone in the authority section of
    ///   the reply.  When the authoritative server creates this record its TTL
    ///   is taken from the minimum of the SOA.MINIMUM field and SOA's TTL.
    ///   This TTL decrements in a similar manner to a normal cached answer and
    ///   upon reaching zero (0) indicates the cached negative answer MUST NOT
    ///   be used again.
    ///
    ///   A negative answer that resulted from a name error (NXDOMAIN) should
    ///   be cached such that it can be retrieved and returned in response to
    ///   another query for the same <QNAME, QCLASS> that resulted in the
    ///   cached negative response.
    ///
    ///   A negative answer that resulted from a no data error (NODATA) should
    ///   be cached such that it can be retrieved and returned in response to
    ///   another query for the same <QNAME, QTYPE, QCLASS> that resulted in
    ///   the cached negative response.
    ///
    ///   The NXT record, if it exists in the authority section of a negative
    ///   answer received, MUST be stored such that it can be be located and
    ///   returned with SOA record in the authority section, as should any SIG
    ///   records in the authority section.  For NXDOMAIN answers there is no
    ///   "necessary" obvious relationship between the NXT records and the
    ///   QNAME.  The NXT record MUST have the same owner name as the query
    ///   name for NODATA responses.
    ///
    ///   Negative responses without SOA records SHOULD NOT be cached as there
    ///   is no way to prevent the negative responses looping forever between a
    ///   pair of servers even with a short TTL.
    ///
    ///   Despite the DNS forming a tree of servers, with various mis-
    ///   configurations it is possible to form a loop in the query graph, e.g.
    ///   two servers listing each other as forwarders, various lame server
    ///   configurations.  Without a TTL count down a cache negative response
    ///   when received by the next server would have its TTL reset.  This
    ///   negative indication could then live forever circulating between the
    ///   servers involved.
    ///
    ///   As with caching positive responses it is sensible for a resolver to
    ///   limit for how long it will cache a negative response as the protocol
    ///   supports caching for up to 68 years.  Such a limit should not be
    ///   greater than that applied to positive answers and preferably be
    ///   tunable.  Values of one to three hours have been found to work well
    ///   and would make sensible a default.  Values exceeding one day have
    ///   been found to be problematic.
    /// ```
    pub fn negative_ttl(&self) -> Option<u32> {
        // TODO: should this ensure that the SOA zone matches the Queried Zone?
        self.authorities()
            .iter()
            .filter_map(|record| record.data().as_soa().map(|soa| (record.ttl(), soa)))
            .next()
            .map(|(ttl, soa)| (ttl).min(soa.minimum()))
    }

    /// Does the response contain any records matching the query name and type?
    pub fn contains_answer(&self) -> bool {
        for q in self.queries() {
            let found = match q.query_type() {
                RecordType::ANY => self.all_sections().any(|r| r.name() == q.name()),
                RecordType::SOA => {
                    // for SOA name must be part of the SOA zone
                    self.all_sections()
                        .filter(|r| r.record_type().is_soa())
                        .any(|r| r.name().zone_of(q.name()))
                }
                q_type => {
                    if !self.answers().is_empty() {
                        true
                    } else {
                        self.all_sections()
                            .filter(|r| r.record_type() == q_type)
                            .any(|r| r.name() == q.name())
                    }
                }
            };

            if found {
                return true;
            }
        }

        false
    }

    /// Borrow the inner buffer from the response
    pub fn as_buffer(&self) -> &[u8] {
        &self.buffer
    }

    /// Take the inner buffer from the response
    pub fn into_buffer(self) -> Vec<u8> {
        self.buffer
    }

    /// Take the inner Message from the response
    pub fn into_message(self) -> Message {
        self.message
    }

    /// Take the inner Message and buffer from the response
    pub fn into_parts(self) -> (Message, Vec<u8>) {
        (self.message, self.buffer)
    }
}

impl Deref for DnsResponse {
    type Target = Message;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl DerefMut for DnsResponse {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.message
    }
}

impl From<DnsResponse> for Message {
    fn from(response: DnsResponse) -> Self {
        response.message
    }
}

#[cfg(all(test, any(feature = "std", feature = "no-std-rand")))]
mod tests {
    use crate::op::{Message, Query, ResponseCode};
    use crate::rr::RData;
    use crate::rr::rdata::{A, NS, SOA};
    use crate::rr::{Name, Record, RecordType};

    use super::*;

    fn xx() -> Name {
        Name::from_ascii("XX.").unwrap()
    }

    fn ns1() -> Name {
        Name::from_ascii("NS1.XX.").unwrap()
    }

    fn hostmaster() -> Name {
        Name::from_ascii("HOSTMASTER.NS1.XX.").unwrap()
    }

    fn example() -> Name {
        Name::from_ascii("EXAMPLE.").unwrap()
    }

    fn an_example() -> Name {
        Name::from_ascii("AN.EXAMPLE.").unwrap()
    }

    fn ns1_record() -> Record {
        Record::from_rdata(xx(), 88640, RData::NS(NS(ns1())))
    }

    fn ns1_a() -> Record {
        Record::from_rdata(xx(), 88640, RData::A(A::new(127, 0, 0, 2)))
    }

    fn soa() -> Record {
        Record::from_rdata(
            example(),
            88640,
            RData::SOA(SOA::new(ns1(), hostmaster(), 1, 2, 3, 4, 5)),
        )
    }

    #[test]
    fn test_contains_answer() {
        let mut message = Message::query();
        message.set_response_code(ResponseCode::NXDomain);
        message.add_query(Query::query(Name::root(), RecordType::A));
        message.add_answer(Record::from_rdata(
            Name::root(),
            88640,
            RData::A(A::new(127, 0, 0, 2)),
        ));

        let response = DnsResponse::from_message(message).unwrap();

        assert!(response.contains_answer())
    }

    #[test]
    fn contains_soa() {
        let mut message = Message::query();
        message.set_response_code(ResponseCode::NoError);
        message.add_query(Query::query(an_example(), RecordType::SOA));
        message.add_authority(soa());

        let response = DnsResponse::from_message(message).unwrap();

        assert!(response.contains_answer());
    }

    #[test]
    fn contains_any() {
        let mut message = Message::query();
        message.set_response_code(ResponseCode::NoError);
        message.add_query(Query::query(xx(), RecordType::ANY));
        message.add_authority(ns1_record());
        message.add_additional(ns1_a());

        let response = DnsResponse::from_message(message).unwrap();

        assert!(response.contains_answer());
    }
}
