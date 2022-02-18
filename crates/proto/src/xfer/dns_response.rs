// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `DnsResponse` wraps a `Message` and any associated connection details

use std::future::Future;
use std::io;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_channel::mpsc;
use futures_util::ready;
use futures_util::stream::Stream;

use crate::error::{ProtoError, ProtoErrorKind, ProtoResult};
use crate::op::{Message, ResponseCode};
use crate::rr::rdata::SOA;
use crate::rr::{RData, RecordType};

/// A stream returning DNS responses
pub struct DnsResponseStream {
    inner: DnsResponseStreamInner,
    done: bool,
}

impl DnsResponseStream {
    fn new(inner: DnsResponseStreamInner) -> Self {
        Self { inner, done: false }
    }
}

impl Stream for DnsResponseStream {
    type Item = Result<DnsResponse, ProtoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        use DnsResponseStreamInner::*;

        // if the standard futures are done, don't poll again
        if self.done {
            return Poll::Ready(None);
        }

        // split mutable refs to Self
        let Self {
            ref mut inner,
            ref mut done,
        } = *self.as_mut();

        let result = match inner {
            Timeout(fut) => {
                let x = match ready!(fut.as_mut().poll(cx)) {
                    Ok(x) => x,
                    Err(e) => Err(e.into()),
                };
                *done = true;
                x
            }
            Receiver(ref mut fut) => match ready!(Pin::new(fut).poll_next(cx)) {
                Some(x) => x,
                None => return Poll::Ready(None),
            },
            Error(err) => {
                *done = true;
                Err(err.take().expect("cannot poll after complete"))
            }
            Boxed(fut) => {
                let x = ready!(fut.as_mut().poll(cx));
                *done = true;
                x
            }
        };

        match result {
            Err(e) if matches!(e.kind(), ProtoErrorKind::Timeout) => Poll::Ready(None),
            r => Poll::Ready(Some(r)),
        }
    }
}

impl From<TimeoutFuture> for DnsResponseStream {
    fn from(f: TimeoutFuture) -> Self {
        Self::new(DnsResponseStreamInner::Timeout(f))
    }
}

impl From<mpsc::Receiver<ProtoResult<DnsResponse>>> for DnsResponseStream {
    fn from(receiver: mpsc::Receiver<ProtoResult<DnsResponse>>) -> Self {
        Self::new(DnsResponseStreamInner::Receiver(receiver))
    }
}

impl From<ProtoError> for DnsResponseStream {
    fn from(e: ProtoError) -> Self {
        Self::new(DnsResponseStreamInner::Error(Some(e)))
    }
}

impl<F> From<Pin<Box<F>>> for DnsResponseStream
where
    F: Future<Output = Result<DnsResponse, ProtoError>> + Send + 'static,
{
    fn from(f: Pin<Box<F>>) -> Self {
        Self::new(DnsResponseStreamInner::Boxed(
            f as Pin<Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send>>,
        ))
    }
}

enum DnsResponseStreamInner {
    Timeout(TimeoutFuture),
    Receiver(mpsc::Receiver<ProtoResult<DnsResponse>>),
    Error(Option<ProtoError>),
    Boxed(Pin<Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send>>),
}

type TimeoutFuture = Pin<
    Box<dyn Future<Output = Result<Result<DnsResponse, ProtoError>, io::Error>> + Send + 'static>,
>;

// TODO: this needs to have the IP addr of the remote system...
// TODO: see https://github.com/bluejekyll/trust-dns/issues/383 for removing vec of messages and instead returning a Stream
/// A DNS response object
///
/// For Most DNS requests, only one response is expected, the exception is a multicast request.
#[derive(Clone, Debug)]
pub struct DnsResponse(Message);

// TODO: when `impl Trait` lands in stable, remove this, and expose FlatMap over answers, et al.
impl DnsResponse {
    /// Retrieves the SOA from the response. This will only exist if it was an authoritative response.
    pub fn soa(&self) -> Option<SOA> {
        self.name_servers()
            .iter()
            .filter_map(|record| record.data().and_then(RData::as_soa))
            .next()
            .cloned()
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
        self.name_servers()
            .iter()
            .filter_map(|record| {
                record
                    .data()
                    .and_then(RData::as_soa)
                    .map(|soa| (record.ttl(), soa))
            })
            .next()
            .map(|(ttl, soa)| (ttl as u32).min(soa.minimum()).max(0))
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

    /// Retrieve the type of the negative response.
    ///   The Various types should be handled when caching or otherwise differently.
    ///
    /// See [NegativeType]
    pub fn negative_type(&self) -> Option<NegativeType> {
        let response_code = self.response_code();
        let ttl_from_soa = self.negative_ttl();
        let has_soa = ttl_from_soa.map_or(false, |_| true);
        let has_ns_records = self.name_servers().iter().any(|r| r.record_type().is_ns());
        let has_cname = self.answers().iter().any(|r| r.record_type().is_cname());
        let has_non_cname = self.answers().iter().any(|r| !r.record_type().is_cname());
        let has_additionals = self.additional_count() > 0;

        match (
            response_code,
            has_soa,
            has_ns_records,
            has_cname,
            has_non_cname,
            has_additionals,
        ) {
            (ResponseCode::NXDomain, true, true, _, false, _) => Some(NegativeType::NameErrorType1),
            (ResponseCode::NXDomain, true, false, _, false, _) => {
                Some(NegativeType::NameErrorType2)
            }
            (ResponseCode::NXDomain, false, false, true, false, _) => {
                Some(NegativeType::NameErrorType3)
            }
            (ResponseCode::NXDomain, false, true, _, false, _) => {
                Some(NegativeType::NameErrorType4)
            }
            (ResponseCode::NoError, true, true, false, false, _) => Some(NegativeType::NoDataType1),
            (ResponseCode::NoError, true, false, false, false, _) => {
                Some(NegativeType::NoDataType2)
            }
            (ResponseCode::NoError, false, false, false, false, false) => {
                Some(NegativeType::NoDataType3)
            }
            (ResponseCode::NoError, false, true, _, false, _) => Some(NegativeType::Referral),
            _ => None,
        }
    }
}

impl Deref for DnsResponse {
    type Target = Message;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DnsResponse {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<DnsResponse> for Message {
    fn from(response: DnsResponse) -> Self {
        response.0
    }
}

impl From<Message> for DnsResponse {
    fn from(message: Message) -> Self {
        Self(message)
    }
}

/// ```text
/// [RFC 2308](https://tools.ietf.org/html/rfc2308#section-2) DNS NCACHE March 1998
///
///
/// 2 - Negative Responses
///
///    The most common negative responses indicate that a particular RRset
///    does not exist in the DNS.  The first sections of this document deal
///    with this case.  Other negative responses can indicate failures of a
///    nameserver, those are dealt with in section 7 (Other Negative
///    Responses).
///
///    A negative response is indicated by one of the following conditions:
///
/// 2.1 - Name Error
///
///    Name errors (NXDOMAIN) are indicated by the presence of "Name Error"
///    in the RCODE field.  In this case the domain referred to by the QNAME
///    does not exist.  Note: the answer section may have SIG and CNAME RRs
///    and the authority section may have SOA, NXT [RFC2065] and SIG RRsets.
///
///    It is possible to distinguish between a referral and a NXDOMAIN
///    response by the presense of NXDOMAIN in the RCODE regardless of the
///    presence of NS or SOA records in the authority section.
///
///    NXDOMAIN responses can be categorised into four types by the contents
///    of the authority section.  These are shown below along with a
///    referral for comparison.  Fields not mentioned are not important in
///    terms of the examples.
///
///    See [NegativeType] below:
///        [NegativeType::NameErrorType1]
///        [NegativeType::NameErrorType2]
///        [NegativeType::NameErrorType3]
///        [NegativeType::NameErrorType4]
///        [NegativeType::Referral]
///
///    Note, in the four examples of NXDOMAIN responses, it is known that
///    the name "AN.EXAMPLE." exists, and has as its value a CNAME record.
///    The NXDOMAIN refers to "TRIPPLE.XX", which is then known not to
///    exist.  On the other hand, in the referral example, it is shown that
///    "AN.EXAMPLE" exists, and has a CNAME RR as its value, but nothing is
///    known one way or the other about the existence of "TRIPPLE.XX", other
///    than that "NS1.XX" or "NS2.XX" can be consulted as the next step in
///    obtaining information about it.
///
///    Where no CNAME records appear, the NXDOMAIN response refers to the
///    name in the label of the RR in the question section.
///
/// 2.1.1 Special Handling of Name Error
///
///    This section deals with errors encountered when implementing negative
///    caching of NXDOMAIN responses.
///
///    There are a large number of resolvers currently in existence that
///    fail to correctly detect and process all forms of NXDOMAIN response.
///    Some resolvers treat a TYPE 1 NXDOMAIN response as a referral.  To
///    alleviate this problem it is recommended that servers that are
///    authoritative for the NXDOMAIN response only send TYPE 2 NXDOMAIN
///    responses, that is the authority section contains a SOA record and no
///    NS records.  If a non- authoritative server sends a type 1 NXDOMAIN
///    response to one of these old resolvers, the result will be an
///    unnecessary query to an authoritative server.  This is undesirable,
///    but not fatal except when the server is being used a FORWARDER.  If
///    however the resolver is using the server as a FORWARDER to such a
///    resolver it will be necessary to disable the sending of TYPE 1
///    NXDOMAIN response to it, use TYPE 2 NXDOMAIN instead.
///
///    Some resolvers incorrectly continue processing if the authoritative
///    answer flag is not set, looping until the query retry threshold is
///    exceeded and then returning SERVFAIL.  This is a problem when your
///    nameserver is listed as a FORWARDER for such resolvers.  If the
///    nameserver is used as a FORWARDER by such resolver, the authority
///    flag will have to be forced on for NXDOMAIN responses to these
///    resolvers.  In practice this causes no problems even if turned on
///    always, and has been the default behaviour in BIND from 4.9.3
///    onwards.
///
/// 2.2 - No Data
///
///    NODATA is indicated by an answer with the RCODE set to NOERROR and no
///    relevant answers in the answer section.  The authority section will
///    contain an SOA record, or there will be no NS records there.
///    NODATA responses have to be algorithmically determined from the
///    response's contents as there is no RCODE value to indicate NODATA.
///    In some cases to determine with certainty that NODATA is the correct
///    response it can be necessary to send another query.
///
///    The authority section may contain NXT and SIG RRsets in addition to
///    NS and SOA records.  CNAME and SIG records may exist in the answer
///    section.
///
///    It is possible to distinguish between a NODATA and a referral
///    response by the presence of a SOA record in the authority section or
///    the absence of NS records in the authority section.
///
///    NODATA responses can be categorised into three types by the contents
///    of the authority section.  These are shown below along with a
///    referral for comparison.  Fields not mentioned are not important in
///    terms of the examples.
///
///    See [NegativeType] below:
///        [NegativeType::NoDataType1]
///        [NegativeType::NoDataType2]
///        [NegativeType::NoDataType3]
///
///    These examples, unlike the NXDOMAIN examples above, have no CNAME
///    records, however they could, in just the same way that the NXDOMAIN
///    examples did, in which case it would be the value of the last CNAME
///    (the QNAME) for which NODATA would be concluded.
///
/// 2.2.1 - Special Handling of No Data
///
///    There are a large number of resolvers currently in existence that
///    fail to correctly detect and process all forms of NODATA response.
///    Some resolvers treat a TYPE 1 NODATA response as a referral.  To
///    alleviate this problem it is recommended that servers that are
///    authoritative for the NODATA response only send TYPE 2 NODATA
///    responses, that is the authority section contains a SOA record and no
///    NS records.  Sending a TYPE 1 NODATA response from a non-
///    authoritative server to one of these resolvers will only result in an
///    unnecessary query.  If a server is listed as a FORWARDER for another
///    resolver it may also be necessary to disable the sending of TYPE 1
///    NODATA response for non-authoritative NODATA responses.
///    Some name servers fail to set the RCODE to NXDOMAIN in the presence
///    of CNAMEs in the answer section.  If a definitive NXDOMAIN / NODATA
///    answer is required in this case the resolver must query again using
///    the QNAME as the query label.
///
/// 3 - Negative Answers from Authoritative Servers
///
///    Name servers authoritative for a zone MUST include the SOA record of
///    the zone in the authority section of the response when reporting an
///    NXDOMAIN or indicating that no data of the requested type exists.
///    This is required so that the response may be cached.  The TTL of this
///    record is set from the minimum of the MINIMUM field of the SOA record
///    and the TTL of the SOA itself, and indicates how long a resolver may
///    cache the negative answer.  The TTL SIG record associated with the
///    SOA record should also be trimmed in line with the SOA's TTL.
///
///    If the containing zone is signed [RFC2065] the SOA and appropriate
///    NXT and SIG records MUST be added.
///
/// ```
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum NegativeType {
    /// ```text
    ///            NXDOMAIN RESPONSE: TYPE 1.
    ///
    ///            Header:
    ///                RDCODE=NXDOMAIN
    ///            Query:
    ///                AN.EXAMPLE. A
    ///            Answer:
    ///                AN.EXAMPLE. CNAME TRIPPLE.XX.
    ///            Authority:
    ///                XX. SOA NS1.XX. HOSTMASTER.NS1.XX. ....
    ///                XX. NS NS1.XX.
    ///                XX. NS NS2.XX.
    ///            Additional:
    ///                NS1.XX. A 127.0.0.2
    ///                NS2.XX. A 127.0.0.3
    /// ```
    NameErrorType1,

    /// ```text
    ///            NXDOMAIN RESPONSE: TYPE 2.
    ///
    ///            Header:
    ///                RDCODE=NXDOMAIN
    ///            Query:
    ///                AN.EXAMPLE. A
    ///            Answer:
    ///                AN.EXAMPLE. CNAME TRIPPLE.XX.
    ///            Authority:
    ///                XX. SOA NS1.XX. HOSTMASTER.NS1.XX. ....
    ///            Additional:
    ///                <empty>
    /// ```
    NameErrorType2,

    /// ```text
    ///            NXDOMAIN RESPONSE: TYPE 3.
    ///
    ///            Header:
    ///                RDCODE=NXDOMAIN
    ///            Query:
    ///                AN.EXAMPLE. A
    ///            Answer:
    ///                AN.EXAMPLE. CNAME TRIPPLE.XX.
    ///            Authority:
    ///                <empty>
    ///            Additional:
    ///                <empty>
    /// ```
    NameErrorType3,

    /// ```text
    ///            NXDOMAIN RESPONSE: TYPE 4
    ///
    ///            Header:
    ///                RDCODE=NXDOMAIN
    ///            Query:
    ///                AN.EXAMPLE. A
    ///            Answer:
    ///                AN.EXAMPLE. CNAME TRIPPLE.XX.
    ///            Authority:
    ///                XX. NS NS1.XX.
    ///                XX. NS NS2.XX.
    ///            Additional:
    ///                NS1.XX. A 127.0.0.2
    ///                NS2.XX. A 127.0.0.3
    /// ```
    NameErrorType4,

    /// ```text
    ///            NODATA RESPONSE: TYPE 1.
    ///
    ///            Header:
    ///                RDCODE=NOERROR
    ///            Query:
    ///                ANOTHER.EXAMPLE. A
    ///            Answer:
    ///                <empty>
    ///            Authority:
    ///                EXAMPLE. SOA NS1.XX. HOSTMASTER.NS1.XX. ....
    ///                EXAMPLE. NS NS1.XX.
    ///                EXAMPLE. NS NS2.XX.
    ///            Additional:
    ///                NS1.XX. A 127.0.0.2
    ///                NS2.XX. A 127.0.0.3
    /// ```
    NoDataType1,

    /// ```text
    ///            NO DATA RESPONSE: TYPE 2.
    ///
    ///            Header:
    ///                RDCODE=NOERROR
    ///            Query:
    ///                ANOTHER.EXAMPLE. A
    ///            Answer:
    ///                <empty>
    ///            Authority:
    ///                EXAMPLE. SOA NS1.XX. HOSTMASTER.NS1.XX. ....
    ///            Additional:
    ///                <empty>
    /// ```
    NoDataType2,

    /// ```text
    ///            NO DATA RESPONSE: TYPE 3.
    ///            Header:
    ///                RDCODE=NOERROR
    ///            Query:
    ///                ANOTHER.EXAMPLE. A
    ///            Answer:
    ///                <empty>
    ///            Authority:
    ///                <empty>
    ///            Additional:
    ///                <empty>
    /// ```
    NoDataType3,

    /// ```text
    ///            REFERRAL RESPONSE.
    ///
    ///            Header:
    ///                RDCODE=NOERROR
    ///            Query:
    ///                AN.EXAMPLE. A
    ///            Answer:
    ///                AN.EXAMPLE. CNAME TRIPPLE.XX.
    ///            Authority:
    ///                XX. NS NS1.XX.
    ///                XX. NS NS2.XX.
    ///            Additional:
    ///                NS1.XX. A 127.0.0.2
    ///                NS2.XX. A 127.0.0.3
    ///
    ///            REFERRAL RESPONSE.
    ///
    ///            Header:
    ///                RDCODE=NOERROR
    ///            Query:
    ///                ANOTHER.EXAMPLE. A
    ///            Answer:
    ///                <empty>
    ///            Authority:
    ///                EXAMPLE. NS NS1.XX.
    ///                EXAMPLE. NS NS2.XX.
    ///            Additional:
    ///                NS1.XX. A 127.0.0.2
    ///                NS2.XX. A 127.0.0.3
    /// ```
    Referral,
}

impl NegativeType {
    /// The response contains an SOA record
    pub fn is_authoritative(&self) -> bool {
        matches!(
            self,
            NegativeType::NameErrorType1
                | NegativeType::NameErrorType2
                | NegativeType::NoDataType1
                | NegativeType::NoDataType2
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::op::{Message, Query, ResponseCode};
    use crate::rr::rdata::SOA;
    use crate::rr::RData;
    use crate::rr::{Name, Record, RecordType};

    use super::*;

    fn xx() -> Name {
        Name::from_ascii("XX.").unwrap()
    }

    fn ns1() -> Name {
        Name::from_ascii("NS1.XX.").unwrap()
    }

    fn ns2() -> Name {
        Name::from_ascii("NS1.XX.").unwrap()
    }

    fn hostmaster() -> Name {
        Name::from_ascii("HOSTMASTER.NS1.XX.").unwrap()
    }

    fn tripple_xx() -> Name {
        Name::from_ascii("TRIPPLE.XX.").unwrap()
    }

    fn example() -> Name {
        Name::from_ascii("EXAMPLE.").unwrap()
    }

    fn an_example() -> Name {
        Name::from_ascii("AN.EXAMPLE.").unwrap()
    }

    fn another_example() -> Name {
        Name::from_ascii("ANOTHER.EXAMPLE.").unwrap()
    }

    fn an_cname_record() -> Record {
        Record::from_rdata(an_example(), 88640, RData::CNAME(tripple_xx()))
    }

    fn ns1_record() -> Record {
        Record::from_rdata(xx(), 88640, RData::NS(ns1()))
    }

    fn ns2_record() -> Record {
        Record::from_rdata(xx(), 88640, RData::NS(ns2()))
    }

    fn ns1_a() -> Record {
        Record::from_rdata(xx(), 88640, RData::A([127, 0, 0, 2].into()))
    }

    fn ns2_a() -> Record {
        Record::from_rdata(xx(), 88640, RData::A([127, 0, 0, 3].into()))
    }

    fn soa() -> Record {
        Record::from_rdata(
            example(),
            88640,
            RData::SOA(SOA::new(ns1(), hostmaster(), 1, 2, 3, 4, 5)),
        )
    }

    fn an_query() -> Query {
        Query::query(an_example(), RecordType::A)
    }

    fn another_query() -> Query {
        Query::query(another_example(), RecordType::A)
    }

    #[test]
    fn test_contains_answer() {
        let mut message = Message::default();
        message.set_response_code(ResponseCode::NXDomain);
        message.add_query(Query::query(Name::root(), RecordType::A));
        message.add_answer(Record::from_rdata(
            Name::root(),
            88640,
            RData::A([127, 0, 0, 2].into()),
        ));

        let response = DnsResponse::from(message);

        assert!(response.contains_answer())
    }

    #[test]
    fn test_nx_type1() {
        let mut message = Message::default();
        message.set_response_code(ResponseCode::NXDomain);
        message.add_query(an_query());
        message.add_answer(an_cname_record());
        message.add_name_server(soa());
        message.add_name_server(ns1_record());
        message.add_name_server(ns2_record());
        message.add_additional(ns1_a());
        message.add_additional(ns2_a());

        let response = DnsResponse::from(message);
        let ty = response.negative_type();

        assert!(response.contains_answer());
        assert_eq!(ty.unwrap(), NegativeType::NameErrorType1);
    }

    #[test]
    fn test_nx_type2() {
        let mut message = Message::default();
        message.set_response_code(ResponseCode::NXDomain);
        message.add_query(an_query());
        message.add_answer(an_cname_record());
        message.add_name_server(soa());

        let response = DnsResponse::from(message);
        let ty = response.negative_type();

        assert!(response.contains_answer());
        assert_eq!(ty.unwrap(), NegativeType::NameErrorType2);
    }

    #[test]
    fn test_nx_type3() {
        let mut message = Message::default();
        message.set_response_code(ResponseCode::NXDomain);
        message.add_query(an_query());
        message.add_answer(an_cname_record());

        let response = DnsResponse::from(message);
        let ty = response.negative_type();

        assert!(response.contains_answer());
        assert_eq!(ty.unwrap(), NegativeType::NameErrorType3);
    }

    #[test]
    fn test_nx_type4() {
        let mut message = Message::default();
        message.set_response_code(ResponseCode::NXDomain);
        message.add_query(an_query());
        message.add_answer(an_cname_record());
        message.add_name_server(ns1_record());
        message.add_name_server(ns2_record());
        message.add_additional(ns1_a());
        message.add_additional(ns2_a());

        let response = DnsResponse::from(message);
        let ty = response.negative_type();

        assert!(response.contains_answer());
        assert_eq!(ty.unwrap(), NegativeType::NameErrorType4);
    }

    #[test]
    fn test_no_data_type1() {
        let mut message = Message::default();
        message.set_response_code(ResponseCode::NoError);
        message.add_query(another_query());
        message.add_name_server(soa());
        message.add_name_server(ns1_record());
        message.add_name_server(ns2_record());
        message.add_additional(ns1_a());
        message.add_additional(ns2_a());
        let response = DnsResponse::from(message);
        let ty = response.negative_type();

        assert!(!response.contains_answer());
        assert_eq!(ty.unwrap(), NegativeType::NoDataType1);
    }

    #[test]
    fn test_no_data_type2() {
        let mut message = Message::default();
        message.set_response_code(ResponseCode::NoError);
        message.add_query(another_query());
        message.add_name_server(soa());

        let response = DnsResponse::from(message);
        let ty = response.negative_type();

        assert!(!response.contains_answer());
        assert_eq!(ty.unwrap(), NegativeType::NoDataType2);
    }

    #[test]
    fn test_no_data_type3() {
        let mut message = Message::default();
        message.set_response_code(ResponseCode::NoError);
        message.add_query(another_query());

        let response = DnsResponse::from(message);
        let ty = response.negative_type();

        assert!(!response.contains_answer());
        assert_eq!(ty.unwrap(), NegativeType::NoDataType3);
    }

    #[test]
    fn referral() {
        let mut message = Message::default();
        message.set_response_code(ResponseCode::NoError);
        message.add_query(an_query());
        message.add_answer(an_cname_record());
        message.add_name_server(ns1_record());
        message.add_name_server(ns2_record());
        message.add_additional(ns1_a());
        message.add_additional(ns2_a());

        let response = DnsResponse::from(message);
        let ty = response.negative_type();

        assert!(response.contains_answer());
        assert_eq!(ty.unwrap(), NegativeType::Referral);

        let mut message = Message::default();
        message.set_response_code(ResponseCode::NoError);
        message.add_query(another_query());
        message.add_name_server(ns1_record());
        message.add_name_server(ns2_record());
        message.add_additional(ns1_a());
        message.add_additional(ns2_a());

        let response = DnsResponse::from(message);
        let ty = response.negative_type();

        assert!(!response.contains_answer());
        assert_eq!(ty.unwrap(), NegativeType::Referral);
    }

    #[test]
    fn contains_soa() {
        let mut message = Message::default();
        message.set_response_code(ResponseCode::NoError);
        message.add_query(Query::query(an_example(), RecordType::SOA));
        message.add_name_server(soa());

        let response = DnsResponse::from(message);

        assert!(response.contains_answer());
    }

    #[test]
    fn contains_any() {
        let mut message = Message::default();
        message.set_response_code(ResponseCode::NoError);
        message.add_query(Query::query(xx(), RecordType::ANY));
        message.add_name_server(ns1_record());
        message.add_additional(ns1_a());

        let response = DnsResponse::from(message);

        assert!(response.contains_answer());
    }
}
