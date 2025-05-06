// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use futures_util::{
    ready,
    stream::{Stream, StreamExt},
};
use rand;
use tracing::debug;

use hickory_proto::{
    ProtoError, ProtoErrorKind,
    op::{Edns, Message, MessageSigner, MessageType, OpCode, Query, update_message},
    rr::{DNSClass, Name, Record, RecordSet, RecordType, rdata::SOA},
    runtime::TokioTime,
    xfer::{
        BufDnsStreamHandle, DnsClientStream, DnsExchange, DnsExchangeBackground, DnsExchangeSend,
        DnsHandle, DnsMultiplexer, DnsRequest, DnsRequestOptions, DnsRequestSender, DnsResponse,
    },
};

#[doc(hidden)]
#[deprecated(since = "0.25.0", note = "use `Client` instead")]
pub type ClientFuture = Client;

/// A DNS Client implemented over futures-rs.
///
/// This Client is generic and capable of wrapping UDP, TCP, and other underlying DNS protocol
///  implementations.
#[derive(Clone)]
pub struct Client {
    exchange: DnsExchange,
    use_edns: bool,
}

impl Client {
    /// Spawns a new Client Stream. This uses a default timeout of 5 seconds for all requests.
    ///
    /// # Arguments
    ///
    /// * `stream` - A stream of bytes that can be used to send/receive DNS messages
    ///   (see TcpClientStream or UdpClientStream)
    /// * `stream_handle` - The handle for the `stream` on which bytes can be sent/received.
    /// * `signer` - An optional signer for requests, needed for Updates with Sig0, otherwise not needed
    #[allow(clippy::new_ret_no_self)]
    pub async fn new<F, S>(
        stream: F,
        stream_handle: BufDnsStreamHandle,
        signer: Option<Arc<dyn MessageSigner>>,
    ) -> Result<(Self, DnsExchangeBackground<DnsMultiplexer<S>, TokioTime>), ProtoError>
    where
        F: Future<Output = Result<S, ProtoError>> + Send + Unpin + 'static,
        S: DnsClientStream + 'static + Unpin,
    {
        Self::with_timeout(stream, stream_handle, Duration::from_secs(5), signer).await
    }

    /// Spawns a new Client Stream.
    ///
    /// # Arguments
    ///
    /// * `stream` - A stream of bytes that can be used to send/receive DNS messages
    ///   (see TcpClientStream or UdpClientStream)
    /// * `stream_handle` - The handle for the `stream` on which bytes can be sent/received.
    /// * `timeout_duration` - All requests may fail due to lack of response, this is the time to
    ///   wait for a response before canceling the request.
    /// * `signer` - An optional signer for requests, needed for Updates with Sig0, otherwise not needed
    pub async fn with_timeout<F, S>(
        stream: F,
        stream_handle: BufDnsStreamHandle,
        timeout_duration: Duration,
        signer: Option<Arc<dyn MessageSigner>>,
    ) -> Result<(Self, DnsExchangeBackground<DnsMultiplexer<S>, TokioTime>), ProtoError>
    where
        F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
        S: DnsClientStream + 'static + Unpin,
    {
        let mp = DnsMultiplexer::with_timeout(stream, stream_handle, timeout_duration, signer);
        Self::connect(mp).await
    }

    /// Returns a future, which itself wraps a future which is awaiting connection.
    ///
    /// The connect_future should be lazy.
    ///
    /// # Returns
    ///
    /// This returns a tuple of Self a handle to send dns messages and an optional background.
    ///  The background task must be run on an executor before handle is used, if it is Some.
    ///  If it is None, then another thread has already run the background.
    pub async fn connect<F, S>(
        connect_future: F,
    ) -> Result<(Self, DnsExchangeBackground<S, TokioTime>), ProtoError>
    where
        S: DnsRequestSender,
        F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    {
        let result = DnsExchange::connect(connect_future).await;
        let use_edns = true;
        result.map(|(exchange, bg)| (Self { exchange, use_edns }, bg))
    }

    /// (Re-)enable usage of EDNS for outgoing messages
    pub fn enable_edns(&mut self) {
        self.use_edns = true;
    }

    /// Disable usage of EDNS for outgoing messages
    pub fn disable_edns(&mut self) {
        self.use_edns = false;
    }
}

impl DnsHandle for Client {
    type Response = DnsExchangeSend;

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&self, request: R) -> Self::Response {
        self.exchange.send(request)
    }

    fn is_using_edns(&self) -> bool {
        self.use_edns
    }
}

impl<T> ClientHandle for T where T: DnsHandle {}

/// A trait for implementing high level functions of DNS.
pub trait ClientHandle: 'static + Clone + DnsHandle + Send {
    /// A *classic* DNS query
    ///
    /// *Note* As of now, this will not recurse on PTR or CNAME record responses, that is up to
    ///        the caller.
    ///
    /// # Arguments
    ///
    /// * `name` - the label to lookup
    /// * `query_class` - most likely this should always be DNSClass::IN
    /// * `query_type` - record type to lookup
    fn query(
        &mut self,
        name: Name,
        query_class: DNSClass,
        query_type: RecordType,
    ) -> ClientResponse<<Self as DnsHandle>::Response> {
        let mut query = Query::query(name, query_type);
        query.set_query_class(query_class);
        let mut options = DnsRequestOptions::default();
        options.use_edns = self.is_using_edns();
        ClientResponse(self.lookup(query, options))
    }

    /// Sends a NOTIFY message to the remote system
    ///
    /// [RFC 1996](https://tools.ietf.org/html/rfc1996), DNS NOTIFY, August 1996
    ///
    ///
    /// ```text
    /// 1. Rationale and Scope
    ///
    ///   1.1. Slow propagation of new and changed data in a DNS zone can be
    ///   due to a zone's relatively long refresh times.  Longer refresh times
    ///   are beneficial in that they reduce load on the Primary Zone Servers, but
    ///   that benefit comes at the cost of long intervals of incoherence among
    ///   authority servers whenever the zone is updated.
    ///
    ///   1.2. The DNS NOTIFY transaction allows Primary Zone Servers to inform Secondary
    ///   Zone Servers when the zone has changed -- an interrupt as opposed to poll
    ///   model -- which it is hoped will reduce propagation delay while not
    ///   unduly increasing the masters' load.  This specification only allows
    ///   slaves to be notified of SOA RR changes, but the architecture of
    ///   NOTIFY is intended to be extensible to other RR types.
    ///
    ///   1.3. This document intentionally gives more definition to the roles
    ///   of "Primary", "Secondary" and "Stealth" servers, their enumeration in NS
    ///   RRs, and the SOA MNAME field.  In that sense, this document can be
    ///   considered an addendum to [RFC1035].
    ///
    /// ```
    ///
    /// The below section describes how the Notify message should be constructed. The function
    ///  implementation accepts a Record, but the actual data of the record should be ignored by the
    ///  server, i.e. the server should make a request subsequent to receiving this Notification for
    ///  the authority record, but could be used to decide to request an update or not:
    ///
    /// ```text
    ///   3.7. A NOTIFY request has QDCOUNT>0, ANCOUNT>=0, AUCOUNT>=0,
    ///   ADCOUNT>=0.  If ANCOUNT>0, then the answer section represents an
    ///   unsecure hint at the new RRset for this <QNAME,QCLASS,QTYPE>.  A
    ///   Secondary receiving such a hint is free to treat equivalence of this
    ///   answer section with its local data as a "no further work needs to be
    ///   done" indication.  If ANCOUNT=0, or ANCOUNT>0 and the answer section
    ///   differs from the Secondary's local data, then the Secondary should query its
    ///   known Primaries to retrieve the new data.
    /// ```
    ///
    /// Client's should be ready to handle, or be aware of, a server response of NOTIMP:
    ///
    /// ```text
    ///   3.12. If a NOTIFY request is received by a Secondary who does not
    ///   implement the NOTIFY opcode, it will respond with a NOTIMP
    ///   (unimplemented feature error) message.  A Primary Zone Server who receives
    ///   such a NOTIMP should consider the NOTIFY transaction complete for
    ///   that Secondary.
    /// ```
    ///
    /// # Arguments
    ///
    /// * `name` - the label which is being notified
    /// * `query_class` - most likely this should always be DNSClass::IN
    /// * `query_type` - record type which has been updated
    /// * `rrset` - the new version of the record(s) being notified
    fn notify<R>(
        &mut self,
        name: Name,
        query_class: DNSClass,
        query_type: RecordType,
        rrset: Option<R>,
    ) -> ClientResponse<<Self as DnsHandle>::Response>
    where
        R: Into<RecordSet>,
    {
        debug!("notifying: {} {:?}", name, query_type);

        // build the message
        let mut message: Message = Message::new();
        let id: u16 = rand::random();
        message
            .set_id(id)
            // 3.3. NOTIFY is similar to QUERY in that it has a request message with
            // the header QR flag "clear" and a response message with QR "set".  The
            // response message contains no useful information, but its reception by
            // the Primary is an indication that the Secondary has received the NOTIFY
            // and that the Primary Zone Server can remove the Secondary from any retry queue for
            // this NOTIFY event.
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Notify);

        // Extended dns
        if self.is_using_edns() {
            message
                .extensions_mut()
                .get_or_insert_with(Edns::new)
                .set_max_payload(update_message::MAX_PAYLOAD_LEN)
                .set_version(0);
        }

        // add the query
        let mut query: Query = Query::new();
        query
            .set_name(name)
            .set_query_class(query_class)
            .set_query_type(query_type);
        message.add_query(query);

        // add the notify message, see https://tools.ietf.org/html/rfc1996, section 3.7
        if let Some(rrset) = rrset {
            message.add_answers(rrset.into());
        }

        ClientResponse(self.send(message))
    }

    /// Sends a record to create on the server, this will fail if the record exists (atomicity
    ///  depends on the server)
    ///
    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    ///  2.4.3 - RRset Does Not Exist
    ///
    ///   No RRs with a specified NAME and TYPE (in the zone and class denoted
    ///   by the Zone Section) can exist.
    ///
    ///   For this prerequisite, a requestor adds to the section a single RR
    ///   whose NAME and TYPE are equal to that of the RRset whose nonexistence
    ///   is required.  The RDLENGTH of this record is zero (0), and RDATA
    ///   field is therefore empty.  CLASS must be specified as NONE in order
    ///   to distinguish this condition from a valid RR whose RDLENGTH is
    ///   naturally zero (0) (for example, the NULL RR).  TTL must be specified
    ///   as zero (0).
    ///
    /// 2.5.1 - Add To An RRset
    ///
    ///    RRs are added to the Update Section whose NAME, TYPE, TTL, RDLENGTH
    ///    and RDATA are those being added, and CLASS is the same as the zone
    ///    class.  Any duplicate RRs will be silently ignored by the Primary Zone
    ///    Server.
    /// ```
    ///
    /// # Arguments
    ///
    /// * `rrset` - the record(s) to create
    /// * `zone_origin` - the zone name to update, i.e. SOA name
    ///
    /// The update must go to a zone authority (i.e. the server used in the ClientConnection)
    fn create<R>(
        &mut self,
        rrset: R,
        zone_origin: Name,
    ) -> ClientResponse<<Self as DnsHandle>::Response>
    where
        R: Into<RecordSet>,
    {
        let rrset = rrset.into();
        let message = update_message::create(rrset, zone_origin, self.is_using_edns());

        ClientResponse(self.send(message))
    }

    /// Appends a record to an existing rrset, optionally require the rrset to exist (atomicity
    ///  depends on the server)
    ///
    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    /// 2.4.1 - RRset Exists (Value Independent)
    ///
    ///   At least one RR with a specified NAME and TYPE (in the zone and class
    ///   specified in the Zone Section) must exist.
    ///
    ///   For this prerequisite, a requestor adds to the section a single RR
    ///   whose NAME and TYPE are equal to that of the zone RRset whose
    ///   existence is required.  RDLENGTH is zero and RDATA is therefore
    ///   empty.  CLASS must be specified as ANY to differentiate this
    ///   condition from that of an actual RR whose RDLENGTH is naturally zero
    ///   (0) (e.g., NULL).  TTL is specified as zero (0).
    ///
    /// 2.5.1 - Add To An RRset
    ///
    ///    RRs are added to the Update Section whose NAME, TYPE, TTL, RDLENGTH
    ///    and RDATA are those being added, and CLASS is the same as the zone
    ///    class.  Any duplicate RRs will be silently ignored by the Primary Zone
    ///    Server.
    /// ```
    ///
    /// # Arguments
    ///
    /// * `rrset` - the record(s) to append to an RRSet
    /// * `zone_origin` - the zone name to update, i.e. SOA name
    /// * `must_exist` - if true, the request will fail if the record does not exist
    ///
    /// The update must go to a zone authority (i.e. the server used in the ClientConnection). If
    /// the rrset does not exist and must_exist is false, then the RRSet will be created.
    fn append<R>(
        &mut self,
        rrset: R,
        zone_origin: Name,
        must_exist: bool,
    ) -> ClientResponse<<Self as DnsHandle>::Response>
    where
        R: Into<RecordSet>,
    {
        let rrset = rrset.into();
        let message = update_message::append(rrset, zone_origin, must_exist, self.is_using_edns());

        ClientResponse(self.send(message))
    }

    /// Compares and if it matches, swaps it for the new value (atomicity depends on the server)
    ///
    /// ```text
    ///  2.4.2 - RRset Exists (Value Dependent)
    ///
    ///   A set of RRs with a specified NAME and TYPE exists and has the same
    ///   members with the same RDATAs as the RRset specified here in this
    ///   section.  While RRset ordering is undefined and therefore not
    ///   significant to this comparison, the sets be identical in their
    ///   extent.
    ///
    ///   For this prerequisite, a requestor adds to the section an entire
    ///   RRset whose preexistence is required.  NAME and TYPE are that of the
    ///   RRset being denoted.  CLASS is that of the zone.  TTL must be
    ///   specified as zero (0) and is ignored when comparing RRsets for
    ///   identity.
    ///
    ///  2.5.4 - Delete An RR From An RRset
    ///
    ///   RRs to be deleted are added to the Update Section.  The NAME, TYPE,
    ///   RDLENGTH and RDATA must match the RR being deleted.  TTL must be
    ///   specified as zero (0) and will otherwise be ignored by the Primary
    ///   Zone Server.  CLASS must be specified as NONE to distinguish this from an
    ///   RR addition.  If no such RRs exist, then this Update RR will be
    ///   silently ignored by the Primary Zone Server.
    ///
    ///  2.5.1 - Add To An RRset
    ///
    ///   RRs are added to the Update Section whose NAME, TYPE, TTL, RDLENGTH
    ///   and RDATA are those being added, and CLASS is the same as the zone
    ///   class.  Any duplicate RRs will be silently ignored by the Primary
    ///   Zone Server.
    /// ```
    ///
    /// # Arguments
    ///
    /// * `current` - the current rrset which must exist for the swap to complete
    /// * `new` - the new rrset with which to replace the current rrset
    /// * `zone_origin` - the zone name to update, i.e. SOA name
    ///
    /// The update must go to a zone authority (i.e. the server used in the ClientConnection).
    fn compare_and_swap<C, N>(
        &mut self,
        current: C,
        new: N,
        zone_origin: Name,
    ) -> ClientResponse<<Self as DnsHandle>::Response>
    where
        C: Into<RecordSet>,
        N: Into<RecordSet>,
    {
        let current = current.into();
        let new = new.into();

        let message =
            update_message::compare_and_swap(current, new, zone_origin, self.is_using_edns());
        ClientResponse(self.send(message))
    }

    /// Deletes a record (by rdata) from an rrset, optionally require the rrset to exist.
    ///
    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    /// 2.4.1 - RRset Exists (Value Independent)
    ///
    ///   At least one RR with a specified NAME and TYPE (in the zone and class
    ///   specified in the Zone Section) must exist.
    ///
    ///   For this prerequisite, a requestor adds to the section a single RR
    ///   whose NAME and TYPE are equal to that of the zone RRset whose
    ///   existence is required.  RDLENGTH is zero and RDATA is therefore
    ///   empty.  CLASS must be specified as ANY to differentiate this
    ///   condition from that of an actual RR whose RDLENGTH is naturally zero
    ///   (0) (e.g., NULL).  TTL is specified as zero (0).
    ///
    /// 2.5.4 - Delete An RR From An RRset
    ///
    ///   RRs to be deleted are added to the Update Section.  The NAME, TYPE,
    ///   RDLENGTH and RDATA must match the RR being deleted.  TTL must be
    ///   specified as zero (0) and will otherwise be ignored by the Primary
    ///   Zone Server.  CLASS must be specified as NONE to distinguish this from an
    ///   RR addition.  If no such RRs exist, then this Update RR will be
    ///   silently ignored by the Primary Zone Server.
    /// ```
    ///
    /// # Arguments
    ///
    /// * `rrset` - the record(s) to delete from a RRSet, the name, type and rdata must match the
    ///   record to delete
    /// * `zone_origin` - the zone name to update, i.e. SOA name
    /// * `signer` - the signer, with private key, to use to sign the request
    ///
    /// The update must go to a zone authority (i.e. the server used in the ClientConnection). If
    /// the rrset does not exist and must_exist is false, then the RRSet will be deleted.
    fn delete_by_rdata<R>(
        &mut self,
        rrset: R,
        zone_origin: Name,
    ) -> ClientResponse<<Self as DnsHandle>::Response>
    where
        R: Into<RecordSet>,
    {
        let rrset = rrset.into();
        let message = update_message::delete_by_rdata(rrset, zone_origin, self.is_using_edns());

        ClientResponse(self.send(message))
    }

    /// Deletes an entire rrset, optionally require the rrset to exist.
    ///
    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    /// 2.4.1 - RRset Exists (Value Independent)
    ///
    ///   At least one RR with a specified NAME and TYPE (in the zone and class
    ///   specified in the Zone Section) must exist.
    ///
    ///   For this prerequisite, a requestor adds to the section a single RR
    ///   whose NAME and TYPE are equal to that of the zone RRset whose
    ///   existence is required.  RDLENGTH is zero and RDATA is therefore
    ///   empty.  CLASS must be specified as ANY to differentiate this
    ///   condition from that of an actual RR whose RDLENGTH is naturally zero
    ///   (0) (e.g., NULL).  TTL is specified as zero (0).
    ///
    /// 2.5.2 - Delete An RRset
    ///
    ///   One RR is added to the Update Section whose NAME and TYPE are those
    ///   of the RRset to be deleted.  TTL must be specified as zero (0) and is
    ///   otherwise not used by the Primary Zone Server.  CLASS must be specified as
    ///   ANY.  RDLENGTH must be zero (0) and RDATA must therefore be empty.
    ///   If no such RRset exists, then this Update RR will be silently ignored
    ///   by the Primary Zone Server.
    /// ```
    ///
    /// # Arguments
    ///
    /// * `record` - The name, class and record_type will be used to match and delete the RecordSet
    /// * `zone_origin` - the zone name to update, i.e. SOA name
    ///
    /// The update must go to a zone authority (i.e. the server used in the ClientConnection). If
    /// the rrset does not exist and must_exist is false, then the RRSet will be deleted.
    fn delete_rrset(
        &mut self,
        record: Record,
        zone_origin: Name,
    ) -> ClientResponse<<Self as DnsHandle>::Response> {
        assert!(zone_origin.zone_of(record.name()));
        let message = update_message::delete_rrset(record, zone_origin, self.is_using_edns());

        ClientResponse(self.send(message))
    }

    /// Deletes all records at the specified name
    ///
    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    /// 2.5.3 - Delete All RRsets From A Name
    ///
    ///   One RR is added to the Update Section whose NAME is that of the name
    ///   to be cleansed of RRsets.  TYPE must be specified as ANY.  TTL must
    ///   be specified as zero (0) and is otherwise not used by the Primary
    ///   Zone Server.  CLASS must be specified as ANY.  RDLENGTH must be zero (0)
    ///   and RDATA must therefore be empty.  If no such RRsets exist, then
    ///   this Update RR will be silently ignored by the Primary Zone Server.
    /// ```
    ///
    /// # Arguments
    ///
    /// * `name_of_records` - the name of all the record sets to delete
    /// * `zone_origin` - the zone name to update, i.e. SOA name
    /// * `dns_class` - the class of the SOA
    ///
    /// The update must go to a zone authority (i.e. the server used in the ClientConnection). This
    /// operation attempts to delete all resource record sets the specified name regardless of
    /// the record type.
    fn delete_all(
        &mut self,
        name_of_records: Name,
        zone_origin: Name,
        dns_class: DNSClass,
    ) -> ClientResponse<<Self as DnsHandle>::Response> {
        assert!(zone_origin.zone_of(&name_of_records));
        let message = update_message::delete_all(
            name_of_records,
            zone_origin,
            dns_class,
            self.is_using_edns(),
        );

        ClientResponse(self.send(message))
    }

    /// Download all records from a zone, or all records modified since given SOA was observed.
    /// The request will either be a AXFR Query (ask for full zone transfer) if a SOA was not
    /// provided, or a IXFR Query (incremental zone transfer) if a SOA was provided.
    ///
    /// # Arguments
    /// * `zone_origin` - the zone name to update, i.e. SOA name
    /// * `last_soa` - the last SOA known, if any. If provided, name must match `zone_origin`
    fn zone_transfer(
        &mut self,
        zone_origin: Name,
        last_soa: Option<SOA>,
    ) -> ClientStreamXfr<<Self as DnsHandle>::Response> {
        let ixfr = last_soa.is_some();
        let message = update_message::zone_transfer(zone_origin, last_soa);

        ClientStreamXfr::new(self.send(message), ixfr)
    }
}

/// A stream result of a Client Request
#[must_use = "stream do nothing unless polled"]
pub struct ClientStreamingResponse<R>(pub(crate) R)
where
    R: Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin + 'static;

impl<R> Stream for ClientStreamingResponse<R>
where
    R: Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin + 'static,
{
    type Item = Result<DnsResponse, ProtoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(ready!(self.0.poll_next_unpin(cx)))
    }
}

/// A future result of a Client Request
#[must_use = "futures do nothing unless polled"]
pub struct ClientResponse<R>(pub(crate) R)
where
    R: Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin + 'static;

impl<R> Future for ClientResponse<R>
where
    R: Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin + 'static,
{
    type Output = Result<DnsResponse, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(match ready!(self.0.poll_next_unpin(cx)) {
            Some(r) => r,
            None => Err(ProtoError::from(ProtoErrorKind::Timeout)),
        })
    }
}

/// A stream result of a zone transfer Client Request
/// Accept messages until the end of a zone transfer. For AXFR, it search for a starting and an
/// ending SOA. For IXFR, it do so taking into account there will be other SOA inbetween
#[must_use = "stream do nothing unless polled"]
pub struct ClientStreamXfr<R>
where
    R: Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin + 'static,
{
    state: ClientStreamXfrState<R>,
}

impl<R> ClientStreamXfr<R>
where
    R: Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin + 'static,
{
    fn new(inner: R, maybe_incr: bool) -> Self {
        Self {
            state: ClientStreamXfrState::Start { inner, maybe_incr },
        }
    }
}

/// State machine for ClientStreamXfr, implementing almost all logic
#[derive(Debug)]
enum ClientStreamXfrState<R> {
    Start {
        inner: R,
        maybe_incr: bool,
    },
    Second {
        inner: R,
        expected_serial: u32,
        maybe_incr: bool,
    },
    Axfr {
        inner: R,
        expected_serial: u32,
    },
    Ixfr {
        inner: R,
        even: bool,
        expected_serial: u32,
    },
    Ended,
    Invalid,
}

impl<R> ClientStreamXfrState<R> {
    /// Helper to get the stream from the enum
    fn inner(&mut self) -> &mut R {
        use ClientStreamXfrState::*;
        match self {
            Start { inner, .. } => inner,
            Second { inner, .. } => inner,
            Axfr { inner, .. } => inner,
            Ixfr { inner, .. } => inner,
            Ended | Invalid => unreachable!(),
        }
    }

    /// Helper to ingest answer Records
    // TODO: this is complex enough it should get its own tests
    fn process(&mut self, answers: &[Record]) -> Result<(), ProtoError> {
        use ClientStreamXfrState::*;
        fn get_serial(r: &Record) -> Option<u32> {
            r.data().as_soa().map(SOA::serial)
        }

        if answers.is_empty() {
            return Ok(());
        }
        match std::mem::replace(self, Invalid) {
            Start { inner, maybe_incr } => {
                if let Some(expected_serial) = get_serial(&answers[0]) {
                    *self = Second {
                        inner,
                        maybe_incr,
                        expected_serial,
                    };
                    self.process(&answers[1..])
                } else {
                    *self = Ended;
                    Ok(())
                }
            }
            Second {
                inner,
                maybe_incr,
                expected_serial,
            } => {
                if let Some(serial) = get_serial(&answers[0]) {
                    // maybe IXFR, or empty AXFR
                    if serial == expected_serial {
                        // empty AXFR
                        *self = Ended;
                        if answers.len() == 1 {
                            Ok(())
                        } else {
                            // invalid answer : trailing records
                            Err(ProtoErrorKind::Message(
                                "invalid zone transfer, contains trailing records",
                            )
                            .into())
                        }
                    } else if maybe_incr {
                        *self = Ixfr {
                            inner,
                            expected_serial,
                            even: true,
                        };
                        self.process(&answers[1..])
                    } else {
                        *self = Ended;
                        Err(ProtoErrorKind::Message(
                            "invalid zone transfer, expected AXFR, got IXFR",
                        )
                        .into())
                    }
                } else {
                    // standard AXFR
                    *self = Axfr {
                        inner,
                        expected_serial,
                    };
                    self.process(&answers[1..])
                }
            }
            Axfr {
                inner,
                expected_serial,
            } => {
                let soa_count = answers
                    .iter()
                    .filter(|a| a.record_type() == RecordType::SOA)
                    .count();
                match soa_count {
                    0 => {
                        *self = Axfr {
                            inner,
                            expected_serial,
                        };
                        Ok(())
                    }
                    1 => {
                        *self = Ended;
                        match answers.last().map(|r| r.record_type()) {
                            Some(RecordType::SOA) => Ok(()),
                            _ => Err(ProtoErrorKind::Message(
                                "invalid zone transfer, contains trailing records",
                            )
                            .into()),
                        }
                    }
                    _ => {
                        *self = Ended;
                        Err(ProtoErrorKind::Message(
                            "invalid zone transfer, contains trailing records",
                        )
                        .into())
                    }
                }
            }
            Ixfr {
                inner,
                even,
                expected_serial,
            } => {
                let even = answers
                    .iter()
                    .fold(even, |even, a| even ^ (a.record_type() == RecordType::SOA));
                if even {
                    if let Some(serial) = get_serial(answers.last().unwrap()) {
                        if serial == expected_serial {
                            *self = Ended;
                            return Ok(());
                        }
                    }
                }
                *self = Ixfr {
                    inner,
                    even,
                    expected_serial,
                };
                Ok(())
            }
            Ended | Invalid => {
                unreachable!();
            }
        }
    }
}

impl<R> Stream for ClientStreamXfr<R>
where
    R: Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin + 'static,
{
    type Item = Result<DnsResponse, ProtoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        use ClientStreamXfrState::*;

        if matches!(self.state, Ended) {
            return Poll::Ready(None);
        }

        let message = ready!(self.state.inner().poll_next_unpin(cx)).map(|response| {
            let ok = response?;
            self.state.process(ok.answers())?;
            Ok(ok)
        });
        Poll::Ready(message)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    use ClientStreamXfrState::*;
    use futures_util::stream::iter;
    use hickory_proto::{
        rr::{
            RData,
            rdata::{A, SOA},
        },
        runtime::TokioRuntimeProvider,
    };
    use test_support::subscribe;

    fn soa_record(serial: u32) -> Record {
        let soa = RData::SOA(SOA::new(
            Name::from_ascii("example.com.").unwrap(),
            Name::from_ascii("admin.example.com.").unwrap(),
            serial,
            60,
            60,
            60,
            60,
        ));
        Record::from_rdata(Name::from_ascii("example.com.").unwrap(), 600, soa)
    }

    fn a_record(ip: u8) -> Record {
        let a = RData::A(A::new(0, 0, 0, ip));
        Record::from_rdata(Name::from_ascii("www.example.com.").unwrap(), 600, a)
    }

    fn get_stream_testcase(
        records: Vec<Vec<Record>>,
    ) -> impl Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin + 'static {
        let stream = records.into_iter().map(|r| {
            Ok({
                let mut m = Message::new();
                m.insert_answers(r);
                DnsResponse::from_message(m).unwrap()
            })
        });
        iter(stream)
    }

    #[tokio::test]
    async fn test_stream_xfr_valid_axfr() {
        subscribe();
        let stream = get_stream_testcase(vec![vec![
            soa_record(3),
            a_record(1),
            a_record(2),
            soa_record(3),
        ]]);
        let mut stream = ClientStreamXfr::new(stream, false);
        assert!(matches!(stream.state, Start { .. }));

        let response = stream.next().await.unwrap().unwrap();
        assert!(matches!(stream.state, Ended));
        assert_eq!(response.answers().len(), 4);

        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn test_stream_xfr_valid_axfr_multipart() {
        subscribe();
        let stream = get_stream_testcase(vec![
            vec![soa_record(3)],
            vec![a_record(1)],
            vec![soa_record(3)],
            vec![a_record(2)], // will be ignored as connection is dropped before reading this message
        ]);
        let mut stream = ClientStreamXfr::new(stream, false);
        assert!(matches!(stream.state, Start { .. }));

        let response = stream.next().await.unwrap().unwrap();
        assert!(matches!(stream.state, Second { .. }));
        assert_eq!(response.answers().len(), 1);

        let response = stream.next().await.unwrap().unwrap();
        assert!(matches!(stream.state, Axfr { .. }));
        assert_eq!(response.answers().len(), 1);

        let response = stream.next().await.unwrap().unwrap();
        assert!(matches!(stream.state, Ended));
        assert_eq!(response.answers().len(), 1);

        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn test_stream_xfr_empty_axfr() {
        subscribe();
        let stream = get_stream_testcase(vec![vec![soa_record(3)], vec![soa_record(3)]]);
        let mut stream = ClientStreamXfr::new(stream, false);
        assert!(matches!(stream.state, Start { .. }));

        let response = stream.next().await.unwrap().unwrap();
        assert!(matches!(stream.state, Second { .. }));
        assert_eq!(response.answers().len(), 1);

        let response = stream.next().await.unwrap().unwrap();
        assert!(matches!(stream.state, Ended));
        assert_eq!(response.answers().len(), 1);

        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn test_stream_xfr_axfr_with_ixfr_reply() {
        subscribe();
        let stream = get_stream_testcase(vec![vec![
            soa_record(3),
            soa_record(2),
            a_record(1),
            soa_record(3),
            a_record(2),
            soa_record(3),
        ]]);
        let mut stream = ClientStreamXfr::new(stream, false);
        assert!(matches!(stream.state, Start { .. }));

        stream.next().await.unwrap().unwrap_err();
        assert!(matches!(stream.state, Ended));

        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn test_stream_xfr_axfr_with_non_xfr_reply() {
        subscribe();
        let stream = get_stream_testcase(vec![
            vec![a_record(1)], // assume this is an error response, not a zone transfer
            vec![a_record(2)],
        ]);
        let mut stream = ClientStreamXfr::new(stream, false);
        assert!(matches!(stream.state, Start { .. }));

        let response = stream.next().await.unwrap().unwrap();
        assert!(matches!(stream.state, Ended));
        assert_eq!(response.answers().len(), 1);

        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn test_stream_xfr_invalid_axfr_multipart() {
        subscribe();
        let stream = get_stream_testcase(vec![
            vec![soa_record(3)],
            vec![a_record(1)],
            vec![soa_record(3), a_record(2)],
            vec![soa_record(3)],
        ]);
        let mut stream = ClientStreamXfr::new(stream, false);
        assert!(matches!(stream.state, Start { .. }));

        let response = stream.next().await.unwrap().unwrap();
        assert!(matches!(stream.state, Second { .. }));
        assert_eq!(response.answers().len(), 1);

        let response = stream.next().await.unwrap().unwrap();
        assert!(matches!(stream.state, Axfr { .. }));
        assert_eq!(response.answers().len(), 1);

        stream.next().await.unwrap().unwrap_err();
        assert!(matches!(stream.state, Ended));

        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn test_stream_xfr_valid_ixfr() {
        subscribe();
        let stream = get_stream_testcase(vec![vec![
            soa_record(3),
            soa_record(2),
            a_record(1),
            soa_record(3),
            a_record(2),
            soa_record(3),
        ]]);
        let mut stream = ClientStreamXfr::new(stream, true);
        assert!(matches!(stream.state, Start { .. }));

        let response = stream.next().await.unwrap().unwrap();
        assert!(matches!(stream.state, Ended));
        assert_eq!(response.answers().len(), 6);

        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn test_stream_xfr_valid_ixfr_multipart() {
        subscribe();
        let stream = get_stream_testcase(vec![
            vec![soa_record(3)],
            vec![soa_record(2)],
            vec![a_record(1)],
            vec![soa_record(3)],
            vec![a_record(2)],
            vec![soa_record(3)],
            vec![a_record(3)], //
        ]);
        let mut stream = ClientStreamXfr::new(stream, true);
        assert!(matches!(stream.state, Start { .. }));

        let response = stream.next().await.unwrap().unwrap();
        assert!(matches!(stream.state, Second { .. }));
        assert_eq!(response.answers().len(), 1);

        let response = stream.next().await.unwrap().unwrap();
        assert!(matches!(stream.state, Ixfr { even: true, .. }));
        assert_eq!(response.answers().len(), 1);

        let response = stream.next().await.unwrap().unwrap();
        assert!(matches!(stream.state, Ixfr { even: true, .. }));
        assert_eq!(response.answers().len(), 1);

        let response = stream.next().await.unwrap().unwrap();
        assert!(matches!(stream.state, Ixfr { even: false, .. }));
        assert_eq!(response.answers().len(), 1);

        let response = stream.next().await.unwrap().unwrap();
        assert!(matches!(stream.state, Ixfr { even: false, .. }));
        assert_eq!(response.answers().len(), 1);

        let response = stream.next().await.unwrap().unwrap();
        assert!(matches!(stream.state, Ended));
        assert_eq!(response.answers().len(), 1);

        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn async_client() {
        subscribe();
        use crate::client::{Client, ClientHandle};
        use hickory_proto::{
            rr::{DNSClass, Name, RData, RecordType},
            tcp::TcpClientStream,
        };
        use std::str::FromStr;

        // Since we used UDP in the previous examples, let's change things up a bit and use TCP here
        let addr = SocketAddr::from(([8, 8, 8, 8], 53));
        let (stream, sender) = TcpClientStream::new(addr, None, None, TokioRuntimeProvider::new());

        // Create a new client, the bg is a background future which handles
        //   the multiplexing of the DNS requests to the server.
        //   the client is a handle to an unbounded queue for sending requests via the
        //   background. The background must be scheduled to run before the client can
        //   send any dns requests
        let client = Client::new(stream, sender, None);

        // await the connection to be established
        let (mut client, bg) = client.await.expect("connection failed");

        // make sure to run the background task
        tokio::spawn(bg);

        // Create a query future
        let query = client.query(
            Name::from_str("www.example.com.").unwrap(),
            DNSClass::IN,
            RecordType::A,
        );

        // wait for its response
        let (message_returned, buffer) = query.await.unwrap().into_parts();

        // validate it's what we expected
        if let RData::A(addr) = message_returned.answers()[0].data() {
            assert_eq!(*addr, A::new(93, 184, 215, 14));
        }

        let message_parsed = Message::from_vec(&buffer)
            .expect("buffer was parsed already by Client so we should be able to do it again");

        // validate it's what we expected
        if let RData::A(addr) = message_parsed.answers()[0].data() {
            assert_eq!(*addr, A::new(93, 184, 215, 14));
        }
    }
}
