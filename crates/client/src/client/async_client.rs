// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::proto::error::ProtoError;
use crate::proto::xfer::{
    DnsClientStream, DnsExchange, DnsExchangeBackground, DnsExchangeConnect, DnsExchangeSend,
    DnsHandle, DnsMultiplexer, DnsMultiplexerConnect, DnsMultiplexerSerialResponse, DnsRequest,
    DnsRequestOptions, DnsRequestSender, DnsResponse, DnsStreamHandle,
};
use crate::proto::TokioTime;
use futures::{ready, Future, FutureExt};
use log::debug;
use rand;

use crate::error::*;
use crate::op::{update_message, Message, MessageType, OpCode, Query};
use crate::rr::dnssec::Signer;
use crate::rr::{DNSClass, Name, Record, RecordSet, RecordType};

// TODO: this should be configurable
pub const MAX_PAYLOAD_LEN: u16 = 1500 - 40 - 8; // 1500 (general MTU) - 40 (ipv6 header) - 8 (udp header)

/// A DNS Client implemented over futures-rs.
///
/// This Client is generic and capable of wrapping UDP, TCP, and other underlying DNS protocol
///  implementations.
pub type ClientFuture<R> = AsyncClient<R>;

/// A DNS Client implemented over futures-rs.
///
/// This Client is generic and capable of wrapping UDP, TCP, and other underlying DNS protocol
///  implementations.
pub struct AsyncClient<R>
where
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    exchange: DnsExchange<R>,
}

impl AsyncClient<DnsMultiplexerSerialResponse> {
    /// Spawns a new AsyncClient Stream. This uses a default timeout of 5 seconds for all requests.
    ///
    /// # Arguments
    ///
    /// * `stream` - A stream of bytes that can be used to send/receive DNS messages
    ///              (see TcpClientStream or UdpClientStream)
    /// * `stream_handle` - The handle for the `stream` on which bytes can be sent/received.
    /// * `signer` - An optional signer for requests, needed for Updates with Sig0, otherwise not needed
    #[allow(clippy::new_ret_no_self)]
    pub fn new<F, S>(
        stream: F,
        stream_handle: Box<dyn DnsStreamHandle>,
        signer: Option<Arc<Signer>>,
    ) -> AsyncClientConnect<
        DnsMultiplexerConnect<F, S, Signer>,
        DnsMultiplexer<S, Signer>,
        DnsMultiplexerSerialResponse,
    >
    where
        F: Future<Output = Result<S, ProtoError>> + Send + Unpin + 'static,
        S: DnsClientStream + Unpin + 'static,
    {
        Self::with_timeout(stream, stream_handle, Duration::from_secs(5), signer)
    }

    /// Spawns a new AsyncClient Stream.
    ///
    /// # Arguments
    ///
    /// * `stream` - A stream of bytes that can be used to send/receive DNS messages
    ///              (see TcpClientStream or UdpClientStream)
    /// * `timeout_duration` - All requests may fail due to lack of response, this is the time to
    ///                        wait for a response before canceling the request.
    /// * `stream_handle` - The handle for the `stream` on which bytes can be sent/received.
    /// * `signer` - An optional signer for requests, needed for Updates with Sig0, otherwise not needed
    pub fn with_timeout<F, S>(
        stream: F,
        stream_handle: Box<dyn DnsStreamHandle>,
        timeout_duration: Duration,
        signer: Option<Arc<Signer>>,
    ) -> AsyncClientConnect<
        DnsMultiplexerConnect<F, S, Signer>,
        DnsMultiplexer<S, Signer>,
        DnsMultiplexerSerialResponse,
    >
    where
        F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
        S: DnsClientStream + Unpin + 'static,
    {
        let mp = DnsMultiplexer::with_timeout(stream, stream_handle, timeout_duration, signer);
        Self::connect(mp)
    }
}

impl<R> AsyncClient<R>
where
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    /// Returns a future, which itself wraps a future which is awaiting connection.
    ///
    /// The connect_future should be lazy.
    ///
    /// # Returns
    ///
    /// This returns a tuple of Self a handle to send dns messages and an optional background.
    ///  The background task must be run on an executor before handle is used, if it is Some.
    ///  If it is None, then another thread has already run the background.
    pub fn connect<F, S>(connect_future: F) -> AsyncClientConnect<F, S, R>
    where
        S: DnsRequestSender<DnsResponseFuture = R>,
        F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    {
        AsyncClientConnect(DnsExchange::connect(connect_future))
    }
}

impl<R> Clone for AsyncClient<R>
where
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    fn clone(&self) -> Self {
        AsyncClient {
            exchange: self.exchange.clone(),
        }
    }
}

impl<Resp> DnsHandle for AsyncClient<Resp>
where
    Resp: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    type Response = DnsExchangeSend<Resp>;

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&mut self, request: R) -> Self::Response {
        self.exchange.send(request)
    }
}

/// A future that resolves to an AsyncClient
#[must_use = "futures do nothing unless polled"]
pub struct AsyncClientConnect<F, S, R>(DnsExchangeConnect<F, S, R, TokioTime>)
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender<DnsResponseFuture = R> + 'static,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin;

#[allow(clippy::type_complexity)]
impl<F, S, R> Future for AsyncClientConnect<F, S, R>
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender<DnsResponseFuture = R> + 'static + Send + Unpin,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    type Output = Result<(AsyncClient<R>, DnsExchangeBackground<S, R, TokioTime>), ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let result = ready!(self.0.poll_unpin(cx));
        let client_background = result.map(|(exchange, bg)| (AsyncClient { exchange }, bg));

        Poll::Ready(client_background)
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
        ClientResponse(self.lookup(query, DnsRequestOptions::default()))
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
    ///   Secondary receiving such a hint is free to treat equivilence of this
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
        {
            let edns = message.edns_mut();
            edns.set_max_payload(MAX_PAYLOAD_LEN);
            edns.set_version(0);
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
        let message = update_message::create(rrset, zone_origin);

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
        let message = update_message::append(rrset, zone_origin, must_exist);

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

        let message = update_message::compare_and_swap(current, new, zone_origin);
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
    ///              record to delete
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
        let message = update_message::delete_by_rdata(rrset, zone_origin);

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
        let message = update_message::delete_rrset(record, zone_origin);

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
        let message = update_message::delete_all(name_of_records, zone_origin, dns_class);

        ClientResponse(self.send(message))
    }
}

/// A future result of a Client Request
#[must_use = "futures do nothing unless polled"]
pub struct ClientResponse<R>(R)
where
    R: Future<Output = Result<DnsResponse, ProtoError>> + Send + Unpin + 'static;

impl<R> Future for ClientResponse<R>
where
    R: Future<Output = Result<DnsResponse, ProtoError>> + Send + Unpin + 'static,
{
    type Output = Result<DnsResponse, ClientError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.0.poll_unpin(cx).map_err(ClientError::from)
    }
}
