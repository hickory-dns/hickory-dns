// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::sync::Arc;
use std::time::Duration;
use std::pin::Pin;
use std::task::Context;

use futures::{Future, FutureExt, Poll};
use proto::error::ProtoError;
use proto::xfer::{
    BufDnsRequestStreamHandle, DnsClientStream, DnsExchange, DnsExchangeConnect, DnsHandle,
    DnsMultiplexer, DnsMultiplexerConnect, DnsMultiplexerSerialResponse, DnsRequest,
    DnsRequestOptions, DnsRequestSender, DnsResponse, DnsStreamHandle, OneshotDnsResponseReceiver,
};
use rand;

use crate::error::*;
use crate::op::{Message, MessageType, OpCode, Query, update_message};
use crate::rr::dnssec::Signer;
use crate::rr::{DNSClass, Name, Record, RecordSet, RecordType};

// TODO: this should be configurable
pub const MAX_PAYLOAD_LEN: u16 = 1500 - 40 - 8; // 1500 (general MTU) - 40 (ipv6 header) - 8 (udp header)

// TODO: ClientFuture to ClientAsync or AsyncClient?
/// A DNS Client implemented over futures-rs.
///
/// This Client is generic and capable of wrapping UDP, TCP, and other underlying DNS protocol
///  implementations.
#[must_use = "futures do nothing unless polled"]
pub struct ClientFuture<SenderFuture, Sender, Response>
where
    SenderFuture: Future<Output = Result<Sender, ProtoError>> + 'static + Send + Unpin,
    Sender: DnsRequestSender<DnsResponseFuture = Response> + 'static,
    Response: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    inner: InnerClientFuture<SenderFuture, Sender, Response>,
}

impl<F, S>
    ClientFuture<
        DnsMultiplexerConnect<F, S, Signer>,
        DnsMultiplexer<S, Signer, Box<dyn DnsStreamHandle>>,
        DnsMultiplexerSerialResponse,
    >
where
    F: Future<Output = Result<S, ProtoError>> + Send + Unpin + 'static,
    S: DnsClientStream + Send + Unpin + 'static,
{
    /// Spawns a new ClientFuture Stream. This uses a default timeout of 5 seconds for all requests.
    ///
    /// # Arguments
    ///
    /// * `stream` - A stream of bytes that can be used to send/receive DNS messages
    ///              (see TcpClientStream or UdpClientStream)
    /// * `stream_handle` - The handle for the `stream` on which bytes can be sent/received.
    /// * `signer` - An optional signer for requests, needed for Updates with Sig0, otherwise not needed
    pub fn new(
        stream: F,
        stream_handle: Box<dyn DnsStreamHandle>,
        signer: Option<Arc<Signer>>,
    ) -> (Self, BasicClientHandle<DnsMultiplexerSerialResponse>) {
        Self::with_timeout(stream, stream_handle, Duration::from_secs(5), signer)
    }

    /// Spawns a new ClientFuture Stream.
    ///
    /// # Arguments
    ///
    /// * `stream` - A stream of bytes that can be used to send/receive DNS messages
    ///              (see TcpClientStream or UdpClientStream)
    /// * `timeout_duration` - All requests may fail due to lack of response, this is the time to
    ///                        wait for a response before canceling the request.
    /// * `stream_handle` - The handle for the `stream` on which bytes can be sent/received.
    /// * `signer` - An optional signer for requests, needed for Updates with Sig0, otherwise not needed
    pub fn with_timeout(
        stream: F,
        stream_handle: Box<dyn DnsStreamHandle>,
        timeout_duration: Duration,
        signer: Option<Arc<Signer>>,
    ) -> (Self, BasicClientHandle<DnsMultiplexerSerialResponse>) {
        let mp = DnsMultiplexer::with_timeout(stream, stream_handle, timeout_duration, signer);
        Self::connect(mp)
    }
}

impl<F, S, R> ClientFuture<F, S, R>
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender<DnsResponseFuture = R>,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    /// Returns a future, which itself wraps a future which is awaiting connection.
    ///
    /// The connect_future should be lazy.
    ///
    /// # Returns
    ///
    /// This returns a tuple of Self and a handle to send dns messages. Self is a
    ///  background task, it must be run on an executor before handle is used.
    pub fn connect(connect_future: F) -> (Self, BasicClientHandle<R>) {
        let (exchange, handle) = DnsExchange::connect(connect_future);

        (
            Self {
                inner: InnerClientFuture::DnsExchangeConnect(exchange),
            },
            BasicClientHandle {
                message_sender: BufDnsRequestStreamHandle::new(handle),
            },
        )
    }
}

impl<SenderFuture, Sender, Response> Future for ClientFuture<SenderFuture, Sender, Response>
where
    SenderFuture: Future<Output = Result<Sender, ProtoError>> + Send + Unpin,
    Sender: DnsRequestSender<DnsResponseFuture = Response>,
    Response: Future<Output = Result<DnsResponse, ProtoError>> + Send + Unpin,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.inner
            .poll_unpin(cx)
            .map_err(|e| warn!("poll errored in background ClientFuture: {}", e))
            .map(|_: Result<(), ()>| ())
    }
}

enum InnerClientFuture<SenderFuture, Sender, Response>
where
    SenderFuture: Future<Output = Result<Sender, ProtoError>> + 'static + Send + Unpin,
    Sender: DnsRequestSender<DnsResponseFuture = Response>,
    Response: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    DnsExchangeConnect(DnsExchangeConnect<SenderFuture, Sender, Response>),
    DnsExchange(DnsExchange<Sender, Response>),
}

impl<SenderFuture, Sender, Response> Future for InnerClientFuture<SenderFuture, Sender, Response>
where
    SenderFuture: Future<Output = Result<Sender, ProtoError>> + Send + Unpin,
    Sender: DnsRequestSender<DnsResponseFuture = Response>,
    Response: Future<Output = Result<DnsResponse, ProtoError>> + Send + Unpin,
{
    type Output = Result<(), ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            // we're either awaiting the connection, or we're always returning the exchange's result
            let next = match *self {
                InnerClientFuture::DnsExchangeConnect(ref mut connect) => ready!(connect.poll_unpin(cx))?,
                InnerClientFuture::DnsExchange(ref mut exchange) => return exchange.poll_unpin(cx),
            };

            // asign the next and final state
            *self = InnerClientFuture::DnsExchange(next);
        }
    }
}

/// Root ClientHandle implementation returned by ClientFuture
///
/// This can be used directly to perform queries. See `trust_dns::client::SecureClientHandle` for
///  a DNSSEc chain validator.
pub struct BasicClientHandle<Resp>
where
    Resp: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send,
{
    message_sender: BufDnsRequestStreamHandle<Resp>,
}

impl<Resp> DnsHandle for BasicClientHandle<Resp>
where
    Resp: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    type Response = OneshotDnsResponseReceiver<Resp>;

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&mut self, request: R) -> Self::Response {
        self.message_sender.send(request)
    }
}

impl<Resp> Clone for BasicClientHandle<Resp>
where
    Resp: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send,
{
    fn clone(&self) -> Self {
        Self {
            message_sender: self.message_sender.clone(),
        }
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
    ///   are beneficial in that they reduce load on the master servers, but
    ///   that benefit comes at the cost of long intervals of incoherence among
    ///   authority servers whenever the zone is updated.
    ///
    ///   1.2. The DNS NOTIFY transaction allows master servers to inform slave
    ///   servers when the zone has changed -- an interrupt as opposed to poll
    ///   model -- which it is hoped will reduce propagation delay while not
    ///   unduly increasing the masters' load.  This specification only allows
    ///   slaves to be notified of SOA RR changes, but the architecture of
    ///   NOTIFY is intended to be extensible to other RR types.
    ///
    ///   1.3. This document intentionally gives more definition to the roles
    ///   of "Master," "Slave" and "Stealth" servers, their enumeration in NS
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
    ///   slave receiving such a hint is free to treat equivilence of this
    ///   answer section with its local data as a "no further work needs to be
    ///   done" indication.  If ANCOUNT=0, or ANCOUNT>0 and the answer section
    ///   differs from the slave's local data, then the slave should query its
    ///   known masters to retrieve the new data.
    /// ```
    ///
    /// Client's should be ready to handle, or be aware of, a server response of NOTIMP:
    ///
    /// ```text
    ///   3.12. If a NOTIFY request is received by a slave who does not
    ///   implement the NOTIFY opcode, it will respond with a NOTIMP
    ///   (unimplemented feature error) message.  A master server who receives
    ///   such a NOTIMP should consider the NOTIFY transaction complete for
    ///   that slave.
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
        message.set_id(id)
           // 3.3. NOTIFY is similar to QUERY in that it has a request message with
           // the header QR flag "clear" and a response message with QR "set".  The
           // response message contains no useful information, but its reception by
           // the master is an indication that the slave has received the NOTIFY
           // and that the master can remove the slave from any retry queue for
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
            .set_name(name.clone())
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
    ///    class.  Any duplicate RRs will be silently ignored by the primary
    ///    master.
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
    ///    class.  Any duplicate RRs will be silently ignored by the primary
    ///    master.
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
    ///   specified as zero (0) and will otherwise be ignored by the primary
    ///   master.  CLASS must be specified as NONE to distinguish this from an
    ///   RR addition.  If no such RRs exist, then this Update RR will be
    ///   silently ignored by the primary master.
    ///
    ///  2.5.1 - Add To An RRset
    ///
    ///   RRs are added to the Update Section whose NAME, TYPE, TTL, RDLENGTH
    ///   and RDATA are those being added, and CLASS is the same as the zone
    ///   class.  Any duplicate RRs will be silently ignored by the primary
    ///   master.
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
    ///   specified as zero (0) and will otherwise be ignored by the primary
    ///   master.  CLASS must be specified as NONE to distinguish this from an
    ///   RR addition.  If no such RRs exist, then this Update RR will be
    ///   silently ignored by the primary master.
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
    ///   otherwise not used by the primary master.  CLASS must be specified as
    ///   ANY.  RDLENGTH must be zero (0) and RDATA must therefore be empty.
    ///   If no such RRset exists, then this Update RR will be silently ignored
    ///   by the primary master.
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
    ///   be specified as zero (0) and is otherwise not used by the primary
    ///   master.  CLASS must be specified as ANY.  RDLENGTH must be zero (0)
    ///   and RDATA must therefore be empty.  If no such RRsets exist, then
    ///   this Update RR will be silently ignored by the primary master.
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
