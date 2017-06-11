// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::{HashMap, HashSet};
use std::io;
use std::time::Duration;

use chrono::UTC;
use futures::{Async, Complete, Future, Poll, task};
use futures::IntoFuture;
use futures::stream::{Peekable, Fuse as StreamFuse, Stream};
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::sync::oneshot;
use rand::Rng;
use rand;
use tokio_core::reactor::{Handle, Timeout};

use error::*;
use op::{Message, MessageType, OpCode, Query, UpdateMessage};
use rr::{domain, DNSClass, IntoRecordSet, RData, Record, RecordType};
use rr::dnssec::Signer;
use rr::rdata::NULL;

const QOS_MAX_RECEIVE_MSGS: usize = 100; // max number of messages to receive from the UDP socket

/// A reference to a Sender of bytes returned from the creation of a UdpClientStream or TcpClientStream
pub type StreamHandle = UnboundedSender<Vec<u8>>;

/// Implementations of Sinks for sending DNS messages
pub trait ClientStreamHandle {
    /// Sends a message to the Handle for delivery to the server.
    fn send(&mut self, buffer: Vec<u8>) -> io::Result<()>;
}

impl ClientStreamHandle for StreamHandle {
    fn send(&mut self, buffer: Vec<u8>) -> io::Result<()> {
        UnboundedSender::send(self, buffer).map_err(|_| {
                                                        io::Error::new(io::ErrorKind::Other,
                                                                       "unknown")
                                                    })
    }
}

/// A DNS Client implemented over futures-rs.
///
/// This Client is generic and capable of wrapping UDP, TCP, and other underlying DNS protocol
///  implementations.
#[must_use = "futures do nothing unless polled"]
pub struct ClientFuture<S: Stream<Item = Vec<u8>, Error = io::Error>> {
    stream: S,
    reactor_handle: Handle,
    timeout_duration: Duration,
    // TODO genericize and remove this Box
    stream_handle: Box<ClientStreamHandle>,
    new_receiver:
        Peekable<StreamFuse<UnboundedReceiver<(Message, Complete<ClientResult<Message>>)>>>,
    active_requests: HashMap<u16, (Complete<ClientResult<Message>>, Timeout)>,
    // TODO: Maybe make a typed version of ClientFuture for Updates?
    signer: Option<Signer>,
}

impl<S: Stream<Item = Vec<u8>, Error = io::Error> + 'static> ClientFuture<S> {
    /// Spawns a new ClientFuture Stream. This uses a default timeout of 5 seconds for all requests.
    ///
    /// # Arguments
    ///
    /// * `stream` - A stream of bytes that can be used to send/receive DNS messages
    ///              (see TcpClientStream or UdpClientStream)
    /// * `loop_handle` - A Handle to the Tokio reactor Core, this is the Core on which the
    ///                   the Stream will be spawned
    /// * `stream_handle` - The handle for the `stream` on which bytes can be sent/received.
    /// * `signer` - An optional signer for requests, needed for Updates with Sig0, otherwise not needed
    pub fn new(stream: Box<Future<Item = S, Error = io::Error>>,
               stream_handle: Box<ClientStreamHandle>,
               loop_handle: Handle,
               signer: Option<Signer>)
               -> BasicClientHandle {
        Self::with_timeout(stream,
                           stream_handle,
                           loop_handle,
                           Duration::from_secs(5),
                           signer)
    }

    /// Spawns a new ClientFuture Stream.
    ///
    /// # Arguments
    ///
    /// * `stream` - A stream of bytes that can be used to send/receive DNS messages
    ///              (see TcpClientStream or UdpClientStream)
    /// * `loop_handle` - A Handle to the Tokio reactor Core, this is the Core on which the
    ///                   the Stream will be spawned
    /// * `timeout_duration` - All requests may fail due to lack of response, this is the time to
    ///                        wait for a response before canceling the request.
    /// * `stream_handle` - The handle for the `stream` on which bytes can be sent/received.
    /// * `signer` - An optional signer for requests, needed for Updates with Sig0, otherwise not needed
    pub fn with_timeout(stream: Box<Future<Item = S, Error = io::Error>>,
                        stream_handle: Box<ClientStreamHandle>,
                        loop_handle: Handle,
                        timeout_duration: Duration,
                        signer: Option<Signer>)
                        -> BasicClientHandle {
        let (sender, rx) = unbounded();

        let loop_handle_clone = loop_handle.clone();
        loop_handle
            .spawn(stream
                       .then(move |res| match res {
                                 Ok(stream) => {
                                     ClientStreamOrError::Future(ClientFuture {
                                                                     stream: stream,
                                                                     reactor_handle:
                                                                         loop_handle_clone,
                                                                     timeout_duration:
                                                                         timeout_duration,
                                                                     stream_handle: stream_handle,
                                                                     new_receiver: rx.fuse()
                                                                         .peekable(),
                                                                     active_requests:
                                                                         HashMap::new(),
                                                                     signer: signer,
                                                                 })
                                 }
                                 Err(stream_error) => {
                                     ClientStreamOrError::Errored(ClientStreamErrored {
                                                                      error: stream_error,
                                                                      new_receiver: rx.fuse()
                                                                          .peekable(),
                                                                  })
                                 }
                             })
                       .map_err(|e: ClientError| {
                                    error!("error in Client: {}", e);
                                }));

        BasicClientHandle { message_sender: sender }
    }

    /// loop over active_requests and remove cancelled requests
    ///  this should free up space if we already had 4096 active requests
    fn drop_cancelled(&mut self) {
        // TODO: should we have a timeout here? or always expect the caller to do this?
        let mut canceled = HashSet::new();
        for (&id, &mut (ref mut req, ref mut timeout)) in self.active_requests.iter_mut() {
            if let Ok(Async::Ready(())) = req.poll_cancel() {
              canceled.insert(id);
            }

            // check for timeouts...
            match timeout.poll() {
                Ok(Async::Ready(_)) => {
                    warn!("request timeout: {}", id);
                    canceled.insert(id);
                }
                Ok(Async::NotReady) => (),
                Err(e) => {
                    error!("unexpected error from timeout: {}", e);
                    canceled.insert(id);
                }
            }
        }

        // drop all the canceled requests
        for id in canceled {
            if let Some((req, _)) = self.active_requests.remove(&id) {
                // TODO, perhaps there is a different reason timeout? but there shouldn't be...
                //  being lazy and always returning timeout in this case (if it was canceled then the
                //  then the otherside isn't really paying attention anyway)

                // complete the request, it's failed...
                req.send(Err(ClientErrorKind::Timeout.into()))
                    .expect("error notifying wait, possible future leak");
            }
        }
    }

    /// creates random query_id, validates against all active queries
    fn next_random_query_id(&self) -> Async<u16> {
        let mut rand = rand::thread_rng();

        for _ in 0..100 {
            let id = rand.gen_range(0_u16, u16::max_value());

            if !self.active_requests.contains_key(&id) {
                return Async::Ready(id);
            }
        }

        warn!("could not get next random query id, delaying");
        task::current().notify();
        Async::NotReady
    }
}

impl<S: Stream<Item = Vec<u8>, Error = io::Error> + 'static> Future for ClientFuture<S> {
    type Item = ();
    type Error = ClientError;

    fn poll(&mut self) -> Poll<(), Self::Error> {
        self.drop_cancelled();

        // loop over new_receiver for all outbound requests
        loop {
            // get next query_id
            let query_id: Option<u16> = match self.new_receiver.peek() {
                Ok(Async::Ready(Some(_))) => {
                    debug!("got message from receiver");

                    // we have a new message to send
                    match self.next_random_query_id() {
                        Async::Ready(id) => Some(id),
                        Async::NotReady => break,
                    }
                }
                Ok(_) => None,
                Err(()) => {
          warn!("receiver was shutdown?");
          break
        }
            };

            // finally pop the reciever
            match self.new_receiver.poll() {
                Ok(Async::Ready(Some((mut message, complete)))) => {
                    // if there was a message, and the above succesion was succesful,
                    //  register the new message, if not do not register, and set the complete to error.
                    // getting a random query id, this mitigates potential cache poisoning.
                    // TODO: for SIG0 we can't change the message id after signing.
                    let query_id = query_id.expect("query_id should have been set above");
                    message.set_id(query_id);

                    // update messages need to be signed.
                    if let OpCode::Update = message.op_code() {
                        if let Some(ref signer) = self.signer {
                            // TODO: it's too bad this happens here...
                            if let Err(e) = message.sign(signer, UTC::now().timestamp() as u32) {
                                warn!("could not sign message: {}", e);
                                complete
                                    .send(Err(e.into()))
                                    .expect("error notifying wait, possible future leak");
                                continue; // to the next message...
                            }
                        }
                    }

                    // store a Timeout for this message before sending
                    let timeout = match Timeout::new(self.timeout_duration, &self.reactor_handle) {
                        Ok(timeout) => timeout,
                        Err(e) => {
                            warn!("could not create timer: {}", e);
                            complete
                                .send(Err(e.into()))
                                .expect("error notifying wait, possible future leak");
                            continue; // to the next message...
                        }
                    };

                    // send the message
                    match message.to_vec() {
                        Ok(buffer) => {
                            debug!("sending message id: {}", query_id);
                            try!(self.stream_handle.send(buffer));
                            // add to the map -after- the client send b/c we don't want to put it in the map if
                            //  we ended up returning from the send.
                            self.active_requests
                                .insert(message.id(), (complete, timeout));
                        }
                        Err(e) => {
                            debug!("error message id: {} error: {}", query_id, e);
                            // complete with the error, don't add to the map of active requests
                            complete
                                .send(Err(e.into()))
                                .expect("error notifying wait, possible future leak");
                        }
                    }
                }
                Ok(_) => break,
                Err(()) => {
          warn!("receiver was shutdown?");
          break
        }
            }
        }

        // Collect all inbound requests, max 100 at a time for QoS
        //   by having a max we will guarantee that the client can't be DOSed in this loop
        // TODO: make the QoS configurable
        let mut messages_received = 0;
        for i in 0..QOS_MAX_RECEIVE_MSGS {
            match try!(self.stream.poll()) {
                Async::Ready(Some(buffer)) => {
                    messages_received = i;

                    //   deserialize or log decode_error
                    match Message::from_vec(&buffer) {
                        Ok(message) => {
                            match self.active_requests.remove(&message.id()) {
                                Some((complete, _)) => {
                                    complete
                                        .send(Ok(message))
                                        .expect("error notifying wait, possible future leak")
                                }
                                None => debug!("unexpected request_id: {}", message.id()),
                            }
                        }
                        // TODO: return src address for diagnostics
                        Err(e) => debug!("error decoding message: {}", e),
                    }

                }
                Async::Ready(None) |
                Async::NotReady => break,
            }
        }

        // Clean shutdown happens when all pending requests are done and the
        // incoming channel has been closed (e.g. you'll never receive another
        // request). try! will early return the error...
        let done = if let Async::Ready(None) = try!(self.new_receiver.peek()) {
            true
        } else {
            false
        };
        if self.active_requests.is_empty() && done {
            return Ok(().into()); // we are done
        }

        // If still active, then if the qos (for _ in 0..100 loop) limit
        // was hit then "yield". This'll make sure that the future is
        // woken up immediately on the next turn of the event loop.
        if messages_received == QOS_MAX_RECEIVE_MSGS {
            task::current().notify();
        }

        // Finally, return not ready to keep the 'driver task' alive.
        return Ok(Async::NotReady);
    }
}

/// Always returns the specified io::Error to the remote Sender
struct ClientStreamErrored {
    error: io::Error,
    new_receiver:
        Peekable<StreamFuse<UnboundedReceiver<(Message, Complete<ClientResult<Message>>)>>>,
}

impl Future for ClientStreamErrored {
    type Item = ();
    type Error = ClientError;

    fn poll(&mut self) -> Poll<(), Self::Error> {
        match self.new_receiver.poll() {
            Ok(Async::Ready(Some((_, complete)))) => {
                complete
                    .send(Err(ClientError::from(&self.error).clone()))
                    .expect("error notifying wait, possible future leak");

                task::current().notify();
                return Ok(Async::NotReady);
            }
            Ok(Async::Ready(None)) => return Ok(Async::Ready(())),            
            _ => return Err(ClientErrorKind::NoError.into()),
        }
    }
}

enum ClientStreamOrError<S: Stream<Item = Vec<u8>, Error = io::Error> + 'static> {
    Future(ClientFuture<S>),
    Errored(ClientStreamErrored),
}

impl<S: Stream<Item = Vec<u8>, Error = io::Error> + 'static> Future for ClientStreamOrError<S> {
    type Item = ();
    type Error = ClientError;

    fn poll(&mut self) -> Poll<(), Self::Error> {
        match *self {
            ClientStreamOrError::Future(ref mut f) => f.poll(),
            ClientStreamOrError::Errored(ref mut e) => e.poll(),
        }
    }
}

/// Root ClientHandle implementaton returned by ClientFuture
///
/// This can be used directly to perform queries. See `trust_dns::client::SecureClientHandle` for
///  a DNSSEc chain validator.
#[derive(Clone)]
#[must_use = "queries can only be sent through a ClientHandle"]
pub struct BasicClientHandle {
    message_sender: UnboundedSender<(Message, Complete<ClientResult<Message>>)>,
}

impl ClientHandle for BasicClientHandle {
    fn send(&mut self, message: Message) -> Box<Future<Item = Message, Error = ClientError>> {
        let (complete, receiver) = oneshot::channel();
        let message_sender: &mut _ = &mut self.message_sender;

        let receiver = match message_sender.send((message, complete)) {
            Ok(()) => receiver,
            Err(e) => {
                let (complete, receiver) = oneshot::channel();
                complete
                    .send(Err(e.into()))
                    .expect("error notifying wait, possible future leak");
                receiver
            }
        };

        // conver the oneshot into a Box of a Future message and error.
        Box::new(receiver
                     .map_err(|c| ClientError::from(c))
                     .map(|result| result.into_future())
                     .flatten())
    }
}

/// A trait for implementing high level functions of DNS.
#[must_use = "queries can only be sent through a ClientHandle"]
pub trait ClientHandle: Clone {
    /// Send a message via the channel in the client
    ///
    /// # Arguments
    ///
    /// * `message` - the fully constructed Message to send, note that most implementations of
    ///               will most likely be required to rewrite the QueryId, do no rely on that as
    ///               being stable.
    fn send(&mut self, message: Message) -> Box<Future<Item = Message, Error = ClientError>>;

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
    fn query(&mut self,
             name: domain::Name,
             query_class: DNSClass,
             query_type: RecordType)
             -> Box<Future<Item = Message, Error = ClientError>> {
        debug!("querying: {} {:?}", name, query_type);

        // build the message
        let mut message: Message = Message::new();
        let id: u16 = rand::random();
        // TODO make recursion a parameter
        message
            .set_id(id)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true);

        // Extended dns
        {
            let edns = message.edns_mut();
            edns.set_max_payload(1500);
            edns.set_version(0);
        }

        // add the query
        let mut query: Query = Query::new();
        query
            .set_name(name.clone())
            .set_query_class(query_class)
            .set_query_type(query_type);
        message.add_query(query);

        self.send(message)
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
    ///   slaves to be notified of SOA RR changes, but the architechture of
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
    ///  implmentation accepts a Record, but the actual data of the record should be ignored by the
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
    fn notify<R>(&mut self,
                 name: domain::Name,
                 query_class: DNSClass,
                 query_type: RecordType,
                 rrset: Option<R>)
                 -> Box<Future<Item = Message, Error = ClientError>>
        where R: IntoRecordSet
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
            edns.set_max_payload(1500);
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
            message.add_answers(rrset.into_record_set());
        }

        self.send(message)
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
    fn create<R>(&mut self,
                 rrset: R,
                 zone_origin: domain::Name)
                 -> Box<Future<Item = Message, Error = ClientError>>
        where R: IntoRecordSet
    {
        // TODO: assert non-empty rrset?
        let rrset = rrset.into_record_set();
        assert!(zone_origin.zone_of(rrset.name()));

        // for updates, the query section is used for the zone
        let mut zone: Query = Query::new();
        zone.set_name(zone_origin)
            .set_query_class(rrset.dns_class())
            .set_query_type(RecordType::SOA);

        // build the message
        let mut message: Message = Message::new();
        message
            .set_id(rand::random())
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Update)
            .set_recursion_desired(false);
        message.add_zone(zone);

        let mut prerequisite = Record::with(rrset.name().clone(), rrset.record_type(), 0);
        prerequisite.set_dns_class(DNSClass::NONE);
        message.add_pre_requisite(prerequisite);
        message.add_updates(rrset);

        // Extended dns
        {
            let edns = message.edns_mut();
            edns.set_max_payload(1500);
            edns.set_version(0);
        }

        self.send(message)
    }

    /// Appends a record to an existing rrset, optionally require the rrset to exis (atomicity
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
    fn append<R>(&mut self,
                 rrset: R,
                 zone_origin: domain::Name,
                 must_exist: bool)
                 -> Box<Future<Item = Message, Error = ClientError>>
        where R: IntoRecordSet
    {
        let rrset = rrset.into_record_set();
        assert!(zone_origin.zone_of(rrset.name()));

        // for updates, the query section is used for the zone
        let mut zone: Query = Query::new();
        zone.set_name(zone_origin)
            .set_query_class(rrset.dns_class())
            .set_query_type(RecordType::SOA);

        // build the message
        let mut message: Message = Message::new();
        message
            .set_id(rand::random())
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Update)
            .set_recursion_desired(false);
        message.add_zone(zone);

        if must_exist {
            let mut prerequisite = Record::with(rrset.name().clone(), rrset.record_type(), 0);
            prerequisite.set_dns_class(DNSClass::ANY);
            message.add_pre_requisite(prerequisite);
        }

        message.add_updates(rrset);

        // Extended dns
        {
            let edns = message.edns_mut();
            edns.set_max_payload(1500);
            edns.set_version(0);
        }

        self.send(message)
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
    /// # Arguements
    ///
    /// * `current` - the current rrset which must exist for the swap to complete
    /// * `new` - the new rrset with which to replace the current rrset
    /// * `zone_origin` - the zone name to update, i.e. SOA name
    ///
    /// The update must go to a zone authority (i.e. the server used in the ClientConnection).
    fn compare_and_swap<C, N>(&mut self,
                              current: C,
                              new: N,
                              zone_origin: domain::Name)
                              -> Box<Future<Item = Message, Error = ClientError>>
        where C: IntoRecordSet,
              N: IntoRecordSet
    {
        let current = current.into_record_set();
        let new = new.into_record_set();

        assert!(zone_origin.zone_of(current.name()));
        assert!(zone_origin.zone_of(new.name()));

        // for updates, the query section is used for the zone
        let mut zone: Query = Query::new();
        zone.set_name(zone_origin)
            .set_query_class(new.dns_class())
            .set_query_type(RecordType::SOA);

        // build the message
        let mut message: Message = Message::new();
        message
            .set_id(rand::random())
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Update)
            .set_recursion_desired(false);
        message.add_zone(zone);

        // make sure the record is what is expected
        let mut prerequisite = current.clone();
        prerequisite.set_ttl(0);
        message.add_pre_requisites(prerequisite);

        // add the delete for the old record
        let mut delete = current;
        // the class must be none for delete
        delete.set_dns_class(DNSClass::NONE);
        // the TTL should be 0
        delete.set_ttl(0);
        message.add_updates(delete);

        // insert the new record...
        message.add_updates(new);

        // Extended dns
        {
            let edns = message.edns_mut();
            edns.set_max_payload(1500);
            edns.set_version(0);
        }

        self.send(message)
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
    fn delete_by_rdata<R>(&mut self,
                          rrset: R,
                          zone_origin: domain::Name)
                          -> Box<Future<Item = Message, Error = ClientError>>
        where R: IntoRecordSet
    {
        let mut rrset = rrset.into_record_set();
        assert!(zone_origin.zone_of(rrset.name()));

        // for updates, the query section is used for the zone
        let mut zone: Query = Query::new();
        zone.set_name(zone_origin)
            .set_query_class(rrset.dns_class())
            .set_query_type(RecordType::SOA);

        // build the message
        let mut message: Message = Message::new();
        message
            .set_id(rand::random())
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Update)
            .set_recursion_desired(false);
        message.add_zone(zone);

        // the class must be none for delete
        rrset.set_dns_class(DNSClass::NONE);
        // the TTL shoudl be 0
        rrset.set_ttl(0);
        message.add_updates(rrset);

        // Extended dns
        {
            let edns = message.edns_mut();
            edns.set_max_payload(1500);
            edns.set_version(0);
        }

        self.send(message)
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
    fn delete_rrset(&mut self,
                    mut record: Record,
                    zone_origin: domain::Name)
                    -> Box<Future<Item = Message, Error = ClientError>> {
        assert!(zone_origin.zone_of(record.name()));

        // for updates, the query section is used for the zone
        let mut zone: Query = Query::new();
        zone.set_name(zone_origin)
            .set_query_class(record.dns_class())
            .set_query_type(RecordType::SOA);

        // build the message
        let mut message: Message = Message::new();
        message
            .set_id(rand::random())
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Update)
            .set_recursion_desired(false);
        message.add_zone(zone);

        // the class must be none for an rrset delete
        record.set_dns_class(DNSClass::ANY);
        // the TTL shoudl be 0
        record.set_ttl(0);
        // the rdata must be null to delete all rrsets
        record.set_rdata(RData::NULL(NULL::new()));
        message.add_update(record);

        // Extended dns
        {
            let edns = message.edns_mut();
            edns.set_max_payload(1500);
            edns.set_version(0);
        }

        self.send(message)
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
    /// operation attempts to delete all resource record sets the the specified name reguardless of
    /// the record type.
    fn delete_all(&mut self,
                  name_of_records: domain::Name,
                  zone_origin: domain::Name,
                  dns_class: DNSClass)
                  -> Box<Future<Item = Message, Error = ClientError>> {
        assert!(zone_origin.zone_of(&name_of_records));

        // for updates, the query section is used for the zone
        let mut zone: Query = Query::new();
        zone.set_name(zone_origin)
            .set_query_class(dns_class)
            .set_query_type(RecordType::SOA);

        // build the message
        let mut message: Message = Message::new();
        message
            .set_id(rand::random())
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Update)
            .set_recursion_desired(false);
        message.add_zone(zone);

        // the TTL shoudl be 0
        // the rdata must be null to delete all rrsets
        // the record type must be any
        let mut record = Record::with(name_of_records, RecordType::ANY, 0);

        // the class must be none for an rrset delete
        record.set_dns_class(DNSClass::ANY);

        message.add_update(record);

        // Extended dns
        {
            let edns = message.edns_mut();
            edns.set_max_payload(1500);
            edns.set_version(0);
        }

        self.send(message)
    }
}
