// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashMap;
use std::io;

use chrono::UTC;
use futures;
use futures::{Async, Complete, Future, Poll, task};
use futures::IntoFuture;
use futures::stream::{Peekable, Fuse as StreamFuse, Stream};
use futures::task::park;
use rand::Rng;
use rand;
use tokio_core::reactor::Handle;
use tokio_core::channel::{channel, Sender, Receiver};

use ::error::*;
use ::rr::{domain, DNSClass, RData, Record, RecordType};
use ::rr::dnssec::Signer;
use ::rr::rdata::NULL;
use ::op::{Message, MessageType, OpCode, Query, UpdateMessage};

const QOS_MAX_RECEIVE_MSGS: usize = 100; // max number of messages to receive from the UDP socket

type StreamHandle = Sender<Vec<u8>>;

#[must_use = "futures do nothing unless polled"]
pub struct ClientFuture<S: Stream<Item=Vec<u8>, Error=io::Error>> {
  stream: S,
  stream_handle: StreamHandle,
  new_receiver: Peekable<StreamFuse<Receiver<(Message, Complete<ClientResult<Message>>)>>>,
  active_requests: HashMap<u16, Complete<ClientResult<Message>>>,
  // TODO: Maybe make a typed version of ClientFuture for Updates?
  signer: Option<Signer>,
}

impl<S: Stream<Item=Vec<u8>, Error=io::Error> + 'static> ClientFuture<S> {
  pub fn new(stream: Box<Future<Item=S, Error=io::Error>>,
         stream_handle: StreamHandle,
         loop_handle: Handle,
         signer: Option<Signer>) -> BasicClientHandle {
    let (sender, rx) = channel(&loop_handle).expect("could not get channel!");

    loop_handle.spawn(
      stream.map(move |stream| {
        ClientFuture{
          stream: stream,
          stream_handle: stream_handle,
          new_receiver: rx.fuse().peekable(),
          active_requests: HashMap::new(),
          signer: signer,
        }
      }).flatten()
      .map_err(|e| {
         error!("error in Client: {}", e);
      })
    );

    BasicClientHandle { message_sender: sender }
  }

  /// loop over active_requests and remove cancelled requests
  ///  this should free up space if we already had 4096 active requests
  fn drop_cancelled(&mut self) {
    // TODO: should we have a timeout here? or always expect the caller to do this?
    let mut canceled = Vec::new();
    for (&id, req) in self.active_requests.iter_mut() {
      if let Ok(Async::Ready(())) = req.poll_cancel() {
        canceled.push(id);
      }
    }

    // drop all the canceled requests
    for id in canceled {
      self.active_requests.remove(&id);
    }
  }

  /// creates random query_id, validates against all active queries
  fn next_random_query_id(&self) -> Async<u16> {
    let mut rand = rand::thread_rng();

    for _ in 0..100 {
      let id = rand.gen_range(0_u16, u16::max_value());

      if !self.active_requests.contains_key(&id) {
        return Async::Ready(id)
      }
    }

    warn!("could not get next random query id, delaying");
    park().unpark();
    Async::NotReady
  }
}

impl<S: Stream<Item=Vec<u8>, Error=io::Error> + 'static> Future for ClientFuture<S> {
  type Item = ();
  type Error = ClientError;

  fn poll(&mut self) -> Poll<(), Self::Error> {
    self.drop_cancelled();

    // loop over new_receiver for all outbound requests
    loop {
      // get next query_id
      // FIXME: remove try! attempt to receive more messages below and clear
      //  completes. i.e. is it a valid case where the receiver has been closed
      //  but completes are still awaiting responses?
      let query_id: Option<u16> = match try!(self.new_receiver.peek()) {
        Async::Ready(Some(_)) => {
          debug!("got message from receiver");

          // we have a new message to send
          match self.next_random_query_id() {
            Async::Ready(id) => Some(id),
            Async::NotReady => break,
          }
        },
        _ => None,
      };

      // finally pop the reciever
      match try!(self.new_receiver.poll()) {
        Async::Ready(Some((mut message, complete))) => {
          // if there was a message, and the above succesion was succesful,
          //  register the new message, if not do not register, and set the complete to error.
          // getting a random query id, this mitigates potential cache poisoning.
          // FIXME: for SIG0 we can't change the message id after signing.
          let query_id = query_id.expect("query_id should have been set above");
          message.id(query_id);

          // update messages need to be signed.
          if let OpCode::Update = message.get_op_code() {
            if let Some(ref signer) = self.signer {
              // TODO: it's too bad this happens here...
              if let Err(e) = message.sign(signer, UTC::now().timestamp() as u32) {
                warn!("could not sign message: {}", e);
                complete.complete(Err(e.into()));
                continue // to the next message...
              }
            }
          }

          // send the message
          match message.to_vec() {
            Ok(buffer) => {
              debug!("sending message id: {}", query_id);
              try!(self.stream_handle.send(buffer));
              // add to the map -after- the client send b/c we don't want to put it in the map if
              //  we ended up returning from the send.
              self.active_requests.insert(message.get_id(), complete);
            },
            Err(e) => {
              debug!("error message id: {} error: {}", query_id, e);
              // complete with the error, don't add to the map of active requests
              complete.complete(Err(e.into()));
            },
          }
        },
        Async::Ready(None) | Async::NotReady => break,
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
              match self.active_requests.remove(&message.get_id()) {
                Some(complete) => complete.complete(Ok(message)),
                None => debug!("unexpected request_id: {}", message.get_id()),
              }
            },
            // TODO: return src address for diagnostics
            Err(e) => debug!("error decoding message: {}", e),
          }

        },
        Async::Ready(None) | Async::NotReady => break,
      }
    }

    // Clean shutdown happens when all pending requests are done and the
    // incoming channel has been closed (e.g. you'll never receive another
    // request).
    let done = if let Async::Ready(None) = try!(self.new_receiver.peek()) { true } else { false };
    if self.active_requests.is_empty() && done {
      return Ok(().into()); // we are done
    }

    // If still active, then if the qos (for _ in 0..100 loop) limit
    // was hit then "yield". This'll make sure that the future is
    // woken up immediately on the next turn of the event loop.
    if messages_received == QOS_MAX_RECEIVE_MSGS {
      task::park().unpark();
    }

    // Finally, return not ready to keep the 'driver task' alive.
    return Ok(Async::NotReady)
  }
}

#[derive(Clone)]
#[must_use = "futures do nothing unless polled"]
pub struct BasicClientHandle {
  message_sender: Sender<(Message, Complete<ClientResult<Message>>)>,
}

impl ClientHandle for BasicClientHandle {
  fn send(&self, message: Message) -> Box<Future<Item=Message, Error=ClientError>> {
    debug!("sending message");
    let (complete, oneshot) = futures::oneshot();

    let oneshot = match self.message_sender.send((message, complete)) {
      Ok(()) => oneshot,
      Err(e) => {
        let (complete, oneshot) = futures::oneshot();
        complete.complete(Err(e.into()));
        oneshot
      }
    };

    // conver the oneshot into a Box of a Future message and error.
    Box::new(oneshot.map_err(|c| ClientError::from(c)).map(|result| result.into_future()).flatten())
  }
}

pub trait ClientHandle {
  /// Send a message via the channel in the client
  ///
  /// # Arguments
  ///
  /// * `message` - the fully constructed Message to send, note that most implementations of
  ///               will most likely be required to rewrite the QueryId, do no rely on that as
  ///               being stable.
  fn send(&self, message: Message) -> Box<Future<Item=Message, Error=ClientError>>;

  /// A *classic* DNS query, i.e. does not perform and DNSSec operations
  ///
  /// *Note* As of now, this will not recurse on PTR or CNAME record responses, that is up to
  ///        the caller.
  ///
  /// # Arguments
  ///
  /// * `name` - the label to lookup
  /// * `query_class` - most likely this should always be DNSClass::IN
  /// * `query_type` - record type to lookup
  ///
  /// TODO: The result of this should be generified to allow for Caches and SecureBasicClientHandle
  ///  to all share a trait
  fn query(&self, name: domain::Name, query_class: DNSClass, query_type: RecordType)
    -> Box<Future<Item=Message, Error=ClientError>> {
    debug!("querying: {} {:?}", name, query_type);

    // build the message
    let mut message: Message = Message::new();
    let id: u16 = rand::random();
    // TODO make recursion a parameter
    message.id(id).message_type(MessageType::Query).op_code(OpCode::Query).recursion_desired(true);

    // Extended dns
    {
      let edns = message.get_edns_mut();
      edns.set_max_payload(1500);
      edns.set_version(0);
    }

    // add the query
    let mut query: Query = Query::new();
    query.name(name.clone()).query_class(query_class).query_type(query_type);
    message.add_query(query);

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
  /// * `record` - the name of the record to create
  /// * `zone_origin` - the zone name to update, i.e. SOA name
  ///
  /// The update must go to a zone authority (i.e. the server used in the ClientConnection)
  fn create(&self,
            record: Record,
            zone_origin: domain::Name)
            -> Box<Future<Item=Message, Error=ClientError>> {
    assert!(zone_origin.zone_of(record.get_name()));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.name(zone_origin).query_class(record.get_dns_class()).query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message.id(rand::random()).message_type(MessageType::Query).op_code(OpCode::Update).recursion_desired(false);
    message.add_zone(zone);

    let mut prerequisite = Record::with(record.get_name().clone(), record.get_rr_type(), 0);
    prerequisite.dns_class(DNSClass::NONE);
    message.add_pre_requisite(prerequisite);
    message.add_update(record);

    // Extended dns
    {
      let edns = message.get_edns_mut();
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
  /// * `record` - the record to append to an RRSet
  /// * `zone_origin` - the zone name to update, i.e. SOA name
  /// * `must_exist` - if true, the request will fail if the record does not exist
  ///
  /// The update must go to a zone authority (i.e. the server used in the ClientConnection). If
  /// the rrset does not exist and must_exist is false, then the RRSet will be created.
  fn append(&self,
            record: Record,
            zone_origin: domain::Name,
            must_exist: bool)
            -> Box<Future<Item=Message, Error=ClientError>> {
    assert!(zone_origin.zone_of(record.get_name()));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.name(zone_origin).query_class(record.get_dns_class()).query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message.id(rand::random()).message_type(MessageType::Query).op_code(OpCode::Update).recursion_desired(false);
    message.add_zone(zone);

    if must_exist {
      let mut prerequisite = Record::with(record.get_name().clone(), record.get_rr_type(), 0);
      prerequisite.dns_class(DNSClass::ANY);
      message.add_pre_requisite(prerequisite);
    }

    message.add_update(record);

    // Extended dns
    {
      let edns = message.get_edns_mut();
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
  /// * `current` - the current current which must exist for the swap to complete
  /// * `new` - the new record with which to replace the current record
  /// * `zone_origin` - the zone name to update, i.e. SOA name
  ///
  /// The update must go to a zone authority (i.e. the server used in the ClientConnection).
  fn compare_and_swap(&self,
                      current: Record,
                      new: Record,
                      zone_origin: domain::Name)
                      -> Box<Future<Item=Message, Error=ClientError>> {
    assert!(zone_origin.zone_of(current.get_name()));
    assert!(zone_origin.zone_of(new.get_name()));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.name(zone_origin).query_class(new.get_dns_class()).query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message.id(rand::random()).message_type(MessageType::Query).op_code(OpCode::Update).recursion_desired(false);
    message.add_zone(zone);

    // make sure the record is what is expected
    let mut prerequisite = current.clone();
    prerequisite.ttl(0);
    message.add_pre_requisite(prerequisite);

    // add the delete for the old record
    let mut delete = current;
    // the class must be none for delete
    delete.dns_class(DNSClass::NONE);
    // the TTL shoudl be 0
    delete.ttl(0);
    message.add_update(delete);

    // insert the new record...
    message.add_update(new);

    // Extended dns
    {
      let edns = message.get_edns_mut();
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
  /// * `record` - the record to delete from a RRSet, the name, type and rdata must match the
  ///              record to delete
  /// * `zone_origin` - the zone name to update, i.e. SOA name
  /// * `signer` - the signer, with private key, to use to sign the request
  ///
  /// The update must go to a zone authority (i.e. the server used in the ClientConnection). If
  /// the rrset does not exist and must_exist is false, then the RRSet will be deleted.
  fn delete_by_rdata(&self,
                     mut record: Record,
                     zone_origin: domain::Name)
                     -> Box<Future<Item=Message, Error=ClientError>> {
    assert!(zone_origin.zone_of(record.get_name()));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.name(zone_origin).query_class(record.get_dns_class()).query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message.id(rand::random()).message_type(MessageType::Query).op_code(OpCode::Update).recursion_desired(false);
    message.add_zone(zone);

    // the class must be none for delete
    record.dns_class(DNSClass::NONE);
    // the TTL shoudl be 0
    record.ttl(0);
    message.add_update(record);

    // Extended dns
    {
      let edns = message.get_edns_mut();
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
  /// * `record` - the record to delete from a RRSet, the name, and type must match the
  ///              record set to delete
  /// * `zone_origin` - the zone name to update, i.e. SOA name
  /// * `signer` - the signer, with private key, to use to sign the request
  ///
  /// The update must go to a zone authority (i.e. the server used in the ClientConnection). If
  /// the rrset does not exist and must_exist is false, then the RRSet will be deleted.
  fn delete_rrset(&self,
                  mut record: Record,
                  zone_origin: domain::Name)
                  -> Box<Future<Item=Message, Error=ClientError>> {
    assert!(zone_origin.zone_of(record.get_name()));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.name(zone_origin).query_class(record.get_dns_class()).query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message.id(rand::random()).message_type(MessageType::Query).op_code(OpCode::Update).recursion_desired(false);
    message.add_zone(zone);

    // the class must be none for an rrset delete
    record.dns_class(DNSClass::ANY);
    // the TTL shoudl be 0
    record.ttl(0);
    // the rdata must be null to delete all rrsets
    record.rdata(RData::NULL(NULL::new()));
    message.add_update(record);

    // Extended dns
    {
      let edns = message.get_edns_mut();
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
  /// * `signer` - the signer, with private key, to use to sign the request
  ///
  /// The update must go to a zone authority (i.e. the server used in the ClientConnection). This
  /// operation attempts to delete all resource record sets the the specified name reguardless of
  /// the record type.
  fn delete_all(&self,
                name_of_records: domain::Name,
                zone_origin: domain::Name,
                dns_class: DNSClass)
                -> Box<Future<Item=Message, Error=ClientError>> {
    assert!(zone_origin.zone_of(&name_of_records));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.name(zone_origin).query_class(dns_class).query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message.id(rand::random()).message_type(MessageType::Query).op_code(OpCode::Update).recursion_desired(false);
    message.add_zone(zone);

    // the TTL shoudl be 0
    // the rdata must be null to delete all rrsets
    // the record type must be any
    let mut record = Record::with(name_of_records, RecordType::ANY, 0);

    // the class must be none for an rrset delete
    record.dns_class(DNSClass::ANY);

    message.add_update(record);

    // Extended dns
    {
      let edns = message.get_edns_mut();
      edns.set_max_payload(1500);
      edns.set_version(0);
    }

    self.send(message)
  }
}

#[cfg(test)]
pub mod test {
  use std::fmt;
  use std::io;
  use std::net::*;

  use chrono::Duration;
  use futures::{Async, Future, finished, Poll};
  use futures::stream::{Fuse, Stream};
  use futures::task::park;
  use openssl::crypto::rsa::RSA;
  use tokio_core::reactor::{Core, Handle};
  use tokio_core::channel::{channel, Receiver};

  use super::{ClientFuture, BasicClientHandle, ClientHandle, StreamHandle};
  use ::op::{Message, ResponseCode};
  use ::authority::Catalog;
  use ::authority::authority_tests::{create_example};
  use ::rr::domain;
  use ::rr::{DNSClass, RData, Record, RecordType};
  use ::rr::dnssec::{Algorithm, Signer};
  use ::serialize::binary::{BinDecoder, BinEncoder, BinSerializable};
  use ::udp::UdpClientStream;
  use ::tcp::TcpClientStream;

  pub struct TestClientStream {
    catalog: Catalog,
    outbound_messages: Fuse<Receiver<Vec<u8>>>,
  }

  impl TestClientStream {
    pub fn new(catalog: Catalog, loop_handle: Handle) -> (Box<Future<Item=Self, Error=io::Error>>, StreamHandle) {
      let (message_sender, outbound_messages) = channel(&loop_handle).expect("somethings wrong with the event loop");

      let stream: Box<Future<Item=TestClientStream, Error=io::Error>> = Box::new(finished(
        TestClientStream { catalog: catalog, outbound_messages: outbound_messages.fuse() }
      ));

      (stream, message_sender)
    }
  }

  impl Stream for TestClientStream {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
      match try!(self.outbound_messages.poll()) {
        // already handled above, here to make sure the poll() pops the next message
        Async::Ready(Some(bytes)) => {
          let mut decoder = BinDecoder::new(&bytes);

          let message = Message::read(&mut decoder).expect("could not decode message");
          let response = self.catalog.handle_request(&message);

          let mut buf = Vec::with_capacity(512);
          {
            let mut encoder = BinEncoder::new(&mut buf);
            response.emit(&mut encoder).expect("could not encode");
          }

          Ok(Async::Ready(Some(buf)))
        },
        // now we get to drop through to the receives...
        // TODO: should we also return None if there are no more messages to send?
        _ => {
          park().unpark();
          Ok(Async::NotReady)
        },
      }
    }
  }

  impl fmt::Debug for TestClientStream {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
      write!(f, "TestClientStream catalog")
    }
  }

  #[test]
  fn test_query_nonet() {
    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.get_origin().clone(), authority);

    let mut io_loop = Core::new().unwrap();
    let (stream, sender) = TestClientStream::new(catalog, io_loop.handle());
    let client = ClientFuture::new(stream, sender, io_loop.handle(), None);

    io_loop.run(test_query(&client)).unwrap();
    io_loop.run(test_query(&client)).unwrap();
  }

  #[test]
  #[ignore]
  fn test_query_udp_ipv4() {
    use std::net::{SocketAddr, ToSocketAddrs};
    use tokio_core::reactor::Core;

    let mut io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = UdpClientStream::new(addr, io_loop.handle());
    let client = ClientFuture::new(stream, sender, io_loop.handle(), None);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.run(test_query(&client)).unwrap();
    io_loop.run(test_query(&client)).unwrap();
  }

  #[test]
  #[ignore]
  fn test_query_udp_ipv6() {
    use std::net::{SocketAddr, ToSocketAddrs};
    use tokio_core::reactor::Core;

    let mut io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("2001:4860:4860::8888",53).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = UdpClientStream::new(addr, io_loop.handle());
    let client = ClientFuture::new(stream, sender, io_loop.handle(), None);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.run(test_query(&client)).unwrap();
    io_loop.run(test_query(&client)).unwrap();
  }

  #[test]
  #[ignore]
  fn test_query_tcp_ipv4() {
    use std::net::{SocketAddr, ToSocketAddrs};
    use tokio_core::reactor::Core;

    let mut io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
    let client = ClientFuture::new(stream, sender, io_loop.handle(), None);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.run(test_query(&client)).unwrap();
    io_loop.run(test_query(&client)).unwrap();
  }

  #[test]
  #[ignore]
  fn test_query_tcp_ipv6() {
    use std::net::{SocketAddr, ToSocketAddrs};
    use tokio_core::reactor::Core;

    let mut io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("2001:4860:4860::8888",53).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
    let client = ClientFuture::new(stream, sender, io_loop.handle(), None);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.run(test_query(&client)).unwrap();
    io_loop.run(test_query(&client)).unwrap();
  }

  #[cfg(test)]
  fn test_query(client: &BasicClientHandle) -> Box<Future<Item=(), Error=()>> {
    use std::net::Ipv4Addr;
    use std::cmp::Ordering;
    use ::rr::RData;

    use log::LogLevel;
    use ::logger::TrustDnsLogger;

    TrustDnsLogger::enable_logging(LogLevel::Debug);

    let name = domain::Name::with_labels(vec!["WWW".to_string(), "example".to_string(), "com".to_string()]);

    Box::new(client.query(name.clone(), DNSClass::IN, RecordType::A)
          .map(move |response| {
            println!("response records: {:?}", response);
            assert_eq!(response.get_queries().first().expect("expected query").get_name().cmp_with_case(&name, false), Ordering::Equal);

            let record = &response.get_answers()[0];
            assert_eq!(record.get_name(), &name);
            assert_eq!(record.get_rr_type(), RecordType::A);
            assert_eq!(record.get_dns_class(), DNSClass::IN);

            if let &RData::A(ref address) = record.get_rdata() {
              assert_eq!(address, &Ipv4Addr::new(93,184,216,34))
            } else {
              assert!(false);
            }
          })
          .map_err(|e| {
            assert!(false, "query failed: {}", e);
          })
        )
  }

  // update tests
  //

  /// create a client with a sig0 section
  fn create_sig0_ready_client(io_loop: &Core) -> (BasicClientHandle, domain::Name) {
    use chrono::Duration;
    use ::rr::rdata::DNSKEY;

    let mut authority = create_example();
    authority.set_allow_update(true);
    let origin = authority.get_origin().clone();

    let rsa = RSA::generate(512).unwrap();

    let signer = Signer::new(Algorithm::RSASHA256,
                             rsa,
                             domain::Name::with_labels(vec!["trusted".to_string(), "example".to_string(), "com".to_string()]),
                             Duration::max_value());

    // insert the KEY for the trusted.example.com
    let mut auth_key = Record::with(domain::Name::with_labels(vec!["trusted".to_string(), "example".to_string(), "com".to_string()]),
                                  RecordType::KEY,
                                  Duration::minutes(5).num_seconds() as u32);
    auth_key.rdata(RData::KEY(DNSKEY::new(false, false, false, signer.get_algorithm(), signer.get_public_key())));
    authority.upsert(auth_key, 0);

    // setup the catalog
    let mut catalog = Catalog::new();
    catalog.upsert(authority.get_origin().clone(), authority);

    let (stream, sender) = TestClientStream::new(catalog, io_loop.handle());
    let client = ClientFuture::new(stream, sender, io_loop.handle(), Some(signer));

    (client, origin)
  }

  #[test]
  fn test_create() {
    let mut io_loop = Core::new().unwrap();
    let (client, origin) = create_sig0_ready_client(&io_loop);

    // create a record
    let mut record = Record::with(domain::Name::with_labels(vec!["new".to_string(), "example".to_string(), "com".to_string()]),
                                  RecordType::A,
                                  Duration::minutes(5).num_seconds() as u32);
    record.rdata(RData::A(Ipv4Addr::new(100,10,100,10)));


    let result = io_loop.run(client.create(record.clone(), origin.clone())).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);
    let result = io_loop.run(client.query(record.get_name().clone(), record.get_dns_class(), record.get_rr_type())).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);
    assert_eq!(result.get_answers().len(), 1);
    assert_eq!(result.get_answers()[0], record);

    // trying to create again should error
    // TODO: it would be cool to make this
    let result = io_loop.run(client.create(record.clone(), origin.clone())).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::YXRRSet);

    // will fail if already set and not the same value.
    let mut record = record.clone();
    record.rdata(RData::A(Ipv4Addr::new(101,11,101,11)));

    let result = io_loop.run(client.create(record.clone(), origin.clone())).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::YXRRSet);
  }

  #[test]
  fn test_append() {
    let mut io_loop = Core::new().unwrap();
    let (client, origin) = create_sig0_ready_client(&io_loop);

    // append a record
    let mut record = Record::with(domain::Name::with_labels(vec!["new".to_string(), "example".to_string(), "com".to_string()]),
                                  RecordType::A,
                                  Duration::minutes(5).num_seconds() as u32);
    record.rdata(RData::A(Ipv4Addr::new(100,10,100,10)));

    // first check the must_exist option
    let result = io_loop.run(client.append(record.clone(), origin.clone(), true)).expect("append failed");
    assert_eq!(result.get_response_code(), ResponseCode::NXRRSet);

    // next append to a non-existent RRset
    let result = io_loop.run(client.append(record.clone(), origin.clone(), false)).expect("append failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop.run(client.query(record.get_name().clone(), record.get_dns_class(), record.get_rr_type())).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);
    assert_eq!(result.get_answers().len(), 1);
    assert_eq!(result.get_answers()[0], record);

    // will fail if already set and not the same value.
    let mut record = record.clone();
    record.rdata(RData::A(Ipv4Addr::new(101,11,101,11)));

    let result = io_loop.run(client.append(record.clone(), origin.clone(), true)).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let result = io_loop.run(client.query(record.get_name().clone(), record.get_dns_class(), record.get_rr_type())).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);
    assert_eq!(result.get_answers().len(), 2);

    assert!(result.get_answers().iter().any(|rr| if let &RData::A(ref ip) = rr.get_rdata() { *ip ==  Ipv4Addr::new(100,10,100,10) } else { false }));
    assert!(result.get_answers().iter().any(|rr| if let &RData::A(ref ip) = rr.get_rdata() { *ip ==  Ipv4Addr::new(101,11,101,11) } else { false }));

    // show that appending the same thing again is ok, but doesn't add any records
    let result = io_loop.run(client.append(record.clone(), origin.clone(), true)).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let result = io_loop.run(client.query(record.get_name().clone(), record.get_dns_class(), record.get_rr_type())).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);
    assert_eq!(result.get_answers().len(), 2);
  }

  #[test]
  fn test_compare_and_swap() {
    let mut io_loop = Core::new().unwrap();
    let (client, origin) = create_sig0_ready_client(&io_loop);

    // create a record
    let mut record = Record::with(domain::Name::with_labels(vec!["new".to_string(), "example".to_string(), "com".to_string()]),
                                  RecordType::A,
                                  Duration::minutes(5).num_seconds() as u32);
    record.rdata(RData::A(Ipv4Addr::new(100,10,100,10)));

    let result = io_loop.run(client.create(record.clone(), origin.clone())).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let current = record;
    let mut new = current.clone();
    new.rdata(RData::A(Ipv4Addr::new(101,11,101,11)));

    let result = io_loop.run(client.compare_and_swap(current.clone(), new.clone(), origin.clone())).expect("compare_and_swap failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let result = io_loop.run(client.query(new.get_name().clone(), new.get_dns_class(), new.get_rr_type())).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);
    assert_eq!(result.get_answers().len(), 1);
    assert!(result.get_answers().iter().any(|rr| if let &RData::A(ref ip) = rr.get_rdata() { *ip ==  Ipv4Addr::new(101,11,101,11) } else { false }));

    // check the it fails if tried again.
    let mut new = new;
    new.rdata(RData::A(Ipv4Addr::new(102,12,102,12)));

    let result = io_loop.run(client.compare_and_swap(current, new.clone(), origin.clone())).expect("compare_and_swap failed");
    assert_eq!(result.get_response_code(), ResponseCode::NXRRSet);

    let result = io_loop.run(client.query(new.get_name().clone(), new.get_dns_class(), new.get_rr_type())).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);
    assert_eq!(result.get_answers().len(), 1);
    assert!(result.get_answers().iter().any(|rr| if let &RData::A(ref ip) = rr.get_rdata() { *ip ==  Ipv4Addr::new(101,11,101,11) } else { false }));
  }

  #[test]
  fn test_delete_by_rdata() {
    let mut io_loop = Core::new().unwrap();
    let (client, origin) = create_sig0_ready_client(&io_loop);

    // append a record
    let mut record = Record::with(domain::Name::with_labels(vec!["new".to_string(), "example".to_string(), "com".to_string()]),
                                  RecordType::A,
                                  Duration::minutes(5).num_seconds() as u32);
    record.rdata(RData::A(Ipv4Addr::new(100,10,100,10)));

    // first check the must_exist option
    let result = io_loop.run(client.delete_by_rdata(record.clone(), origin.clone())).expect("delete failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop.run(client.create(record.clone(), origin.clone())).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let mut record = record.clone();
    record.rdata(RData::A(Ipv4Addr::new(101,11,101,11)));
    let result = io_loop.run(client.append(record.clone(), origin.clone(), true)).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop.run(client.delete_by_rdata(record.clone(), origin.clone())).expect("delete failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let result = io_loop.run(client.query(record.get_name().clone(), record.get_dns_class(), record.get_rr_type())).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);
    assert_eq!(result.get_answers().len(), 1);
    assert!(result.get_answers().iter().any(|rr| if let &RData::A(ref ip) = rr.get_rdata() { *ip ==  Ipv4Addr::new(100,10,100,10) } else { false }));
  }

  #[test]
  fn test_delete_rrset() {
    let mut io_loop = Core::new().unwrap();
    let (client, origin) = create_sig0_ready_client(&io_loop);

    // append a record
    let mut record = Record::with(domain::Name::with_labels(vec!["new".to_string(), "example".to_string(), "com".to_string()]),
                                  RecordType::A,
                                  Duration::minutes(5).num_seconds() as u32);
    record.rdata(RData::A(Ipv4Addr::new(100,10,100,10)));

    // first check the must_exist option
    let result = io_loop.run(client.delete_rrset(record.clone(), origin.clone())).expect("delete failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop.run(client.create(record.clone(), origin.clone())).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let mut record = record.clone();
    record.rdata(RData::A(Ipv4Addr::new(101,11,101,11)));
    let result = io_loop.run(client.append(record.clone(), origin.clone(), true)).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop.run(client.delete_rrset(record.clone(), origin.clone())).expect("delete failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let result = io_loop.run(client.query(record.get_name().clone(), record.get_dns_class(), record.get_rr_type())).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NXDomain);
    assert_eq!(result.get_answers().len(), 0);
  }

  #[test]
  fn test_delete_all() {
    let mut io_loop = Core::new().unwrap();
    let (client, origin) = create_sig0_ready_client(&io_loop);

    // append a record
    let mut record = Record::with(domain::Name::with_labels(vec!["new".to_string(), "example".to_string(), "com".to_string()]),
                                  RecordType::A,
                                  Duration::minutes(5).num_seconds() as u32);
    record.rdata(RData::A(Ipv4Addr::new(100,10,100,10)));

    // first check the must_exist option
    let result = io_loop.run(client.delete_all(record.get_name().clone(), origin.clone(), DNSClass::IN)).expect("delete failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop.run(client.create(record.clone(), origin.clone())).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let mut record = record.clone();
    record.rr_type(RecordType::AAAA);
    record.rdata(RData::AAAA(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)));
    let result = io_loop.run(client.create(record.clone(), origin.clone())).expect("create failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop.run(client.delete_all(record.get_name().clone(), origin.clone(), DNSClass::IN)).expect("delete failed");
    assert_eq!(result.get_response_code(), ResponseCode::NoError);

    let result = io_loop.run(client.query(record.get_name().clone(), record.get_dns_class(), RecordType::A)).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NXDomain);
    assert_eq!(result.get_answers().len(), 0);

    let result = io_loop.run(client.query(record.get_name().clone(), record.get_dns_class(), RecordType::AAAA)).expect("query failed");
    assert_eq!(result.get_response_code(), ResponseCode::NXDomain);
    assert_eq!(result.get_answers().len(), 0);
  }
}
