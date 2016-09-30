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
use futures::{Async, Complete, Future, Oneshot, Poll, task};
use futures::stream::{Peekable, Fuse as StreamFuse, Stream};
use futures::task::park;
use rand::Rng;
use rand;
use tokio_core::reactor::Handle;
use tokio_core::channel::{channel, Sender, Receiver};

use ::error::*;
use ::rr::{domain, DNSClass, Record, RecordType};
use ::rr::dnssec::Signer;
use ::op::{Edns, Message, MessageType, OpCode, Query, UpdateMessage};
use ::udp::{UdpClientStream, UdpClientStreamHandle};
use ::tcp::{TcpClientStream, TcpClientStreamHandle};

const QOS_MAX_RECEIVE_MSGS: usize = 100; // max number of messages to receive from the UDP socket

type StreamHandle = Sender<Vec<u8>>;

pub struct ClientFuture<S: Stream<Item=Vec<u8>, Error=io::Error>> {
  stream: S,
  streamHandle: StreamHandle,
  new_receiver: Peekable<StreamFuse<Receiver<(Message, Complete<ClientResult<Message>>)>>>,
  active_requests: HashMap<u16, Complete<ClientResult<Message>>>,
  // TODO: Maybe make a typed version of ClientFuture for Updates?
  signer: Option<Signer>,
}

impl<S: Stream<Item=Vec<u8>, Error=io::Error> + 'static> ClientFuture<S> {
  fn new(stream: Box<Future<Item=S, Error=io::Error>>,
         streamHandle: StreamHandle,
         loop_handle: Handle,
         signer: Option<Signer>) -> ClientHandle {
    let (sender, rx) = channel(&loop_handle).expect("could not get channel!");

    loop_handle.spawn(
      stream.map(move |stream| {
        ClientFuture{
          stream: stream,
          streamHandle: streamHandle,
          new_receiver: rx.fuse().peekable(),
          active_requests: HashMap::new(),
          signer: signer,
        }
      }).flatten()
      .map_err(|e| {
         error!("error in Client: {}", e);
      })
    );

    ClientHandle { message_sender: sender }
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
              message.sign(signer, UTC::now().timestamp() as u32);
            }
          }

          // send the message
          match message.to_vec() {
            Ok(buffer) => {
              debug!("sending message id: {}", query_id);
              try!(self.streamHandle.send(buffer));
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
struct ClientHandle {
  message_sender: Sender<(Message, Complete<ClientResult<Message>>)>,
}

impl ClientHandle {
  fn send(&self, message: Message) -> io::Result<Oneshot<ClientResult<Message>>> {
    debug!("sending message");
    let (complete, oneshot) = futures::oneshot();
    try!(self.message_sender.send((message, complete)));
    Ok(oneshot)
  }

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
  //  * `dnssec` - request RRSIG records to be returned in query response
  pub fn query(&self, name: &domain::Name, query_class: DNSClass, query_type: RecordType, dnssec: bool)
    -> io::Result<Oneshot<ClientResult<Message>>> {
    debug!("querying: {} {:?}", name, query_type);

    // build the message
    let mut message: Message = Message::new();
    let id: u16 = rand::random();
    // TODO make recursion a parameter
    message.id(id).message_type(MessageType::Query).op_code(OpCode::Query).recursion_desired(true);

    // Extended dns
    let mut edns: Edns = Edns::new();

    if dnssec {
      edns.set_dnssec_ok(true);
      message.authentic_data(true);
      message.checking_disabled(false);
    }

    edns.set_max_payload(1500);
    edns.set_version(0);

    message.set_edns(edns);

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
  /// * `signer` - the signer, with private key, to use to sign the request
  ///
  /// The update must go to a zone authority (i.e. the server used in the ClientConnection)
  pub fn create(&self,
                record: Record,
                zone_origin: domain::Name)
                -> io::Result<Oneshot<ClientResult<Message>>> {
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
    let mut edns: Edns = Edns::new();

    edns.set_max_payload(1500);
    edns.set_version(0);

    message.set_edns(edns);

    // after all other updates to the message, sign it.
    // signed in the to_vec()
    //   message.sign(signer, UTC::now().timestamp() as u32);

    self.send(message)
  }
}

#[cfg(test)]
pub mod test {
  use std::fmt;
  use std::io;

  use futures;
  use futures::{Async, Complete, Future, finished, Oneshot, Poll, task};
  use futures::stream::{Fuse, Stream};
  use futures::task::park;
  use tokio_core::reactor::{Core, Handle};
  use tokio_core::channel::{channel, Sender, Receiver};

  use super::{ClientFuture, ClientHandle, StreamHandle};
  use ::op::Message;
  use ::authority::Catalog;
  use ::authority::authority_tests::{create_example, create_secure_example};
  use ::rr::domain;
  use ::rr::{DNSClass, RecordType};
  use ::serialize::binary::{BinDecoder, BinEncoder, BinSerializable};
  use ::error::*;
  use ::udp::{UdpClientStream, UdpClientStreamHandle};
  use ::tcp::{TcpClientStream, TcpClientStreamHandle};



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
  fn test_query(client: &ClientHandle) -> futures::BoxFuture<(), ()> {
    use std::net::Ipv4Addr;
    use std::cmp::Ordering;
    use ::rr::RData;

    use log::LogLevel;
    use ::logger::TrustDnsLogger;

    TrustDnsLogger::enable_logging(LogLevel::Debug);

    let name = domain::Name::with_labels(vec!["WWW".to_string(), "example".to_string(), "com".to_string()]);

    client.query(&name, DNSClass::IN, RecordType::A, false).expect("error with query")
          .map(move |response| {
            assert!(response.is_ok(), "query failed: {}", response.unwrap_err());

            let response = response.unwrap();

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
          .map_err(|_| {
            assert!(false);
          })
          .boxed()
  }
}
