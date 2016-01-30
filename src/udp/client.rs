/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::net::{SocketAddr, ToSocketAddrs, Ipv4Addr};
use std::io::Cursor;
use std::cell::Cell;

use mio::udp::UdpSocket;
use mio::{Token, EventLoop, Handler, EventSet, PollOpt}; // not * b/c don't want confusion with std::net

use ::error::*;
use ::rr::{DNSClass, RecordType, Record};
use ::rr::domain;
use ::op::{ Message, MessageType, OpCode, Query, Edns, ResponseCode };
use ::serialize::binary::*;

const RESPONSE: Token = Token(0);

pub struct Client<A: ToSocketAddrs + Copy> {
  socket: UdpSocket,
  name_server: A,
  next_id: Cell<u16>,
}

impl Client<(Ipv4Addr,u16)> {
  /// name_server to connect to with default port 53
  pub fn new(name_server: Ipv4Addr) -> ClientResult<Client<(Ipv4Addr,u16)>> {
    Self::with_addr((name_server, 53))
  }
}

impl<A: ToSocketAddrs + Copy> Client<A> {
  pub fn with_addr(addr: A) -> ClientResult<Client<A>> {
    // client binds to all addresses...
    // this shouldn't ever fail
    // TODO switch to use expect once that stabalizes
    let zero_addr = ("0.0.0.0", 0).to_socket_addrs().unwrap().next().unwrap();

    let socket = try!(UdpSocket::bound(&zero_addr));
    Ok(Client { socket: socket, name_server: addr, next_id: Cell::new(1024) } )
  }

  /// When the resolver receives an answer via the normal DNS lookup process, it then checks to
  ///  make sure that the answer is correct. Then starts
  ///  with verifying the DS and DNSKEY records at the DNS root. Then use the DS
  ///  records for the top level domain found at the root, e.g. 'com', to verify the DNSKEY
  ///  records in the 'com' zone. From there see if there is a DS record for the
  ///  subdomain, e.g. 'example.com', in the 'com' zone, and if there is use the
  ///  DS record to verify a DNSKEY record found in the 'example.com' zone. Finally,
  ///  verify the RRSIG record found in the answer for the rrset, e.g. 'www.example.com'.
  pub fn secure_query(&self, name: &domain::Name, query_class: DNSClass, query_type: RecordType) -> ClientResult<Message> {
    // TODO: if we knew we were talking with a DNS server that supported multiple queries, these
    //  could be a single multiple query request...

    // with the secure setting, we should get the RRSIG as well as the answer
    //  the RRSIG is signed by the DNSKEY, the DNSKEY is signed by the DS record in the Parent
    //  zone. The key_tag is the DS record is assigned to the DNSKEY.
    println!("querying: {}", name);
    let record_response = try!(self.inner_query(name, query_class, query_type, true));

    if !record_response.get_answers().iter().any(|rr| rr.get_rr_type() == RecordType::RRSIG) {
      return Err(ClientError::NoRRSIG);
    }

    println!("querying SOA: {}", name);
    // get the SOA for name
    let soa_response = try!(self.inner_query(name, query_class, RecordType::SOA, true));

    let soa_record_opt: Option<&Record> = soa_response.get_answers().iter().
      chain(soa_response.get_name_servers().iter()).find(|rr| rr.get_rr_type() == RecordType::SOA);

    if soa_record_opt.is_none() { return Err(ClientError::NoSOARecord(name.clone())); }
    let mut child: domain::Name = soa_record_opt.unwrap().get_name().clone();
    let mut parent: domain::Name = child.base_name();

    loop {
      // if both are the root, then this
      if child.is_root() && parent.is_root() { break; }

      println!("querying child: {} parent: {}", child, parent);

      // TODO: performance can be improved here to send all the queries at the same time, and then
      //  await the response.
      // TODO: all root certs should be stored locally and validated? approved?
      self.inner_query(&parent, query_class, RecordType::DS, true);
      self.inner_query(&child, query_class, RecordType::DNSKEY, true);

      child = parent;
      parent = child.base_name();
    }

    // verify each RRSIG...
    unimplemented!()
  }

  // send a DNS query to the name_server specified in Clint.
  //
  // ```
  // use std::net::*;
  //
  // use trust_dns::rr::dns_class::DNSClass;
  // use trust_dns::rr::record_type::RecordType;
  // use trust_dns::rr::domain;
  // use trust_dns::rr::record_data::RData;
  // use trust_dns::udp::client::Client;
  //
  // let name = domain::Name::with_labels(vec!["www".to_string(), "example".to_string(), "com".to_string()]);
  // let client = Client::new(("8.8.8.8").parse().unwrap()).unwrap();
  // let response = client.query(name.clone(), DNSClass::IN, RecordType::A).unwrap();
  //
  // let record = &response.get_answers()[0];
  // assert_eq!(record.get_name(), &name);
  // assert_eq!(record.get_rr_type(), RecordType::A);
  // assert_eq!(record.get_dns_class(), DNSClass::IN);
  //
  // if let &RData::A{ ref address } = record.get_rdata() {
  //   assert_eq!(address, &Ipv4Addr::new(93,184,216,34))
  // } else {
  //   assert!(false);
  // }
  //
  // ```
  pub fn query(&self, name: &domain::Name, query_class: DNSClass, query_type: RecordType) -> ClientResult<Message> {
    self.inner_query(name, query_class, query_type, false)
  }

  fn inner_query(&self, name: &domain::Name, query_class: DNSClass, query_type: RecordType, secure: bool) -> ClientResult<Message> {
    // TODO: this isn't DRY, duplicate code with the TCP client

    // build the message
    let mut message: Message = Message::new();
    let id = self.next_id();
    // TODO make recursion a parameter
    message.id(id).message_type(MessageType::Query).op_code(OpCode::Query).recursion_desired(true);

    // Extended dns
    let mut edns: Edns = Edns::new();
    edns.set_dnssec_ok(secure);
    edns.set_max_payload(1400);
    edns.set_version(0);

    message.set_edns(edns);

    // add the query
    let mut query: Query = Query::new();
    query.name(name.clone()).query_class(query_class).query_type(query_type);
    message.add_query(query);

    // get the message bytes and send the query
    let mut buffer: Vec<u8> = Vec::with_capacity(512);
    {
      let mut encoder = BinEncoder::new(&mut buffer);
      try!(message.emit(&mut encoder));
    }

    let addr = try!(try!(self.name_server.to_socket_addrs()).next().ok_or(ClientError::NoNameServer));

    // -- net2 client
    // let sent = try!(self.socket.send_to(&buffer, &addr));
    // println!("sent {} bytes to {:?}", sent, addr);
    // debug!("sent {} bytes to {:?}", sent, addr);
    //
    // buffer.clear();
    // let (_, addr) = try!(self.socket.recv_from(&mut buffer));
    // println!("bytes: {:?} from: {:?}", buffer.len(), addr);
    // debug!("bytes: {:?} from: {:?}", buffer.len(), addr);

    // -- end net2 client

    // --- MIO client, not really necessary unless we want parallel ---

    let mut bytes = Cursor::new(buffer);
    try!(self.socket.send_to(&mut bytes, &addr));

    //----------------------------
    // now listen for the response
    //----------------------------
    // setup the polling and timeout, before sending the message
    // Create an event loop

    let mut event_loop: EventLoop<Response> = try!(EventLoop::new());
    // TODO make the timeout configurable, 5 seconds is the dig default
    // TODO the error is private to mio, which makes this awkward...
    if event_loop.timeout_ms((), 5000).is_err() { return Err(ClientError::TimerError) };
    try!(event_loop.register_opt(&self.socket, RESPONSE, EventSet::readable(), PollOpt::all()));

    let mut response: Response = Response::new(&self.socket);

    // run_once should be enough, if something else nepharious hits the socket, what?
    try!(event_loop.run(&mut response));

    if response.error.is_some() { return Err(response.error.unwrap()) }
    if response.buf.is_none() { return Err(ClientError::NoDataReceived) }
    let buffer = response.buf.unwrap();

    // -- end MIO client

    let mut decoder = BinDecoder::new(&buffer);
    let response = try!(Message::read(&mut decoder));

    if response.get_id() != id { return Err(ClientError::IncorrectMessageId{ got: response.get_id(), expect: id }); }
    if response.get_response_code() != ResponseCode::NoError { return Err(ClientError::ErrorResponse(response.get_response_code())); }

    Ok(response)
  }

  fn next_id(&self) -> u16 {
    let id = self.next_id.get();
    self.next_id.set(id + 1);
    id
  }
}

struct Response<'a> {
  pub buf: Option<Vec<u8>>,
  pub addr: Option<SocketAddr>,
  pub error: Option<ClientError>,
  pub socket: &'a UdpSocket,
}

impl<'a> Response<'a> {
  pub fn new(socket: &'a UdpSocket) -> Self {
    Response{ buf: None, addr: None, error: None, socket: socket }
  }
}

impl<'a> Handler for Response<'a> {
  type Timeout = ();
  type Message = ();

  fn ready(&mut self, event_loop: &mut EventLoop<Self>, token: Token, events: EventSet) {
    match token {
      RESPONSE => {
        if !events.is_readable() {
          debug!("got woken up, but not readable: {:?}", token);
          return
        }

        let mut buf = Vec::with_capacity(4096);

        let recv_result = self.socket.recv_from(&mut buf);
        if recv_result.is_err() {
          // debug b/c we're returning the error explicitly
          debug!("could not recv_from on {:?}: {:?}", self.socket, recv_result);
          self.error = Some(recv_result.unwrap_err().into());
          return
        }

        if recv_result.as_ref().unwrap().is_none() {
          // debug b/c we're returning the error explicitly
          debug!("no return address on recv_from: {:?}", self.socket);
          self.error = Some(ClientError::NoAddress);
          return
        }

        self.addr = Some(recv_result.unwrap().unwrap());
        debug!("bytes: {:?} from: {:?}", buf.len(), self.addr);

        // we got our response, shutdown.
        event_loop.shutdown();

        // set our data
        self.buf = Some(buf);

        // TODO, perhaps parse the response in here, so that the client could ignore messages with the
        //  wrong serial number.
      },
      _ => {
        error!("unrecognized token: {:?}", token);
        self.error = Some(ClientError::NoDataReceived);
      },
    }
  }

  fn timeout(&mut self, event_loop: &mut EventLoop<Self>, _: ()) {
    self.error = Some(ClientError::TimedOut);
    event_loop.shutdown();
  }
}

// TODO: this should be flagged with cfg as a functional test.
#[test]
#[cfg(feature = "ftest")]
fn test_query() {
  use std::net::*;

  use ::rr::dns_class::DNSClass;
  use ::rr::record_type::RecordType;
  use ::rr::domain;
  use ::rr::record_data::RData;
  use ::udp::Client;

  let name = domain::Name::with_labels(vec!["www".to_string(), "example".to_string(), "com".to_string()]);
  let client = Client::new(("8.8.8.8").parse().unwrap()).unwrap();

  let response = client.query(&name, DNSClass::IN, RecordType::A);
  assert!(response.is_ok(), "query failed: {}", response.unwrap_err());

  let response = response.unwrap();

  println!("response records: {:?}", response);

  let record = &response.get_answers()[0];
  assert_eq!(record.get_name(), &name);
  assert_eq!(record.get_rr_type(), RecordType::A);
  assert_eq!(record.get_dns_class(), DNSClass::IN);

  if let &RData::A{ ref address } = record.get_rdata() {
    assert_eq!(address, &Ipv4Addr::new(93,184,216,34))
  } else {
    assert!(false);
  }
}

#[test]
#[cfg(feature = "ftest")]
fn test_secure_query() {
  use std::net::*;

  use ::rr::dns_class::DNSClass;
  use ::rr::record_type::RecordType;
  use ::rr::domain;
  use ::rr::record_data::RData;
  use ::udp::Client;

  let name = domain::Name::with_labels(vec!["www".to_string(), "sdsmt".to_string(), "edu".to_string()]);
  let client = Client::new(("8.8.8.8").parse().unwrap()).unwrap();

  let response = client.secure_query(&name, DNSClass::IN, RecordType::A);
  assert!(response.is_ok(), "query failed: {}", response.unwrap_err());

  let response = response.unwrap();

  println!("response records: {:?}", response);

  let record = &response.get_answers()[0];
  assert_eq!(record.get_name(), &name);
  assert_eq!(record.get_rr_type(), RecordType::A);
  assert_eq!(record.get_dns_class(), DNSClass::IN);

  if let &RData::A{ ref address } = record.get_rdata() {
    assert_eq!(address, &Ipv4Addr::new(93,184,216,34))
  } else {
    assert!(false);
  }
}
