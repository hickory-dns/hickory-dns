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
use std::net::{ToSocketAddrs, Ipv4Addr};
use std::io::{Write, Read};
use std::cell::Cell;

use mio::tcp::TcpStream;
use mio::{Token, EventLoop, Handler, EventSet, PollOpt}; // not * b/c don't want confusion with std::net

use ::error::*;
use ::rr::dns_class::DNSClass;
use ::rr::record_type::RecordType;
use ::rr::domain;
use ::op::message::Message;
use ::op::header::MessageType;
use ::op::op_code::OpCode;
use ::op::query::Query;
use ::serialize::binary::*;

const RESPONSE: Token = Token(0);

pub struct Client<A: ToSocketAddrs + Copy> {
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

    Ok(Client { name_server: addr, next_id: Cell::new(1024) } )
  }

  // send a DNS query to the name_server specified in Clint.
  pub fn query(&self, name: domain::Name, query_class: DNSClass, query_type: RecordType) -> ClientResult<Message> {
    // build the message
    let mut message: Message = Message::new();
    let id = self.next_id();
    // TODO make recursion a parameter
    message.id(id).message_type(MessageType::Query).op_code(OpCode::Query).recursion_desired(true);

    // add the query
    let mut query: Query = Query::new();
    query.name(name).query_class(query_class).query_type(query_type);
    message.add_query(query);

    // TODO, the client should cache the stream for multiple use.
    let addr = try!(try!(self.name_server.to_socket_addrs()).next().ok_or(ClientError::NoNameServer));
    debug!("connecting to {:?}", addr);
    let mut stream = try!(TcpStream::connect(&addr));

    //----------------------------
    // now listen for the response
    //----------------------------
    // setup the polling and timeout, before sending the message
    // Create an event loop

    let mut event_loop: EventLoop<Response> = try!(EventLoop::new());
    // TODO make the timeout configurable, 5 seconds is the dig default
    // TODO the error is private to mio, which makes this awkward...
    if event_loop.timeout_ms((), 5000).is_err() { return Err(ClientError::TimerError) };
    try!(event_loop.register_opt(&stream, RESPONSE, EventSet::all(), PollOpt::all()));

    let mut response: Response = Response::new(message, &mut stream);

    try!(event_loop.run(&mut response));

    if response.error.is_some() { return Err(response.error.unwrap()) }
    if response.buf.is_none() { return Err(ClientError::NoDataReceived) }
    let buffer = response.buf.unwrap();

    let mut decoder = BinDecoder::new(&buffer);
    let response = try!(Message::read(&mut decoder));

    if response.get_id() != id { return Err(ClientError::IncorrectMessageId{ got: response.get_id(), expect: id }); }

    Ok(response)
  }

  fn next_id(&self) -> u16 {
    let id = self.next_id.get();
    self.next_id.set(id + 1);
    id
  }
}

struct Response<'a> {
  pub state: ClientState,
  pub message: Message,
  pub buf: Option<Vec<u8>>,
  pub error: Option<ClientError>,
  pub stream: &'a mut TcpStream,
}

enum ClientState {
  WillWrite,
  //WillRead,
}

impl<'a> Response<'a> {
  pub fn new(message: Message, stream: &'a mut TcpStream) -> Self {
    Response{ state: ClientState::WillWrite, message: message, buf: None, error: None, stream: stream }
  }
}

impl<'a> Handler for Response<'a> {
  type Timeout = ();
  type Message = ();

  fn ready(&mut self, event_loop: &mut EventLoop<Self>, token: Token, events: EventSet) {
    match token {
      RESPONSE => {
        if events.is_writable() {
          // get the message bytes and send the query
          let mut bytes: Vec<u8> = Vec::with_capacity(512);
          {
            let mut encoder = BinEncoder::new(&mut bytes);
            self.error = self.message.emit(&mut encoder).err().map(|o|o.into());
            if self.error.is_some() { return }
          }

          debug!("writing to");
          let len: [u8; 2] = [(bytes.len() >> 8 & 0xFF) as u8, (bytes.len() & 0xFF) as u8];
          self.error = self.stream.write_all(&len).and_then(|_|self.stream.write_all(&bytes)).err().map(|o|o.into());
          if self.error.is_some() { return }

          self.error = self.stream.flush().err().map(|o|o.into());
          debug!("wrote to");
        } else if events.is_readable() {
          // assuming we will always be able to read two bytes.
          let mut len_bytes: [u8;2] = [0u8;2];

          match self.stream.take(2).read(&mut len_bytes) {
            Ok(len) if len != 2 => {
              debug!("did not read all len_bytes expected: 2 got: {:?} bytes from: {:?}", len_bytes, self.stream);
              self.error = Some(ClientError::NotAllBytesReceived{received: len, expect: 2});
              return
            },
            Err(e) => {
              self.error = Some(e.into());
              return
            },
            Ok(_) => (),
          }

          let len: u16 = (len_bytes[0] as u16) << 8 & 0xFF00 | len_bytes[1] as u16 & 0x00FF;

          debug!("reading {:?} bytes from: {:?}", len, self.stream.peer_addr());
          // use a cursor here, and seek to the write spot on each read...
          let mut buf = Vec::with_capacity(len as usize);
          match self.stream.take(len as u64).read_to_end(&mut buf) {
            Ok(got) if got != len as usize => {
              debug!("did not read all bytes got: {} expected: {} bytes from: {:?}", got, len, self.stream.peer_addr());
              self.error = Some(ClientError::NotAllBytesReceived{received: got, expect: len as usize});
              return
            },
            Err(e) => {
              self.error = Some(e.into());
              return
            },
            Ok(_) => (),
          }

          // we got our response, shutdown.
          event_loop.shutdown();

          debug!("read {:?} bytes from: {:?}", buf.len(), self.stream);

          // set our data
          self.buf = Some(buf);

          // TODO, perhaps parse the response in here, so that the client could ignore messages with the
          //  wrong serial number.
        } else if events.is_error() || events.is_hup() {
          debug!("an error occured, connection shutdown early: {:?}", token);
          self.error = Some(ClientError::NoDataReceived);
          event_loop.shutdown();
        } else {
          debug!("got woken up, but not readable or writable: {:?}", token);
          return
        }
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
  use ::tcp::Client;

  let name = domain::Name::with_labels(vec!["www".to_string(), "example".to_string(), "com".to_string()]);
  let client = Client::new(("8.8.8.8").parse().unwrap()).unwrap();

  let response = client.query(name.clone(), DNSClass::IN, RecordType::A);
  assert!(response.is_ok(), "query failed: {}", response.unwrap_err());

  let response = response.unwrap();

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
