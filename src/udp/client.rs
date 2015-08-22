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
use std::net::*; // we need almost everything in here...
use std::cell::Cell;

use ::error::*;
use ::rr::dns_class::DNSClass;
use ::rr::record_type::RecordType;
use ::rr::domain;
use ::op::message::Message;
use ::op::header::MessageType;
use ::op::op_code::OpCode;
use ::op::query::Query;
use ::serialize::binary::*;

pub struct Client {
  socket: UdpSocket,
  name_server: SocketAddrV4,
  next_id: Cell<u16>,
}

impl Client {
  /// name_server to connect to with default port 53
  pub fn new(name_server: Ipv4Addr) -> ClientResult<Client> {
    Self::with_port(name_server, 53)
  }

  /// name_server to connect to, port is the port number that server is listening on (default 53)
  pub fn with_port(name_server: Ipv4Addr, port: u16) -> ClientResult<Client> {
    // client binds to all addresses...
    // TODO when the socket_opts interfaces stabilize, need to add timeouts, ttl, etc.
    let socket = try!(UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::new(0,0,0,0),0)));
    Ok(Client { socket: socket, name_server: SocketAddrV4::new(name_server, port), next_id: Cell::new(4096) })
  }

  /// send a DNS query to the name_server specified in Clint.
  ///
  /// ```
  /// use std::net::*;
  ///
  /// use trust_dns::rr::dns_class::DNSClass;
  /// use trust_dns::rr::record_type::RecordType;
  /// use trust_dns::rr::domain;
  /// use trust_dns::rr::record_data::RData;
  /// use trust_dns::udp::client::Client;
  ///
  /// let name = domain::Name::with_labels(vec!["www".to_string(), "example".to_string(), "com".to_string()]);
  /// let client = Client::new(("8.8.8.8").parse().unwrap()).unwrap();
  /// let response = client.query(name.clone(), DNSClass::IN, RecordType::A).unwrap();
  ///
  /// let record = &response.get_answers()[0];
  /// assert_eq!(record.get_name(), &name);
  /// assert_eq!(record.get_rr_type(), RecordType::A);
  /// assert_eq!(record.get_dns_class(), DNSClass::IN);
  ///
  /// if let &RData::A{ ref address } = record.get_rdata() {
  ///   assert_eq!(address, &Ipv4Addr::new(93,184,216,34))
  /// } else {
  ///   assert!(false);
  /// }
  ///
  /// ```
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

    // get the message bytes and send the query
    let mut encoder = BinEncoder::new();
    try!(message.emit(&mut encoder));

    // TODO proper error handling
    // TODO when the socket_opts interfaces stabilize, need to add timeouts, ttl, etc.
    let bytes = encoder.as_bytes();
    let bytes_sent = try!(self.socket.send_to(&bytes, self.name_server));
    if bytes_sent != bytes.len() { return Err(ClientError::NotAllBytesSent{sent: bytes_sent, expect: bytes.len()}); }

    //----------------------------
    // now listen for the response
    //----------------------------

    // the max buffer size we'll except is 4k
    let mut buf = [0u8; 4096];
    let (bytes_recv, _) = try!(self.socket.recv_from(&mut buf));

    // for i in 0..bytes_recv {
    //   println!("{:02X}", buf[i]);
    // }

    // TODO change parsers to use Read or something else, so that we don't need to copy here.
    let resp_bytes = buf[..bytes_recv].to_vec();
    //resp_bytes.truncate(bytes_recv);



    // TODO, this could probably just be a reference to the slice rather than an owned Vec
    let mut decoder = BinDecoder::new(resp_bytes);
    let response = try!(Message::read(&mut decoder));    // TODO, change all parses to return Results...

    if response.get_id() != id { return Err(ClientError::IncorrectMessageId{ got: response.get_id(), expect: id }); }

    Ok(response)
  }

  fn next_id(&self) -> u16 {
    let id = self.next_id.get();
    self.next_id.set(id + 1);
    id
  }
}

#[test]
fn test_query() {
  use std::net::*;

  use ::rr::dns_class::DNSClass;
  use ::rr::record_type::RecordType;
  use ::rr::domain;
  use ::rr::record_data::RData;
  use ::udp::client::Client;

  let name = domain::Name::with_labels(vec!["www".to_string(), "example".to_string(), "com".to_string()]);
  let client = Client::new(("8.8.8.8").parse().unwrap()).unwrap();
  let response = client.query(name.clone(), DNSClass::IN, RecordType::A).unwrap();

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
