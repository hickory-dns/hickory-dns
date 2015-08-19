use std::net::*; // we need almost everything in here...
use std::cell::Cell;
use std::io;

use super::super::rr::resource::Record;
use super::super::rr::dns_class::DNSClass;
use super::super::rr::record_type::RecordType;
use super::super::rr::domain;
use super::super::op::message::Message;
use super::super::op::header::{Header, MessageType};
use super::super::op::op_code::OpCode;
use super::super::op::query::Query;

pub struct Client {
  socket: UdpSocket,
  name_server: SocketAddrV4,
  next_id: Cell<u16>,
}

impl Client {
  /// name_server to connect to with default port 53
  pub fn new(name_server: Ipv4Addr) -> io::Result<Client> {
    Self::with_port(name_server, 53)
  }

  /// name_server to connect to, port is the port number that server is listening on (default 53)
  pub fn with_port(name_server: Ipv4Addr, port: u16) -> io::Result<Client> {
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
  pub fn query(&self, name: domain::Name, query_class: DNSClass, query_type: RecordType) -> Result<Message, ()> {
    // build the message
    let mut message: Message = Message::new();
    let id = self.next_id();
    message.id(id).message_type(MessageType::Query).op_code(OpCode::Query).recursion_desired(true);

    // add the query
    let mut query: Query = Query::new();
    query.name(name).query_class(query_class).query_type(query_type);
    message.add_query(query);

    // get the message bytes and send the query
    let mut buf: Vec<u8> = Vec::new();
    message.write_to(&mut buf);

    // TODO proper error handling
    // TODO when the socket_opts interfaces stabilize, need to add timeouts, ttl, etc.
    let bytes_sent = self.socket.send_to(&buf, self.name_server).unwrap();
    assert_eq!(bytes_sent, buf.len()); // TODO, proper error...

    //----------------------------
    // now listen for the response
    //----------------------------

    // the max buffer size we'll except is 4k
    let mut buf = [0u8; 4096];
    let (bytes_recv, remote) = self.socket.recv_from(&mut buf).unwrap();

    // TODO change parsers to use Read or something else, so that we don't need to copy here.
    let mut resp_bytes = buf.to_vec();
    resp_bytes.truncate(bytes_recv);
    resp_bytes.reverse();
    let response = Message::parse(&mut resp_bytes);    // TODO, change all parses to return Results...

    assert_eq!(response.get_id(), id); // TODO, better error...
    Ok(response)
  }

  fn next_id(&self) -> u16 {
    let id = self.next_id.get();
    self.next_id.set(id + 1);
    id
  }
}
