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
use std::net::{SocketAddr, ToSocketAddrs};
use std::io;
use std::io::Cursor;
use std::fmt::Debug;

use mio::udp::UdpSocket;
use mio::{Token, EventLoop, Handler, EventSet, PollOpt }; // not * b/c don't want confusion with std::net

use ::authority::Catalog;
use ::op::*;
use ::serialize::binary::*;

const SERVER: Token = Token(0);

pub struct Server {
  socket: UdpSocket,
  catalog: Catalog,
  // TODO: cache?
  // TODO: having this here looks ugly.
  error: Option<io::Result<()>>
}

impl Server {
  /// This should take a list of IPs on which to listen, i.e. IPv4 and IPv6 etc.
  ///  as well as supporting many interfaces at once.
  ///  At the moment it only supports one or the other.
  /// Pass in (0.0.0.0, 53) for to listen on all IPs.
  ///
  /// As of now, this only supports UDP eventually this will also listen on TCP
  pub fn new<A: ToSocketAddrs + Debug>(listen_addr: A, catalog: Catalog) -> io::Result<Self> {
    let socket_addr = try!(try!(listen_addr.to_socket_addrs()).next().
      ok_or(io::Error::new(io::ErrorKind::AddrNotAvailable, format!("no valid IPs: {:?}", listen_addr))));

    Ok(Server { socket: UdpSocket::bound(&socket_addr).unwrap(), catalog: catalog, error: None, })
  }

  pub fn local_addr(&self) -> io::Result<SocketAddr> {
    self.socket.local_addr()
  }

  /// TODO how to do threads? should we do a bunch of listener threads and then query threads?
  /// Ideally the processing would be n-threads for recieving, which hand off to m-threads for
  ///  request handling. It would generally be the case that n <= m.
  pub fn listen(&mut self) -> io::Result<()> {
    info!("Server starting up: {:?}", self.socket);

    let mut event_loop: EventLoop<Server> = try!(EventLoop::new());
    try!(event_loop.register_opt(&self.socket, SERVER, EventSet::readable(), PollOpt::level()));

    // I wonder if the event_loop should be outside the method
    //  to make this easier for testing... or return the event_loop...
    try!(event_loop.run(self));

    if self.error.is_none() { Ok(()) }
    else { Err(io::Error::new(io::ErrorKind::Interrupted, format!("{:?} Interrupted", self.socket))) }
  }

  pub fn handle_message(&self, addr: SocketAddr, request_bytes: Vec<u8>) {
    let mut decoder = BinDecoder::new(&request_bytes);

    let request = Message::read(&mut decoder);

    let response = match request {
      Err(decode_error) => {
        warn!("unable to decode request from client: {:?}: {}", addr, decode_error);
        Catalog::error_msg(0/* id is in the message... */, OpCode::Query/* right default? */, ResponseCode::FormErr)
      },
      Ok(req) => self.catalog.handle_request(req),
    };

    self.send_to(addr, response);
  }

  pub fn send_to(&self, addr: SocketAddr, response: Message) {
    // all responses need these fields set:
    let mut bytes: Vec<u8> = Vec::with_capacity(512);
    let encode_result = {
      let mut encoder:BinEncoder = BinEncoder::new(&mut bytes);
      response.emit(&mut encoder)
    };

    if let Err(encode_error) = encode_result {
      // yes, dangerous, but errors are a much simpler message, so they should encode no problem
      //  otherwise we'll blow the stack, which is ok, there's something horribly wrong in that
      //  case with the code.
      error!("error encoding response to client: {}", encode_error);
      self.send_to(addr, Catalog::error_msg(response.get_id(), response.get_op_code(), ResponseCode::ServFail));
    } else {
      info!("sending message to: {} id: {} rcode: {:?}", addr, response.get_id(), response.get_response_code());

      // TODO when the next version of MIO is released, this clone and unsafe will be unnecessary
      let mut bytes = Cursor::new(bytes.clone());
      let result = self.socket.send_to(&mut bytes, &addr);
      if let Err(error) = result {
        error!("error sending to: {} id: {} error: {}", addr, response.get_id(), error);
      } else {
        debug!("successfully sent message to: {} id: {} bytes: {}", addr, response.get_id(), bytes.get_ref().len());
      }
    }
  }
}

impl Handler for Server {
  type Timeout = ();
  type Message = ();

  fn ready(&mut self, _: &mut EventLoop<Self>, token: Token, events: EventSet) {
    match token {
      SERVER => {
        if !events.is_readable() {
          debug!("got woken up, but not readable: {:?}", token);
          return;
        }

        // it would great to have a pool of buffers, more efficient.
        let mut buf: Vec<u8> = Vec::with_capacity(4096);

        let recv_result = self.socket.recv_from(&mut buf);
        if recv_result.is_err() {
          warn!("could not recv_from on {:?}: {:?}", self.socket, recv_result);
          return
        }

        if recv_result.as_ref().unwrap().is_none() {
          warn!("no return address on recv_from: {:?}", self.socket);
          return
        }

        let addr = recv_result.unwrap().unwrap();
        info!("bytes: {:?} from: {:?}", buf.len(), addr);

        self.handle_message(addr, buf);
      },
      _ => {
        error!("unrecognized token: {:?}", token);
        self.error = Some(Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{:?} InvalidInput", self.socket))));
      },
    }
  }

  fn interrupted(&mut self, event_loop: &mut EventLoop<Self>) {
    event_loop.shutdown();
    warn!("{:?} interrupted", self.socket);
    self.error = Some(Err(io::Error::new(io::ErrorKind::Interrupted, format!("{:?} interrupted", self.socket))));
  }
}


#[cfg(test)]
mod server_tests {
  use super::*;
  use std::thread;
  use std::net::*;

  use ::authority::authority_tests::create_example;
  use ::op::*;
  use ::rr::dns_class::DNSClass;
  use ::rr::record_type::RecordType;
  use ::rr::domain::Name;
  use ::rr::record_data::RData;
  use ::udp::client::Client;
  use ::authority::Catalog;

  #[test]
  fn test_server_origin() {
    let catalog: Catalog = {
      let example = create_example();
      let origin = example.get_origin().clone();

      let mut catalog: Catalog = Catalog::new();
      catalog.upsert(origin.clone(), example);
      catalog
    };

    let server = Server::new(("127.0.0.1", 0), catalog).unwrap();
    let ipaddr = server.local_addr().unwrap(); // for the client to connect to

    /*let server_thread = */thread::Builder::new().name("test_server:server".to_string()).spawn(move || server_thread(server)).unwrap();
    let client_thread = thread::Builder::new().name("test_server:client".to_string()).spawn(move || client_thread_origin(ipaddr)).unwrap();
    // check that the server will work with multiple requests...
    let client_thread2 = thread::Builder::new().name("test_server:client".to_string()).spawn(move || client_thread_origin(ipaddr)).unwrap();

    let client_result = client_thread.join();
    let client_result2 = client_thread2.join();

    //    let server_result = server_thread.join();

    assert!(client_result.is_ok(), "client failed: {:?}", client_result);
    assert!(client_result2.is_ok(), "client2 failed: {:?}", client_result2);
    //    assert!(server_result.is_ok(), "server failed: {:?}", server_result);
  }

  #[test]
  fn test_server_www() {
    let example = create_example();
    let origin = example.get_origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin.clone(), example);

    let server = Server::new(("127.0.0.1", 0), catalog).unwrap();
    let ipaddr = server.local_addr().unwrap(); // for the client to connect to

    /*let server_thread = */thread::Builder::new().name("test_server:server".to_string()).spawn(move || server_thread(server)).unwrap();
    let client_thread = thread::Builder::new().name("test_server:client".to_string()).spawn(move || client_thread_www(ipaddr)).unwrap();

    let client_result = client_thread.join();
    //    let server_result = server_thread.join();

    assert!(client_result.is_ok(), "client failed: {:?}", client_result);
    //    assert!(server_result.is_ok(), "server failed: {:?}", server_result);
  }

  /// This test verifies that we work with standard tools
  #[test]
  #[cfg(feature = "ftest")]
  fn test_server_host_cli() {
    use std::process::*;

    let example = create_example();
    let origin = example.get_origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin.clone(), example);

    let server = Server::new(("127.0.0.1", 0), catalog).unwrap();
    let ipaddr = server.local_addr().unwrap(); // for the client to connect to

    /*let server_thread = */thread::Builder::new().name("test_server:server".to_string()).spawn(move || server_thread(server)).unwrap();
    let client_result = Command::new("dig").arg("@127.0.0.1").arg(format!("-p{}", ipaddr.port()))
                                           .arg("www.example.com").arg("+short")
                                           .output().unwrap_or_else(|e| panic!("failed to spawn dig: {}", e) );

    //    let server_result = server_thread.join();

    assert!(&(client_result.status).success());
    assert_eq!(client_result.stdout, "93.184.216.34\n".as_bytes()); // newline from the dig output

    //    assert!(server_result.is_ok(), "server failed: {:?}", server_result);
  }

  fn client_thread_origin(server_addr: SocketAddr) {
    let name = Name::with_labels(vec!["example".to_string(), "com".to_string()]);
    let client = Client::with_addr(server_addr).unwrap();

    println!("about to query server: {:?}", server_addr);
    let response = client.query(name.clone(), DNSClass::IN, RecordType::A).unwrap();

    assert!(response.get_response_code() == ResponseCode::NoError, "got an error: {:?}", response.get_response_code());

    let record = &response.get_answers()[0];
    assert_eq!(record.get_name(), &name);
    assert_eq!(record.get_rr_type(), RecordType::A);
    assert_eq!(record.get_dns_class(), DNSClass::IN);

    if let &RData::A{ ref address } = record.get_rdata() {
      assert_eq!(address, &Ipv4Addr::new(93,184,216,34))
    } else {
      assert!(false);
    }

    let mut ns: Vec<_> = response.get_name_servers().to_vec();
    ns.sort();

    assert_eq!(ns.len(), 2);
    assert_eq!(ns.first().unwrap().get_rr_type(), RecordType::NS);
    assert_eq!(ns.first().unwrap().get_rdata(), &RData::NS{ nsdname: Name::parse("a.iana-servers.net.", None).unwrap() });
    assert_eq!(ns.last().unwrap().get_rr_type(), RecordType::NS);
    assert_eq!(ns.last().unwrap().get_rdata(), &RData::NS{ nsdname: Name::parse("b.iana-servers.net.", None).unwrap() });
  }

  fn client_thread_www(server_addr: SocketAddr) {
    let name = Name::with_labels(vec!["www".to_string(), "example".to_string(), "com".to_string()]);
    let client = Client::with_addr(server_addr).unwrap();

    println!("about to query server: {:?}", server_addr);
    let response = client.query(name.clone(), DNSClass::IN, RecordType::A).unwrap();

    assert!(response.get_response_code() == ResponseCode::NoError, "got an error: {:?}", response.get_response_code());

    let record = &response.get_answers()[0];
    assert_eq!(record.get_name(), &name);
    assert_eq!(record.get_rr_type(), RecordType::A);
    assert_eq!(record.get_dns_class(), DNSClass::IN);

    if let &RData::A{ ref address } = record.get_rdata() {
      assert_eq!(address, &Ipv4Addr::new(93,184,216,34))
    } else {
      assert!(false);
    }

    let mut ns: Vec<_> = response.get_name_servers().to_vec();
    ns.sort();

    assert_eq!(ns.len(), 2);
    assert_eq!(ns.first().unwrap().get_rr_type(), RecordType::NS);
    assert_eq!(ns.first().unwrap().get_rdata(), &RData::NS{ nsdname: Name::parse("a.iana-servers.net.", None).unwrap() });
    assert_eq!(ns.last().unwrap().get_rr_type(), RecordType::NS);
    assert_eq!(ns.last().unwrap().get_rdata(), &RData::NS{ nsdname: Name::parse("b.iana-servers.net.", None).unwrap() });
  }

  fn server_thread(mut server: Server) {
    server.listen().unwrap();
  }
}
