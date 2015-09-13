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
use std::net::*;
use std::io;

use ::authority::Catalog;
use ::op::*;
use ::serialize::binary::*;

pub struct Server {
  socket: UdpSocket,
  catalog: Catalog,
  // cache?
}

// TODO: convert this to use the MIO library.
impl Server {
  pub fn with_authorities(catalog: Catalog) -> Self {
    // TODO: obviously needs some work ;) waiting on stable socket options
    Server { socket: UdpSocket::bind(("127.0.0.1", 0)).unwrap(), catalog: catalog }
  }

  pub fn local_addr(&self) -> io::Result<SocketAddr> {
    self.socket.local_addr()
  }

  // TODO how to do threads? should we do a bunch of listener threads and then query threads?
  pub fn listen(&self) {
    info!("Server starting up: {:?}", self.socket);

    // TODO loop on recv... eventually make multiple threads for running recv concurrently.
    let mut buf = [0u8; 4096];
    let (read_count, addr) = self.socket.recv_from(&mut buf).unwrap();
    info!("bytes: {:?} from: {:?}", read_count, addr);

    // read message in
    let read_bytes = buf[..read_count].to_vec();  // copy out the bytes from the buffer
    let mut decoder = BinDecoder::new(read_bytes);

    let request = Message::read(&mut decoder);

    if let Err(decode_error) = request {
      warn!("unable to decode request from client: {}: {}", addr, decode_error);
      self.error_to(addr, 0/* id is in the message... */, OpCode::Query/* right default? */, ResponseCode::FormErr);
    } else {
      let request = request.unwrap(); // unwrap the Ok()
      info!("id: {} type: {:?} op_code: {:?}", request.get_id(), request.get_message_type(), request.get_op_code());

      let id = request.get_id();

      match request.get_message_type() {
        // TODO think about threading query lookups for multiple lookups, this could be a huge improvement
        //  especially for recursive lookups
        // TODO probably kick off a thread here
        MessageType::Query => self.handle_message(addr, request),
        MessageType::Response => {
          warn!("got a response as a request from: {} id: {}", addr, id);
          self.error_to(addr, id, request.get_op_code(), ResponseCode::NotImp);
        },
      }
    }
  }

  pub fn handle_message(&self, addr: SocketAddr, request: Message) {
    match request.get_op_code() {
      OpCode::Query => {
        let response = self.catalog.lookup(&request);
        debug!("query response: {:?}", response);
        self.send_to(addr, response);
      },
      c @ _ => {
        error!("unimplemented op_code: {:?}", c);
        self.error_to(addr, request.get_id(), request.get_op_code(), ResponseCode::NotImp);
      },
    }
  }

  pub fn error_to(&self, addr: SocketAddr, id: u16, op_code: OpCode, response_code: ResponseCode) {
    let mut message: Message = Message::new();
    message.message_type(MessageType::Response);
    message.id(id);
    message.response_code(response_code);
    message.op_code(op_code);

    self.send_to(addr, message);
  }

  pub fn send_to(&self, addr: SocketAddr, response: Message) {
    // all responses need these fields set:
    let mut encoder:BinEncoder = BinEncoder::new();
    let encode_result = response.emit(&mut encoder);

    if let Err(encode_error) = encode_result {
      // yes, dangerous, but errors are a much simpler message, so they should encode no problem
      //  otherwise we'll blow the stack, which is ok, there's something horribly wrong in that
      //  case with the code.
      error!("error encoding response to client: {}", encode_error);
      self.error_to(addr, response.get_id(), response.get_op_code(), ResponseCode::ServFail);
    } else {
      info!("sending message to: {} id: {} rcode: {:?}", addr, response.get_id(), response.get_response_code());
      let bytes = encoder.as_bytes();
      let result = self.socket.send_to(&bytes, addr);
      if let Err(error) = result {
        error!("error sending to: {} id: {} error: {}", addr, response.get_id(), error);
      } else {
        debug!("successfully sent message to: {} id: {} bytes: {}", addr, response.get_id(), bytes.len());
      }
    }
  }
}



#[cfg(test)]
mod server_tests {
  use super::*;
  use std::thread;
  use std::net::*;
  use std::process::*;

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
    let example = create_example();
    let origin = example.get_origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin.clone(), example);

    let server = Server::with_authorities(catalog);
    let ipaddr = server.local_addr().unwrap(); // for the client to connect to

    let server_thread = thread::Builder::new().name("test_server:server".to_string()).spawn(move || server_thread(server)).unwrap();
    let client_thread = thread::Builder::new().name("test_server:client".to_string()).spawn(move || client_thread_origin(ipaddr)).unwrap();

    let client_result = client_thread.join();
    let server_result = server_thread.join();

    assert!(client_result.is_ok(), "client failed: {:?}", client_result);
    assert!(server_result.is_ok(), "server failed: {:?}", server_result);
  }

  #[test]
  fn test_server_www() {
    let example = create_example();
    let origin = example.get_origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin.clone(), example);

    let server = Server::with_authorities(catalog);
    let ipaddr = server.local_addr().unwrap(); // for the client to connect to

    let server_thread = thread::Builder::new().name("test_server:server".to_string()).spawn(move || server_thread(server)).unwrap();
    let client_thread = thread::Builder::new().name("test_server:client".to_string()).spawn(move || client_thread_www(ipaddr)).unwrap();

    let client_result = client_thread.join();
    let server_result = server_thread.join();

    assert!(client_result.is_ok(), "client failed: {:?}", client_result);
    assert!(server_result.is_ok(), "server failed: {:?}", server_result);
  }

  // TODO: functional test!
  /// This test verifies that we work with standard tools
  #[test]
  fn test_server_host_cli() {
    let example = create_example();
    let origin = example.get_origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin.clone(), example);

    let server = Server::with_authorities(catalog);
    let ipaddr = server.local_addr().unwrap(); // for the client to connect to

    let server_thread = thread::Builder::new().name("test_server:server".to_string()).spawn(move || server_thread(server)).unwrap();
    let client_result = Command::new("dig").arg("@127.0.0.1").arg(format!("-p{}", ipaddr.port()))
                                           .arg("www.example.com").arg("+short")
                                           .output().unwrap_or_else(|e| panic!("failed to spawn dig: {}", e) );

    let server_result = server_thread.join();

    assert!(&(client_result.status).success());
    assert_eq!(client_result.stdout, "93.184.216.34\n".as_bytes()); // newline from the dig output

    assert!(server_result.is_ok(), "server failed: {:?}", server_result);
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

    let ns = response.get_name_servers();
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

    let ns = response.get_name_servers();
    assert_eq!(ns.len(), 2);
    assert_eq!(ns.first().unwrap().get_rr_type(), RecordType::NS);
    assert_eq!(ns.first().unwrap().get_rdata(), &RData::NS{ nsdname: Name::parse("a.iana-servers.net.", None).unwrap() });
    assert_eq!(ns.last().unwrap().get_rr_type(), RecordType::NS);
    assert_eq!(ns.last().unwrap().get_rdata(), &RData::NS{ nsdname: Name::parse("b.iana-servers.net.", None).unwrap() });
  }

  fn server_thread(server: Server) {
    server.listen();
  }
}
