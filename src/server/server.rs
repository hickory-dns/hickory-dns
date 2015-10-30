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
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::cell::Cell;

use mio::{Token, EventLoop, Handler, EventSet, PollOpt, TryAccept};
use mio::tcp::{TcpListener};
use mio::udp::UdpSocket;

use ::tcp::{TcpHandler, TcpState};
use ::authority::Catalog;

pub struct Server {
  udp_sockets: HashMap<Token, UdpSocket>,
  udp_requests: HashMap<Token, UdpSocket>,
  tcp_sockets: HashMap<Token, TcpListener>,
  tcp_handlers: HashMap<Token, TcpHandler>,
  next_token: Cell<usize>,
  catalog: Arc<Catalog>, // should the catalog just be static?
}

impl Server {
  pub fn new(catalog: Catalog) -> Server {
    Server {
      udp_sockets: HashMap::new(),
      udp_requests: HashMap::new(),
      tcp_sockets: HashMap::new(),
      tcp_handlers: HashMap::new(),
      next_token: Cell::new(0),
      catalog: Arc::new(catalog),
    }
  }

  fn next_token(&self) -> Token {
    for _ in 0..100 {
      self.next_token.set(self.next_token.get()+1);
      let token: Token = Token(self.next_token.get());
      if self.tcp_sockets.contains_key(&token) { continue }
      else if self.tcp_handlers.contains_key(&token) { continue }
      else if self.udp_sockets.contains_key(&token) { continue }

      // ok, safe to use
      return token;
    }

    panic!("tried to get the next token 100 times, failed");
  }

  /// register a TcpListener to the Server. This should already be bound to either an IPv6 or an
  ///  IPv4 address.
  pub fn register_listener(&mut self, listener: TcpListener) {
    let token = self.next_token();
    self.tcp_sockets.insert(token, listener);
  }

  /// TODO how to do threads? should we do a bunch of listener threads and then query threads?
  /// Ideally the processing would be n-threads for recieving, which hand off to m-threads for
  ///  request handling. It would generally be the case that n <= m.
  pub fn listen(&mut self) -> io::Result<()> {
    info!("Server starting up");
    let mut event_loop: EventLoop<Self> = try!(EventLoop::new());

    for (ref token, ref socket) in &self.udp_sockets { try!(event_loop.register_opt(*socket, **token, EventSet::all(), PollOpt::level())); }
    for (ref token, ref socket) in &self.tcp_sockets { try!(event_loop.register_opt(*socket, **token, EventSet::all(), PollOpt::level())); }

    try!(event_loop.run(self));

    Err(io::Error::new(io::ErrorKind::Interrupted, "Server stopping due to interruption"))
  }
}

impl Handler for Server {
  type Timeout = Token; // Timeouts are registered with tokens.
  type Message = ();

  fn ready(&mut self, event_loop: &mut EventLoop<Self>, token: Token, events: EventSet) {
    let mut remove: Option<RemoveFrom> = None;

    if let Some(ref socket) = self.udp_sockets.get(&token) {

    } else if let Some(ref socket) = self.tcp_sockets.get(&token) {
      if events.is_error() { panic!("unexpected error state on: {:?}", socket) }
      else if events.is_hup() { panic!("listening socket hungup: {:?}", socket) }
      else if events.is_readable() || events.is_writable() {
        // there's a new connection coming in
        // give it a new token and insert the stream on the eventlistener
        // then store in the map for reference when dealing with new streams
        match socket.accept() {
          Ok(Some(stream)) => {
            let token = self.next_token();
            match event_loop.register_opt(&stream, token, !EventSet::writable(), PollOpt::level()) {
            //match event_loop.register_opt(&stream, token, EventSet::all(), PollOpt::level()) {
              Err(e) => error!("could not register stream: {:?} cause: {}", stream, e),
              Ok(()) => {
                info!("accepted tcp connection from: {:?} on {:?}", stream.peer_addr(), stream.local_addr().ok());
                self.tcp_handlers.insert(token, TcpHandler::new_server_handler(stream, self.catalog.clone()));
              }
            }
          },
          Ok(None) => return,
          Err(e) => panic!("unexpected error accepting: {}", e),
        }
      }
    } else if let Some(ref mut handler) = self.tcp_handlers.get_mut(&token) {
      if events.is_error() {
        warn!("closing error from: {:?}", handler);
        // TODO: do we need to shutdown the stream?
        remove = Some(RemoveFrom::TcpHandlers(token));
      } else if events.is_hup() {
        info!("client hungup: {:?}", handler);
        // TODO: do we need to shutdown the stream?
        remove = Some(RemoveFrom::TcpHandlers(token));
      } else if events.is_readable() || events.is_writable() {
        // the handler will deal with the rest of the connection, we need to check the return value
        //  for an error with wouldblock, this means that the handler couldn't complete the request.
        match handler.handle_message(events) {
          Ok(TcpState::Done) => {
            // reset, the client will close the connection according to the spec
            handler.reset();
          },
          Ok(..) => {
            // registering the event to only wake up on the correct event
            if let Err(e) = event_loop.reregister(handler.get_stream(), token, handler.get_events(), PollOpt::level()) {
              error!("could not reregister stream: {:?} cause: {}", handler.get_stream(), e);
              remove = Some(RemoveFrom::TcpHandlers(token));
            }
          },
          Err(ref e) if io::ErrorKind::WouldBlock == e.kind() => {
            // this is expected with the connection would block
            // noop
          },
          Err(e) => {
            // shutdown the connection, remove it.
            warn!("connection: {:?} shutdown on error: {}", handler, e);
            // TODO: do we need to shutdown the stream?
            remove = Some(RemoveFrom::TcpHandlers(token));
          }
        }
      }
    }

    // check if we need to remove something
    match remove {
      Some(RemoveFrom::TcpHandlers(t)) => { self.tcp_handlers.remove(&t); },
      Some(RemoveFrom::UdpRequests(t)) => { self.udp_requests.remove(&t); },
      None => (),
    }
  }

  fn interrupted(&mut self, event_loop: &mut EventLoop<Self>) {
    warn!("server interrupted, shutting down");
    event_loop.shutdown();
    //    self.error = Some(Err(io::Error::new(io::ErrorKind::Interrupted, format!("interrupted"))));
  }
}

enum RemoveFrom {
  TcpHandlers(Token),
  UdpRequests(Token),
}

#[cfg(test)]
mod server_tests {
  use std::thread;
  use ::tcp::Client;
  use mio::tcp::TcpListener;
  use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
  use ::authority::Catalog;
  use ::authority::authority_tests::create_example;
  use ::rr::*;
  use super::Server;
  use ::op::*;

  #[test]
  fn test_server_www() {
    let example = create_example();
    let origin = example.get_origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin.clone(), example);

    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127,0,0,1), 0));
    let tcp_listener = TcpListener::bind(&addr).unwrap();

    let ipaddr = tcp_listener.local_addr().unwrap();
    println!("tcp_listner on port: {}", ipaddr);

    let mut server = Server::new(catalog);
    server.register_listener(tcp_listener);

    /*let server_thread = */thread::Builder::new().name("test_server:server".to_string()).spawn(move || server_thread(server)).unwrap();
    let client_thread = thread::Builder::new().name("test_server:client".to_string()).spawn(move || client_thread_www(ipaddr)).unwrap();

    let client_result = client_thread.join();
    //    let server_result = server_thread.join();

    assert!(client_result.is_ok(), "client failed: {:?}", client_result);
    //    assert!(server_result.is_ok(), "server failed: {:?}", server_result);
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
