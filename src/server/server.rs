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

use mio::{Token, EventLoop, Handler, EventSet, PollOpt};
use mio::tcp::{TcpListener, TcpStream};
use mio::udp::UdpSocket;

use ::tcp;
use ::authority::Catalog;

pub struct Server {
  udp_sockets: HashMap<Token, UdpSocket>,
  tcp_sockets: HashMap<Token, TcpListener>,
  tcp_reading: HashMap<Token, (TcpStream, Vec<u8>)>,
  tcp_writing: HashMap<Token, (TcpStream, Vec<u8>)>,
  next_token: usize,
  catalog: Catalog,
}

impl Server {
  pub fn new(catalog: Catalog) -> Server {
    Server {
      udp_sockets: HashMap::new(),
      tcp_sockets: HashMap::new(),
      tcp_reading: HashMap::new(),
      tcp_writing: HashMap::new(),
      next_token: 0,
      catalog: catalog,
    }
  }

  fn next_token(&mut self) -> Token {
    for _ in 0..100 {
      self.next_token += 1;
      let token: Token = Token(self.next_token);
      if self.tcp_sockets.contains_key(&token) { continue }
      else if self.tcp_reading.contains_key(&token) { continue }
      else if self.tcp_writing.contains_key(&token) { continue }
      else if self.udp_sockets.contains_key(&token) { continue }

      // ok, safe to use
      return token;
    }

    panic!("tried to get the next token 100 times, failed");
  }

  /// register a TcpListener to the Server. This should already be bound to either an IPv6 or an
  ///  IPv4 address.
  pub fn register_listener(&mut self, listener: TcpListener) -> io::Result<()> {
    let token = self.next_token();
    self.tcp_sockets.insert(token, listener);
    Ok(())
  }

  /// TODO how to do threads? should we do a bunch of listener threads and then query threads?
  /// Ideally the processing would be n-threads for recieving, which hand off to m-threads for
  ///  request handling. It would generally be the case that n <= m.
  pub fn listen(&mut self) -> io::Result<()> {
    info!("Server starting up");
    let mut event_loop: EventLoop<Self> = try!(EventLoop::new());

    for (ref token, ref socket) in &self.udp_sockets { try!(event_loop.register_opt(*socket, **token, EventSet::readable(), PollOpt::level())); }
    for (ref token, ref socket) in &self.tcp_sockets { try!(event_loop.register_opt(*socket, **token, EventSet::readable(), PollOpt::level())); }

    try!(event_loop.run(self));

    Err(io::Error::new(io::ErrorKind::Interrupted, "Server stopping due to interruption"))
  }
}

impl Handler for Server {
  type Timeout = ();
  type Message = ();

  fn ready(&mut self, _: &mut EventLoop<Self>, token: Token, events: EventSet) {

    if let Some(ref socket) = self.udp_sockets.get(&token) {

    } else if let Some(ref socket) = self.tcp_sockets.get(&token) {

    } else if let Some(ref reader) = self.tcp_reading.get(&token) {

    } else if let Some(ref writer) = self.tcp_writing.get(&token) {

    }

    unreachable!("unrecognized token: {}", token.as_usize());

    // match token {
    //
    //   SERVER => {
    //     if !events.is_readable() {
    //       debug!("got woken up, but not readable: {:?}", token);
    //       return;
    //     }
    //
    //     // it would great to have a pool of buffers, more efficient.
    //     let mut buf: Vec<u8> = Vec::with_capacity(4096);
    //
    //     let recv_result = self.socket.recv_from(&mut buf);
    //     if recv_result.is_err() {
    //       warn!("could not recv_from on {:?}: {:?}", self.socket, recv_result);
    //       return
    //     }
    //
    //     if recv_result.as_ref().unwrap().is_none() {
    //       warn!("no return address on recv_from: {:?}", self.socket);
    //       return
    //     }
    //
    //     let addr = recv_result.unwrap().unwrap();
    //     info!("bytes: {:?} from: {:?}", buf.len(), addr);
    //
    //     self.handle_message(addr, buf);
    //   },
    //   _ => {
    //     error!("unrecognized token: {:?}", token);
    //     self.error = Some(Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{:?} InvalidInput", self.socket))));
    //   },
    // }
  }

  fn interrupted(&mut self, event_loop: &mut EventLoop<Self>) {
    warn!("server interrupted, shutting down");
    event_loop.shutdown();
    //    self.error = Some(Err(io::Error::new(io::ErrorKind::Interrupted, format!("interrupted"))));
  }
}
