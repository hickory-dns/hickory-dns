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

    if let Err(decode_error) = request {
      warn!("unable to decode request from client: {:?}: {}", addr, decode_error);
      self.send_to(addr, Catalog::error_msg(0/* id is in the message... */, OpCode::Query/* right default? */, ResponseCode::FormErr));
    } else {
      let request = request.unwrap(); // unwrap the Ok()
      let response = self.catalog.handle_request(request);
      self.send_to(addr, response);
    }
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
      self.send_to(addr, Catalog::error_msg(response.get_id(), response.get_op_code(), ResponseCode::ServFail));
    } else {
      info!("sending message to: {} id: {} rcode: {:?}", addr, response.get_id(), response.get_response_code());
      let mut bytes = Cursor::new(encoder.as_bytes());
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
