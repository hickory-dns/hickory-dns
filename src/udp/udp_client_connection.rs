// Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use std::net::{SocketAddr, ToSocketAddrs};
use std::io::Cursor;

use mio::udp::UdpSocket;
use mio::{Token, EventLoop, Handler, EventSet, PollOpt}; // not * b/c don't want confusion with std::net

use ::error::*;
use client::ClientConnection;

const RESPONSE: Token = Token(0);

#[derive(Debug)]
pub struct UdpClientConnection {
  name_server: SocketAddr,
  socket: UdpSocket,
}

impl UdpClientConnection {
  pub fn new(name_server: SocketAddr) -> ClientResult<Self> {
    // client binds to all addresses... this shouldn't ever fail
    let zero_addr = ("0.0.0.0", 0).to_socket_addrs().expect("could not parse 0.0.0.0 address").
                                   next().expect("no addresses parsed from 0.0.0.0");

    let socket = try!(UdpSocket::bound(&zero_addr));
    Ok(UdpClientConnection{name_server: name_server, socket: socket})
  }
}

impl ClientConnection for UdpClientConnection {
  fn send(&mut self, buffer: &[u8]) -> ClientResult<Vec<u8>> {
    let mut bytes = Cursor::new(buffer);
    try!(self.socket.send_to(&mut bytes, &self.name_server));

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
    Ok(response.buf.unwrap())
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

// TODO: this should be merged with the server handler
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

// TODO: should test this independently of the client code
