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

//! UDP based DNS client

use std::mem;
use std::net::{SocketAddr, ToSocketAddrs};
use std::fmt;

use mio::udp::UdpSocket;
use mio::{Token, EventLoop, Handler, EventSet, PollOpt}; // not * b/c don't want confusion with std::net

use ::error::*;
use client::ClientConnection;

const RESPONSE: Token = Token(0);

/// UDP based DNS client
pub struct UdpClientConnection {
  name_server: SocketAddr,
  socket: Option<UdpSocket>,
  event_loop: EventLoop<Response>,
}

impl UdpClientConnection {
  /// Creates a new client connection.
  ///
  /// *Note* this has side affects of binding the socket to 0.0.0.0 and starting the listening
  ///        event_loop. Expect this to change in the future.
  ///
  /// # Arguments
  ///
  /// * `name_server` - address of the name server to use for queries
  pub fn new(name_server: SocketAddr) -> ClientResult<Self> {
    // client binds to all addresses... this shouldn't ever fail
    let zero_addr = ("0.0.0.0", 0).to_socket_addrs().expect("could not parse 0.0.0.0 address").
                                   next().expect("no addresses parsed from 0.0.0.0");

    let socket = try!(UdpSocket::bound(&zero_addr));
    let mut event_loop: EventLoop<Response> = try!(EventLoop::new());
    // TODO make the timeout configurable, 5 seconds is the dig default
    // TODO the error is private to mio, which makes this awkward...
    if event_loop.timeout_ms((), 5000).is_err() { return Err(ClientErrorKind::Message("error setting timer").into()) };
    // TODO: Linux requires a register before a reregister, reregister is needed b/c of OSX later
    //  ideally this would not be added to the event loop until the client connection request.
    try!(event_loop.register(&socket, RESPONSE, EventSet::readable(), PollOpt::all()));

    debug!("client event_loop created");

    Ok(UdpClientConnection{name_server: name_server, socket: Some(socket), event_loop: event_loop})
  }
}

impl ClientConnection for UdpClientConnection {
  fn send(&mut self, buffer: Vec<u8>) -> ClientResult<Vec<u8>> {
    debug!("client reregistering");
    // TODO: b/c of OSX this needs to be a reregister (since deregister is not working)
    try!(self.event_loop.reregister(self.socket.as_ref().expect("never none"), RESPONSE, EventSet::readable(), PollOpt::all()));
    debug!("client sending");
    try!(self.socket.as_ref().expect("never none").send_to(&buffer, &self.name_server));
    debug!("client sent data");

    let mut response: Response = Response::new(mem::replace(&mut self.socket, None).expect("never none"));

    // run_once should be enough, if something else nepharious hits the socket, what?
    try!(self.event_loop.run(&mut response));
    debug!("client event_loop running");


    if response.error.is_some() { return Err(response.error.unwrap()) }
    if response.buf.is_none() { return Err(ClientErrorKind::Message("no data was received from the remote").into()) }
    let result = Ok(response.buf.unwrap());
    //debug!("client deregistering");
    // TODO: when this line is added OSX starts failing, but we should have it...
    // try!(self.event_loop.deregister(&response.socket));
    self.socket = Some(response.socket);
    result
  }
}

impl fmt::Debug for UdpClientConnection {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "UdpClientConnection ns: {:?} socket: {:?}", self.name_server, self.socket)
  }
}

struct Response {
  pub buf: Option<Vec<u8>>,
  pub addr: Option<SocketAddr>,
  pub error: Option<ClientError>,
  pub socket: UdpSocket,
}

impl Response {
  pub fn new(socket: UdpSocket) -> Self {
    Response{ buf: None, addr: None, error: None, socket: socket }
  }
}

// TODO: this should be merged with the server handler
impl Handler for Response {
  type Timeout = ();
  type Message = ();

  fn ready(&mut self, event_loop: &mut EventLoop<Self>, token: Token, events: EventSet) {
    match token {
      RESPONSE => {
        if !events.is_readable() {
          debug!("got woken up, but not readable: {:?}", token);
          return
        }

        let mut buf: [u8; 4096] = [0u8; 4096];

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
          self.error = Some(ClientErrorKind::Message("no address received in response").into());
          return
        }

        // TODO: ignore if not from the IP that we requested
        let (length, addr) = recv_result.unwrap().unwrap();
        debug!("bytes: {:?} from: {:?}", length, addr);
        self.addr = Some(addr);

        if length == 0 {
          debug!("0 bytes recieved from: {}", addr);
          return
        }

        // we got our response, shutdown.
        event_loop.shutdown();

        // set our data
        self.buf = Some(buf.iter().take(length).cloned().collect());
      },
      _ => {
        error!("unrecognized token: {:?}", token);
        self.error = Some(ClientErrorKind::Message("no data was received from the remote").into());
      },
    }
  }

  fn timeout(&mut self, event_loop: &mut EventLoop<Self>, _: ()) {
    self.error = Some(ClientErrorKind::Message("timed out awaiting response from server(s)").into());
    event_loop.shutdown();
  }
}

// TODO: should test this independently of the client code
