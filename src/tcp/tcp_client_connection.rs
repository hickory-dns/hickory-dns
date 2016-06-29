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

//! TCP based DNS client

use std::net::SocketAddr;
use std::io;
use std::io::Write;
use std::mem;
use std::fmt;

use mio::tcp::TcpStream;
use mio::{Token, EventLoop, Handler, EventSet, PollOpt}; // not * b/c don't want confusion with std::net

use ::error::*;
use ::client::ClientConnection;
use ::tcp::{TcpHandler, TcpState};

const RESPONSE: Token = Token(0);

/// TCP based DNS client
pub struct TcpClientConnection {
  handler: Option<TcpHandler>,
  event_loop: EventLoop<ClientHandler>,
  error: Option<ClientError>,
}

impl TcpClientConnection {
  /// Creates a new client connection.
  ///
  /// *Note* this has side affects of establishing the connection to the specified DNS server and
  ///        starting the event_loop. Expect this to change in the future.
  ///
  /// # Arguments
  ///
  /// * `name_server` - address of the name server to use for queries
  pub fn new(name_server: SocketAddr) -> ClientResult<Self> {
    // TODO: randomize local port binding issue #23
    //  probably not necessary for TCP...
    debug!("connecting to {:?}", name_server);
    let stream = try!(TcpStream::connect(&name_server));

    let mut event_loop: EventLoop<ClientHandler> = try!(EventLoop::new());
    // TODO make the timeout configurable, 5 seconds is the dig default
    // TODO the error is private to mio, which makes this awkward...
    if event_loop.timeout_ms((), 5000).is_err() { return Err(ClientErrorKind::Message("error setting timer").into()) };
    // TODO: Linux requires a register before a reregister, reregister is needed b/c of OSX later
    //  ideally this would not be added to the event loop until the client connection request.
    try!(event_loop.register(&stream, RESPONSE, EventSet::all(), PollOpt::all()));

    Ok(TcpClientConnection{ handler: Some(TcpHandler::new_client_handler(stream)), event_loop: event_loop, error: None })
  }
}

impl ClientConnection for TcpClientConnection {
  fn send(&mut self, buffer: Vec<u8> ) -> ClientResult<Vec<u8>> {
    self.error = None;
    // TODO: b/c of OSX this needs to be a reregister (since deregister is not working)
    // ideally it should be a register with the later deregister...
    try!(self.event_loop.reregister(self.handler.as_ref().expect("never none").get_stream(), RESPONSE, EventSet::all(), PollOpt::all()));
    // this is the request message, needs to be set each time
    // TODO: it would be cool to reuse this buffer.
    let mut handler = mem::replace(&mut self.handler, None).expect("never none");
    handler.set_buffer(buffer);
    let mut client_handler = ClientHandler{ handler: handler, error: None };
    let result = self.event_loop.run(&mut client_handler);
    self.handler = Some(client_handler.handler);

    try!(result);

    if self.error.is_some() { return Err(mem::replace(&mut self.error, None).unwrap()) }
    Ok(self.handler.as_mut().expect("never none").remove_buffer())
    //debug!("client deregistering");
    // TODO: when this line is added OSX starts failing, but we should have it...
//    try!(self.event_loop.deregister(&response.stream));
  }
}

impl fmt::Debug for TcpClientConnection {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "TcpClientConnection: {:?}", self.handler.as_ref().expect("never none").get_stream())
  }
}

struct ClientHandler {
  pub handler: TcpHandler,
  pub error: Option<ClientError>,
}

// TODO: this should be merged with the server handler
impl Handler for ClientHandler {
  type Timeout = ();
  type Message = ();

  fn ready(&mut self, event_loop: &mut EventLoop<Self>, token: Token, events: EventSet) {
    match token {
      RESPONSE => {
        if events.is_error() {
          warn!("closing, error from: {:?}", self.handler.get_stream());
          // TODO: do we need to shutdown the stream?
          event_loop.shutdown();
        } else if events.is_hup() {
          info!("client hungup: {:?}", self.handler.get_stream());
          // TODO: do we need to shutdown the stream?
          //remove = Some(RemoveFrom::TcpHandlers(token));
          event_loop.shutdown();
        } else if events.is_readable() || events.is_writable() {
          // the handler will deal with the rest of the connection, we need to check the return value
          //  for an error with wouldblock, this means that the handler couldn't complete the request.
          match self.handler.handle_message(events) {
            Ok(TcpState::Done) => {
              // the shutdown will stop the event_loop run to return the requester
              self.handler.reset();
              event_loop.shutdown();
            },
            Ok(..) => {
              // registering the event to only wake up on the correct event
              //  this reduces looping on states like writable that can remain set for a long time
              //if let Err(e) = event_loop.reregister(handler.get_stream(), token, handler.get_events(), PollOpt::level()) {
              debug!("reregistering for next call: {:?}", self.handler.get_events());
              if let Err(e) = event_loop.reregister(self.handler.get_stream(), token, self.handler.get_events(), PollOpt::all()) {
                  error!("could not reregister stream: {:?} cause: {}", self.handler.get_stream(), e);
                  // TODO: need to return an error here
                  //remove = Some(RemoveFrom::TcpHandlers(token));
              }
            },
            Err(ref e) if io::ErrorKind::WouldBlock == e.kind() => {
              // this is expected with the connection would block
              // noop
            },
            Err(e) => {
              // shutdown the connection, remove it.
              warn!("connection: {:?} shutdown on error: {}", self.handler.get_stream(), e);
              // TODO: do we need to shutdown the stream?
              //remove = Some(RemoveFrom::TcpHandlers(token));
              // TODO: need to return an error here
              //self.error = Some(e);
              event_loop.shutdown();
            }
          }
        }
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
