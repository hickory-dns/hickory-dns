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
use std::net::SocketAddr;
use std::io;
use std::sync::Arc;

use mio::udp::UdpSocket;
use mio::EventSet;

use ::op::*;
use ::serialize::binary::*;

pub struct UdpHandler {
  state: UdpState,
  addr: SocketAddr,
  message: Message,
  buffer: Vec<u8>,
}

impl UdpHandler {
  pub fn new_client(server_addr: SocketAddr, request: Message) -> Self {
    let mut bytes: Vec<u8> = Vec::with_capacity(512);
    {
      let mut encoder: BinEncoder = BinEncoder::new(&mut bytes);
      request.emit(&mut encoder).unwrap(); // coding error if this panics (i think?)
    }

    UdpHandler{ state: UdpState::Writing, addr: server_addr, message: request, buffer: bytes}
  }

  pub fn new_server<H>(socket: &UdpSocket, catalog: Arc<H>) -> Option<Self> where H: RequestHandler {
    //let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut buf: [u8; 4096] = [0u8; 4096];
    let recv_result = socket.recv_from(&mut buf);

    match recv_result {
      Ok(Some((length, addr))) => {
        debug!("revieved {} bytes from {:?}", length, addr);
        let request = {
          let mut decoder = BinDecoder::new(&buf);
          Message::read(&mut decoder)
        };

        let response = match request {
          Err(ref decode_error) => {
            warn!("unable to decode request from client: {:?}: {}", addr, decode_error);
            Message::error_msg(0/* id is in the message... */, OpCode::Query/* right default? */, ResponseCode::FormErr)
          },
          Ok(ref req) => catalog.handle_request(req), // this is a buf if the unwrap() fails
        };

        // serialize the data for the response
        let buf = Self::serialize_msg(buf.iter().take(length).cloned().collect(), &response);

        // TODO: this is the easiest spot to do this, but is least useful to shorten
        //  also, it's not clear how useful a truncated response is for secure operations
        if buf.len() > request.unwrap().get_max_payload() as usize {
          // we must truncate the response
          let truncated_response = response.truncate();
          let buf = Self::serialize_msg(buf, &truncated_response);
          Some(UdpHandler{ state: UdpState::Writing, addr: addr, message: response, buffer: buf})
        } else {
          Some(UdpHandler{ state: UdpState::Writing, addr: addr, message: response, buffer: buf})
        }
      },
      Err(e) => {
        warn!("error recieving on socket {:?}: {}", socket, e);
        None
      }
      _ => None,
    }
  }

  pub fn remote_addr(&self) -> SocketAddr {
    self.addr
  }

  pub fn serialize_msg(mut buf: Vec<u8>, response: &Message) -> Vec<u8> {
    buf.clear();
    let encode_result = {
      let mut encoder:BinEncoder = BinEncoder::new(&mut buf);
      response.emit(&mut encoder)
    };

    if let Err(encode_error) = encode_result {
      // yes, dangerous, but errors are a much simpler message, so they should encode no problem
      //  otherwise we'll blow the stack, which is ok, there's something horribly wrong in that
      //  case with the code.
      error!("error encoding response to client: {}", encode_error);
      Self::serialize_msg(buf, &Message::error_msg(response.get_id(), response.get_op_code(), ResponseCode::ServFail))
    } else {
      buf
    }
  }

  pub fn handle_message(&self, socket: &UdpSocket, events: EventSet) -> io::Result<UdpState> {
    match self.state {
      UdpState::Reading => {
        unimplemented!();
      },
      UdpState::Writing => {
        if events.is_writable() {
          info!("sending message to: {} id: {} rcode: {:?}", self.addr, self.message.get_id(), self.message.get_response_code());
          match socket.send_to(&self.buffer, &self.addr) {
            Ok(..) => {
              Ok(UdpState::Done)
            },
            Err(ref e) if io::ErrorKind::WouldBlock == e.kind() => {
              Ok(UdpState::Writing)
            },
            Err(e) => {
              Err(e)
            }
          }
        } else {
          Ok(UdpState::Writing)
        }
      },
      UdpState::Done => panic!("This handler should have been removed or reset"), // valid panic, never should happen
    }
  }
}

pub enum UdpState {
  Reading,
  Writing,
  Done,
}
