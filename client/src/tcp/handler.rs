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
use std::io;
use std::io::{Write, Read};
use std::mem;

use mio::tcp::TcpStream;
use mio::EventSet; // not * b/c don't want confusion with std::net

pub struct TcpHandler {
  tcp_type: TcpType,
  state: TcpState,   // current state of the handler and stream, i.e. are we reading from the client? or writing back to it?
  buffer: Vec<u8>, // current location and buffer we are reading into or writing from
  stream: TcpStream,
}

impl TcpHandler {
  /// initializes this handler with the intention to write first
  pub fn new_client_handler(stream: TcpStream) -> Self {
    Self::new(TcpType::Client, TcpState::WillWriteLength, vec![], stream)
  }

  /// initializes this handler with the intention to read first
  pub fn new_server_handler(stream: TcpStream) -> Self {
    Self::new(TcpType::Server, TcpState::WillReadLength, Vec::with_capacity(512), stream)
  }

  fn new(tcp_type: TcpType, state: TcpState, buffer: Vec<u8>, stream: TcpStream) -> Self {
    TcpHandler{ tcp_type: tcp_type, state: state, buffer: buffer, stream: stream }
  }

  pub fn get_stream(&self) -> &TcpStream {
    &self.stream
  }

  pub fn get_events(&self) -> EventSet {
    Self::get_events_recurse(self.state, self.tcp_type)
  }

  pub fn set_buffer(&mut self, buffer: Vec<u8>) {
    self.buffer = buffer;
  }

  pub fn remove_buffer(&mut self) -> Vec<u8> {
    debug!("buffer: {}", self.buffer.len());
    let buf = mem::replace(&mut self.buffer, vec![]);
    debug!("buf: {}", buf.len());
    return buf;
  }

  pub fn get_buffer(&self) -> &[u8] {
    &self.buffer
  }

  pub fn get_buffer_mut(&mut self) -> &mut Vec<u8> {
    &mut self.buffer
  }

  #[inline(always)]
  fn get_events_recurse(state: TcpState, tcp_type: TcpType) -> EventSet {
    match state {
      TcpState::WillReadLength => !EventSet::writable(),
      TcpState::WillRead{ .. } => !EventSet::writable(),
      TcpState::WillWriteLength => !EventSet::readable(),
      TcpState::WillWrite => !EventSet::readable(),
      TcpState::Done => Self::get_events_recurse(TcpState::initial_state(tcp_type), tcp_type),
    }
  }

  /// The result may be an error case of ErrorKind::WouldBlock, which means that the handler
  ///  handler should be put back into the event loop for more processing.
  pub fn handle_message(&mut self, events: EventSet) -> io::Result<TcpState> {
    // This will loop forever, or until the transaction is done.
    loop {
      self.state = match self.state {
        TcpState::WillReadLength => {
          if events.is_readable() {
            // assuming we will always be able to read two bytes.
            let mut len_bytes: [u8;2] = [0u8;2];
            let len_read = try!((&mut self.stream).take(2).read(&mut len_bytes)) as u16;
            if len_read < 2 {
              debug!("did not read all len_bytes expected: 2 got: {:?} bytes from: {:?}", len_read, self.stream);
              return Err(io::Error::new(io::ErrorKind::InvalidData, "did not receive the length"));
            }

            let length = (len_bytes[0] as u16) << 8 & 0xFF00 | len_bytes[1] as u16 & 0x00FF;
            self.buffer.reserve(length as usize);
            self.buffer.clear();
            TcpState::WillRead{ length: length } // TODO clean up state change with param...
          } else {
            return Ok(self.state); // wrong socket state...
          }
        },
        TcpState::WillRead{ length } => {
          if events.is_readable() {
            // this will return if it would block with ErrKind::WouldBlock
            // TODO: add a TryTake to mio for doing the same thing as TryRead?
            try!((&mut self.stream).take((length as usize - self.buffer.len()) as u64).read_to_end(&mut self.buffer));

            // if we got all the bits...
            if self.buffer.len() == length as usize {
              self.state.next_state(self.tcp_type)
            } else {
              // still waiting on some more
              TcpState::WillRead { length: length }
            }
          } else {
            return Ok(self.state); // wrong socket state...
          }
        },
        TcpState::WillWriteLength => {
          if events.is_writable() {
            let len: [u8; 2] = [(self.buffer.len() >> 8 & 0xFF) as u8, (self.buffer.len() & 0xFF) as u8];
            let wrote: usize = try!(self.stream.write(&len));

            if wrote != 2 {
              return Err(io::Error::new(io::ErrorKind::InvalidData, "did not write the length"));
            }

            self.state.next_state(self.tcp_type)
          } else {
            return Ok(self.state); // wrong socket state...
          }
        },
        TcpState::WillWrite => {
          if events.is_writable() {
            let wrote: usize = try!(self.stream.write(&self.buffer));
            for _ in 0..wrote { self.buffer.pop(); } // adnvance the current position in the buffer
            if self.buffer.is_empty() { self.state.next_state(self.tcp_type) }
            else { TcpState::WillWrite }
          } else {
            return Ok(self.state); // wrong socket state...
          }
        },
        TcpState::Done => {
          return Ok(TcpState::Done);
        }
      };
    }
  }

  /// resets the state of the handler to perform more requests if desired.
  ///  clears the buffers and sets the state back to the initial state
  pub fn reset(&mut self) {
    self.state = TcpState::initial_state(self.tcp_type);
  }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum TcpState {
  WillReadLength, // waiting to recieve data
  WillRead{ length: u16 },  // length of the message to read
  WillWriteLength, // beginning of a response to the other side
  WillWrite, // length of the message to write
  Done,
}

impl TcpState {
  pub fn initial_state(tcp_type: TcpType) -> Self {
    match tcp_type {
      TcpType::Client => TcpState::WillWriteLength,
      TcpType::Server => TcpState::WillReadLength,
    }
  }

  pub fn next_state(&self, tcp_type: TcpType) -> Self {
    match *self {
      TcpState::WillReadLength => panic!("just use the enum constructor"),
      TcpState::WillRead {..} => match tcp_type {
        TcpType::Client => TcpState::Done, // Write (request) then Read (Response) then done
        TcpType::Server => TcpState::WillWriteLength, // Read (request) then Write (Response) then done
      },
      TcpState::WillWriteLength => TcpState::WillWrite,
      TcpState::WillWrite => match tcp_type {
        TcpType::Client => TcpState::WillReadLength, // Write (request) then Read (Response) then done
        TcpType::Server => TcpState::Done, // Read (request) then Write (Response) then done
      },
      TcpState::Done => TcpState::Done,
    }
  }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum TcpType {
  Client,
  Server,
}
