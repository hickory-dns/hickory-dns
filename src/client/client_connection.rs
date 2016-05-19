// Copyright (C) 2016 Benjamin Fry <benjaminfry@me.com>
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
use std::fmt::Debug;

use ::error::*;

pub trait ClientConnection: Sized+Debug {
  /// send the message to the specified address
  fn send(&mut self, bytes: Vec<u8>) -> ClientResult<Vec<u8>>;
  // TODO: split send and read...
}

#[cfg(test)]
pub mod test {
  use std::fmt;
  use super::*;
  use ::op::Message;
  use ::authority::Catalog;
  use ::serialize::binary::{BinDecoder, BinEncoder, BinSerializable};
  use ::error::*;

  pub struct TestClientConnection<'a> {
    catalog: &'a Catalog
  }

  impl<'a> TestClientConnection<'a> {
    pub fn new(catalog: &'a Catalog) -> TestClientConnection<'a> {
      TestClientConnection { catalog: catalog }
    }
  }

  impl<'a> ClientConnection for TestClientConnection<'a> {
    fn send(&mut self, bytes: Vec<u8>) -> ClientResult<Vec<u8>> {
      let mut decoder = BinDecoder::new(&bytes);

      let message = try!(Message::read(&mut decoder));
      let response = self.catalog.handle_request(&message);

      let mut buf = Vec::with_capacity(512);
      {
        let mut encoder = BinEncoder::new(&mut buf);
        try!(response.emit(&mut encoder));
      }

      Ok(buf)
    }
  }

  impl<'a> fmt::Debug for TestClientConnection<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
      write!(f, "TestClientConnection catalog")
    }
  }
}
