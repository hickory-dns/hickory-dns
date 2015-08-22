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
 use ::error::{EncodeError, EncodeResult};


/// Encode DNS messages and resource record types.
pub struct BinEncoder {
  buffer: Vec<u8>,
}

impl BinEncoder {
  pub fn new() -> Self {
    BinEncoder { buffer: Vec::new() }
  }

  pub fn as_bytes(self) -> Vec<u8> {
    self.buffer
  }

  pub fn len(&self) -> usize {
    self.buffer.len()
  }

  pub fn reserve(&mut self, extra: usize) {
    self.buffer.reserve(extra);
  }

  pub fn emit(&mut self, b: u8) -> EncodeResult {
    self.buffer.push(b);
    Ok(())
  }

  /// matches description from above.
  ///
  /// ```
  /// use trust_dns::serialize::binary::encoder::BinEncoder;
  ///
  /// let mut encoder: BinEncoder = BinEncoder::new();
  /// encoder.emit_character_data("abc");
  /// assert_eq!(encoder.as_bytes(), vec![3,b'a',b'b',b'c']);
  /// ```
  pub fn emit_character_data(&mut self, char_data: &str) -> EncodeResult {
    let char_bytes = char_data.as_bytes();
    if char_bytes.len() > 255 { return Err(EncodeError::CharacterDataTooLong(char_bytes.len())) }

    self.buffer.reserve(char_bytes.len() + 1); // reserve the full space for the string and length marker
    self.buffer.push(char_bytes.len() as u8);

    // a separate writer isn't necessary for label since it's the same first byte that's being written

    // TODO use append() once it stabalizes
    for b in char_bytes {
      self.buffer.push(*b);
    }

    Ok(())
  }

  pub fn emit_u16(&mut self, data: u16) -> EncodeResult {
    self.buffer.reserve(2); // two bytes coming

    let b1: u8 = (data >> 8 & 0xFF) as u8;
    let b2: u8 = (data & 0xFF) as u8;

    self.buffer.push(b1);
    self.buffer.push(b2);

    Ok(())
  }


  pub fn emit_i32(&mut self, data: i32) -> EncodeResult {
    self.buffer.reserve(4); // four bytes coming...

    let b1: u8 = (data >> 24 & 0xFF) as u8;
    let b2: u8 = (data >> 16 & 0xFF) as u8;
    let b3: u8 = (data >> 8 & 0xFF) as u8;
    let b4: u8 = (data & 0xFF) as u8;

    self.buffer.push(b1);
    self.buffer.push(b2);
    self.buffer.push(b3);
    self.buffer.push(b4);

    Ok(())
  }


  pub fn emit_u32(&mut self, data: u32) -> EncodeResult {
    self.buffer.reserve(4); // four bytes coming...

    let b1: u8 = (data >> 24 & 0xFF) as u8;
    let b2: u8 = (data >> 16 & 0xFF) as u8;
    let b3: u8 = (data >> 8 & 0xFF) as u8;
    let b4: u8 = (data & 0xFF) as u8;

    self.buffer.push(b1);
    self.buffer.push(b2);
    self.buffer.push(b3);
    self.buffer.push(b4);

    Ok(())
  }
}
