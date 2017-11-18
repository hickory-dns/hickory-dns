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
use error::{ProtoErrorKind, ProtoResult};

/// This is non-destructive to the inner buffer, b/c for pointer types we need to perform a reverse
///  seek to lookup names
///
/// A note on serialization, there was a thought to have this implement the Serde deserializer,
///  but given that this is such a small subset of all the serialization which that performs
///  this is a simpler implementation without the cruft, at least for serializing to/from the
///  binary DNS protocols.
pub struct BinDecoder<'a> {
    buffer: &'a [u8],
    index: usize,
}

impl<'a> BinDecoder<'a> {
    /// Creates a new BinDecoder
    ///
    /// # Arguments
    ///
    /// * `buffer` - buffer from which all data will be read
    pub fn new(buffer: &'a [u8]) -> Self {
        BinDecoder {
            buffer: buffer,
            index: 0,
        }
    }

    /// Pop one byte from the buffer
    pub fn pop(&mut self) -> ProtoResult<u8> {
        if self.index < self.buffer.len() {
            let byte = self.buffer[self.index];
            self.index += 1;
            Ok(byte)
        } else {
            Err(
                ProtoErrorKind::Message("unexpected end of input reached").into(),
            )
        }
    }

    /// Returns the number of bytes in the buffer
    pub fn len(&self) -> usize {
        self.buffer.len() - self.index
    }

    /// Peed one byte forward, without moving the current index forward
    pub fn peek(&self) -> Option<u8> {
        if self.index < self.buffer.len() {
            Some(self.buffer[self.index])
        } else {
            None
        }
    }

    /// Returns the current index in the buffer
    pub fn index(&self) -> usize {
        return self.index;
    }

    /// This is a pretty efficient clone, as the buffer is never cloned, and only the index is set
    ///  to the value passed in
    pub fn clone(&self, index_at: u16) -> BinDecoder {
        BinDecoder {
            buffer: self.buffer,
            index: index_at as usize,
        }
    }

    /// Reads a String from the buffer
    ///
    /// ```text
    /// <character-string> is a single
    /// length octet followed by that number of characters.  <character-string>
    /// is treated as binary information, and can be up to 256 characters in
    /// length (including the length octet).
    /// ```
    ///
    /// # Returns
    ///
    /// A String version of the character data
    pub fn read_character_data(&mut self) -> ProtoResult<String> {
        let length: u8 = try!(self.pop());

        // TODO once Drain stabalizes on Vec, this should be replaced...
        let label_vec: Vec<u8> = try!(self.read_vec(length as usize));

        // translate bytes to string, then lowercase...
        let data = String::from_utf8(label_vec)?;

        Ok(data)
    }

    // TODO: deprecate in favor of read_slice
    /// Reads a Vec out of the buffer
    ///
    /// # Arguments
    ///
    /// * `len` - number of bytes to read from the buffer
    ///
    /// # Returns
    ///
    /// The Vec of the specified length, otherwise an error
    pub fn read_vec(&mut self, len: usize) -> ProtoResult<Vec<u8>> {
        // TODO once Drain stabalizes on Vec, this should be replaced...
        let mut vec: Vec<u8> = Vec::with_capacity(len);
        for _ in 0..len as usize {
            vec.push(try!(self.pop()))
        }

        Ok(vec)
    }

    /// Reads a slice out of the buffer, without allocating
    ///
    /// # Arguments
    ///
    /// * `len` - number of bytes to read from the buffer
    ///
    /// # Returns
    ///
    /// The slice of the specified length, otherwise an error
    pub fn read_slice(&mut self, len: usize) -> ProtoResult<&'a [u8]> {
        let end = self.index + len;
        if end > self.buffer.len() {
            return Err(ProtoErrorKind::Message("buffer exhausted").into())
        }

     
        let slice: &'a [u8] = &self.buffer[self.index .. end];
        self.index += len;
        Ok(slice)
    }

    /// Reads a byte from the buffer, equivalent to `Self::pop()`
    pub fn read_u8(&mut self) -> ProtoResult<u8> {
        self.pop()
    }

    /// Reads the next 2 bytes into u16
    ///
    /// This performs a byte-by-byte manipulation, there
    ///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
    ///
    /// # Return
    ///
    /// Return the u16 from the buffer
    pub fn read_u16(&mut self) -> ProtoResult<u16> {
        let b1: u8 = try!(self.pop());
        let b2: u8 = try!(self.pop());

        // translate from network byte order, i.e. big endian
        Ok(((b1 as u16) << 8) + (b2 as u16))
    }

    /// Reads the next four bytes into i32.
    ///
    /// This performs a byte-by-byte manipulation, there
    ///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
    ///
    /// # Return
    ///
    /// Return the i32 from the buffer
    pub fn read_i32(&mut self) -> ProtoResult<i32> {
        // TODO should this use a default rather than the panic! that will happen in the None case?
        let b1: u8 = try!(self.pop());
        let b2: u8 = try!(self.pop());
        let b3: u8 = try!(self.pop());
        let b4: u8 = try!(self.pop());

        // translate from network byte order, i.e. big endian
        Ok(
            ((b1 as i32) << 24) + ((b2 as i32) << 16) + ((b3 as i32) << 8) + (b4 as i32),
        )
    }

    /// Reads the next four bytes into u32.
    ///
    /// This performs a byte-by-byte manipulation, there
    ///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
    ///
    /// # Return
    ///
    /// Return the u32 from the buffer
    pub fn read_u32(&mut self) -> ProtoResult<u32> {
        // TODO should this use a default rather than the panic! that will happen in the None case?
        let b1: u8 = try!(self.pop());
        let b2: u8 = try!(self.pop());
        let b3: u8 = try!(self.pop());
        let b4: u8 = try!(self.pop());

        // translate from network byte order, i.e. big endian
        Ok(
            ((b1 as u32) << 24) + ((b2 as u32) << 16) + ((b3 as u32) << 8) + (b4 as u32),
        )
    }
}

#[cfg(tests)]
mod tests {
    use super::*;

    #[test]
    fn test_read_slice() {
        let deadbeef = b"deadbeef";
        let mut decoder = BinDecoder::new(deadbeef);

        let read = decoder.read_slice(4).expect("failed to read dead");
        assert_eq!(read, "dead");

        let read = decoder.read_slice(2).expect("failed to read be");
        assert_eq!(read, "be");

        let read = decoder.read_slice(0).expect("failed to read nothing");
        assert_eq!(read, "");

        // this should fail
        assert!(decoder.read_slice(3).is_err());
    }
}