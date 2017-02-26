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
use error::{DecodeErrorKind, DecodeResult};

/// This is non-destructive to the inner buffer, b/c for pointer types we need to perform a reverse
///  seek to lookup names
///
/// A note on serialization, there was a thought to have this implement the rustc-serialization,
///  but given that this is such a small subset of all the serialization which that performs
///  this is a simpler implementation without the cruft, at least for serializing to/from the
///  binary DNS protocols. rustc-serialization will be used for other coms, e.g. json over http
pub struct BinDecoder<'a> {
    buffer: &'a [u8],
    index: usize,
}

impl<'a> BinDecoder<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        BinDecoder {
            buffer: buffer,
            index: 0,
        }
    }

    pub fn pop(&mut self) -> DecodeResult<u8> {
        if self.index < self.buffer.len() {
            let byte = self.buffer[self.index];
            self.index += 1;
            Ok(byte)
        } else {
            Err(DecodeErrorKind::Message("unexpected end of input reached").into())
        }
    }

    pub fn len(&self) -> usize {
        self.buffer.len() - self.index
    }

    pub fn peek(&self) -> Option<u8> {
        if self.index < self.buffer.len() {
            Some(self.buffer[self.index])
        } else {
            None
        }
    }

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

    ///<character-string> is a single
    /// length octet followed by that number of characters.  <character-string>
    /// is treated as binary information, and can be up to 256 characters in
    /// length (including the length octet).
    ///
    /// the vector should be reversed before calling.
    pub fn read_character_data(&mut self) -> DecodeResult<String> {
        let length: u8 = try!(self.pop());

        // TODO once Drain stabalizes on Vec, this should be replaced...
        let label_vec: Vec<u8> = try!(self.read_vec(length as usize));

        // translate bytes to string, then lowercase...
        let data = try!(String::from_utf8(label_vec));

        Ok(data)
    }

    pub fn read_vec(&mut self, len: usize) -> DecodeResult<Vec<u8>> {
        // TODO once Drain stabalizes on Vec, this should be replaced...
        let mut vec: Vec<u8> = Vec::with_capacity(len);
        for _ in 0..len as usize {
            vec.push(try!(self.pop()))
        }

        Ok(vec)
    }

    pub fn read_u8(&mut self) -> DecodeResult<u8> {
        self.pop()
    }

    /// parses the next 2 bytes into u16. This performs a byte-by-byte manipulation, there
    ///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
    ///
    /// the vector should be reversed before calling.
    pub fn read_u16(&mut self) -> DecodeResult<u16> {
        let b1: u8 = try!(self.pop());
        let b2: u8 = try!(self.pop());

        // translate from network byte order, i.e. big endian
        Ok(((b1 as u16) << 8) + (b2 as u16))
    }

    /// parses the next four bytes into i32. This performs a byte-by-byte manipulation, there
    ///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
    ///
    /// the vector should be reversed before calling.
    pub fn read_i32(&mut self) -> DecodeResult<i32> {
        // TODO should this use a default rather than the panic! that will happen in the None case?
        let b1: u8 = try!(self.pop());
        let b2: u8 = try!(self.pop());
        let b3: u8 = try!(self.pop());
        let b4: u8 = try!(self.pop());

        // translate from network byte order, i.e. big endian
        Ok(((b1 as i32) << 24) + ((b2 as i32) << 16) + ((b3 as i32) << 8) + (b4 as i32))
    }

    /// parses the next four bytes into u32. This performs a byte-by-byte manipulation, there
    ///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
    ///
    /// the vector should be reversed before calling.
    pub fn read_u32(&mut self) -> DecodeResult<u32> {
        // TODO should this use a default rather than the panic! that will happen in the None case?
        let b1: u8 = try!(self.pop());
        let b2: u8 = try!(self.pop());
        let b3: u8 = try!(self.pop());
        let b4: u8 = try!(self.pop());

        // translate from network byte order, i.e. big endian
        Ok(((b1 as u32) << 24) + ((b2 as u32) << 16) + ((b3 as u32) << 8) + (b4 as u32))
    }
}
