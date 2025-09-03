/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use alloc::{borrow::ToOwned, string::String, vec::Vec};

use thiserror::Error;

use crate::{rr::Name, serialize::binary::Restrict};

/// This is non-destructive to the inner buffer, b/c for pointer types we need to perform a reverse
///  seek to lookup names
///
/// A note on serialization, there was a thought to have this implement the Serde deserializer,
///  but given that this is such a small subset of all the serialization which that performs
///  this is a simpler implementation without the cruft, at least for serializing to/from the
///  binary DNS protocols.
pub struct BinDecoder<'a> {
    buffer: &'a [u8],    // The entire original buffer
    remaining: &'a [u8], // The unread section of the original buffer, so that reads do not cause a bounds check at the current seek offset
}

pub(crate) type DecodeResult<T> = Result<T, DecodeError>;

/// An error that can occur deep in a decoder
/// This type is kept very small so that function that use it inline often
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// DNS key protocol version doesn't have the expected version 3
    #[cfg(feature = "__dnssec")]
    #[error("dns key value unknown, must be 3: {0}")]
    DnsKeyProtocolNot3(u8),

    /// EDNS resource record label is not the root label, although required
    #[error("edns resource record label must be the root label (.): {0}")]
    EdnsNameNotRoot(Name),

    /// The length of rdata read was not as expected
    #[non_exhaustive]
    #[error("incorrect rdata length read: {read} expected: {len}")]
    IncorrectRDataLengthRead {
        /// The amount of read data
        read: usize,
        /// The expected length of the data
        len: usize,
    },

    /// Insufficient data in the buffer for a read operation
    #[error("unexpected end of input reached")]
    InsufficientBytes,

    /// slice_from was called with an invalid index
    #[error("the index passed to BinDecoder::slice_from must be greater than the decoder position")]
    InvalidPreviousIndex,

    /// Pointer points to an index within or after the current name
    #[error("label points to data not prior to idx: {idx} ptr: {ptr}")]
    PointerNotPriorToLabel {
        /// index of the label containing this pointer
        idx: usize,
        /// location to which the pointer is directing
        ptr: u16,
    },

    /// Label bytes exceeded the limit of 63
    #[error("label bytes exceed 63: {0}")]
    LabelBytesTooLong(usize),

    /// An unrecognized label code was found
    #[error("unrecognized label code: {0:b}")]
    UnrecognizedLabelCode(u8),

    /// A domain name was too long
    #[error("name label data exceed 255: {0}")]
    DomainNameTooLong(usize),

    /// Overlapping labels
    #[error("overlapping labels name {label} other {other}")]
    LabelOverlapsWithOther {
        /// Start of the label that is overlaps
        label: usize,
        /// Start of the other label
        other: usize,
    },

    /// An unknown digest algorithm was found
    #[error("unknown digest algorithm: {0}")]
    UnknownDigestAlgorithm(u8),

    /// An unknown dns class was found
    #[error("dns class string unknown: {0}")]
    UnknownDnsClassStr(String),

    /// An unknown dns class value was found
    #[error("dns class value unknown: {0}")]
    UnknownDnsClassValue(u16),

    /// An unknown record type string was found
    #[error("record type string unknown: {0}")]
    UnknownRecordTypeStr(String),

    /// An unknown record type value was found
    #[error("record type value unknown: {0}")]
    UnknownRecordTypeValue(u16),

    /// Unrecognized nsec3 flags were found
    #[error("nsec3 flags should be 0b0000000*: {0:b}")]
    UnrecognizedNsec3Flags(u8),

    /// Unrecognized csync flags were found
    #[error("csync flags should be 0b000000**: {0:b}")]
    UnrecognizedCsyncFlags(u16),

    /// An unknown algorithm type was found
    #[error("unknown NSEC3 hash algorithm: {0}")]
    UnknownNsec3HashAlgorithm(u8),
}

impl<'a> BinDecoder<'a> {
    /// Creates a new BinDecoder
    ///
    /// # Arguments
    ///
    /// * `buffer` - buffer from which all data will be read
    pub fn new(buffer: &'a [u8]) -> Self {
        BinDecoder {
            buffer,
            remaining: buffer,
        }
    }

    /// Pop one byte from the buffer
    pub fn pop(&mut self) -> DecodeResult<Restrict<u8>> {
        if let Some((first, remaining)) = self.remaining.split_first() {
            self.remaining = remaining;
            return Ok(Restrict::new(*first));
        }
        Err(DecodeError::InsufficientBytes)
    }

    /// Returns the number of bytes in the buffer
    ///
    /// ```
    /// use hickory_proto::serialize::binary::BinDecoder;
    ///
    /// let deadbeef = b"deadbeef";
    /// let mut decoder = BinDecoder::new(deadbeef);
    /// assert_eq!(decoder.len(), 8);
    /// decoder.read_slice(7).unwrap();
    /// assert_eq!(decoder.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        self.remaining.len()
    }

    /// Returns `true` if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Peed one byte forward, without moving the current index forward
    pub fn peek(&self) -> Option<Restrict<u8>> {
        Some(Restrict::new(*self.remaining.first()?))
    }

    /// Returns the current index in the buffer
    pub fn index(&self) -> usize {
        self.buffer.len() - self.remaining.len()
    }

    /// This is a pretty efficient clone, as the buffer is never cloned, and only the index is set
    ///  to the value passed in
    pub fn clone(&self, index_at: u16) -> Self {
        BinDecoder {
            buffer: self.buffer,
            remaining: &self.buffer[index_at as usize..],
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
    pub fn read_character_data(&mut self) -> DecodeResult<Restrict<&[u8]>> {
        let length = self.pop()?.unverified() as usize;
        self.read_slice(length)
    }

    /// Reads a Vec out of the buffer
    ///
    /// # Arguments
    ///
    /// * `len` - number of bytes to read from the buffer
    ///
    /// # Returns
    ///
    /// The Vec of the specified length, otherwise an error
    pub fn read_vec(&mut self, len: usize) -> DecodeResult<Restrict<Vec<u8>>> {
        self.read_slice(len).map(|s| s.map(ToOwned::to_owned))
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
    pub fn read_slice(&mut self, len: usize) -> DecodeResult<Restrict<&'a [u8]>> {
        if len > self.remaining.len() {
            return Err(DecodeError::InsufficientBytes);
        }
        let (read, remaining) = self.remaining.split_at(len);
        self.remaining = remaining;
        Ok(Restrict::new(read))
    }

    /// Reads a slice from a previous index to the current
    pub fn slice_from(&self, index: usize) -> DecodeResult<&'a [u8]> {
        if index > self.index() {
            return Err(DecodeError::InvalidPreviousIndex);
        }

        Ok(&self.buffer[index..self.index()])
    }

    /// Reads a byte from the buffer, equivalent to `Self::pop()`
    pub fn read_u8(&mut self) -> DecodeResult<Restrict<u8>> {
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
    pub fn read_u16(&mut self) -> DecodeResult<Restrict<u16>> {
        Ok(self
            .read_slice(2)?
            .map(|s| u16::from_be_bytes([s[0], s[1]])))
    }

    /// Reads the next four bytes into i32.
    ///
    /// This performs a byte-by-byte manipulation, there
    ///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
    ///
    /// # Return
    ///
    /// Return the i32 from the buffer
    pub fn read_i32(&mut self) -> DecodeResult<Restrict<i32>> {
        Ok(self.read_slice(4)?.map(|s| {
            assert!(s.len() == 4);
            i32::from_be_bytes([s[0], s[1], s[2], s[3]])
        }))
    }

    /// Reads the next four bytes into u32.
    ///
    /// This performs a byte-by-byte manipulation, there
    ///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
    ///
    /// # Return
    ///
    /// Return the u32 from the buffer
    pub fn read_u32(&mut self) -> DecodeResult<Restrict<u32>> {
        Ok(self.read_slice(4)?.map(|s| {
            assert!(s.len() == 4);
            u32::from_be_bytes([s[0], s[1], s[2], s[3]])
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_slice() {
        let deadbeef = b"deadbeef";
        let mut decoder = BinDecoder::new(deadbeef);

        let read = decoder.read_slice(4).expect("failed to read dead");
        assert_eq!(&read.unverified(), b"dead");

        let read = decoder.read_slice(2).expect("failed to read be");
        assert_eq!(&read.unverified(), b"be");

        let read = decoder.read_slice(0).expect("failed to read nothing");
        assert_eq!(&read.unverified(), b"");

        // this should fail
        assert!(decoder.read_slice(3).is_err());
    }

    #[test]
    fn test_read_slice_from() {
        let deadbeef = b"deadbeef";
        let mut decoder = BinDecoder::new(deadbeef);

        decoder.read_slice(4).expect("failed to read dead");
        let read = decoder.slice_from(0).expect("failed to get slice");
        assert_eq!(&read, b"dead");

        decoder.read_slice(2).expect("failed to read be");
        let read = decoder.slice_from(4).expect("failed to get slice");
        assert_eq!(&read, b"be");

        decoder.read_slice(0).expect("failed to read nothing");
        let read = decoder.slice_from(4).expect("failed to get slice");
        assert_eq!(&read, b"be");

        // this should fail
        assert!(decoder.slice_from(10).is_err());
    }
}
