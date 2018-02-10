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
use byteorder::{ByteOrder, NetworkEndian};
use std::marker::PhantomData;

use error::{ProtoErrorKind, ProtoResult};

use super::BinEncodable;

/// Encode DNS messages and resource record types.
pub struct BinEncoder<'a> {
    offset: usize,
    buffer: &'a mut Vec<u8>,
    /// start and end of label pointers, smallvec here?
    name_pointers: Vec<(usize, usize)>, 
    mode: EncodeMode,
    canonical_names: bool,
}

impl<'a> BinEncoder<'a> {
    /// Create a new encoder with the Vec to fill
    pub fn new(buf: &'a mut Vec<u8>) -> Self {
        Self::with_offset(buf, 0, EncodeMode::Normal)
    }

    /// Specify the mode for encoding
    ///
    /// # Arguments
    ///
    /// * `mode` - In Signing mode, it canonical forms of all data are encoded, otherwise format matches the source form
    pub fn with_mode(buf: &'a mut Vec<u8>, mode: EncodeMode) -> Self {
        Self::with_offset(buf, 0, mode)
    }

    /// Begins the encoder at the given offset
    ///
    /// This is used for pointers. If this encoder is starting at some point further in
    ///  the sequence of bytes, for the proper offset of the pointer, the offset accounts for that
    ///  by using the offset to add to the pointer location being written.
    ///
    /// # Arguments
    ///
    /// * `offset` - index at which to start writing into the buffer
    pub fn with_offset(buf: &'a mut Vec<u8>, offset: u32, mode: EncodeMode) -> Self {
        BinEncoder {
            offset: offset as usize,
            buffer: buf,
            name_pointers: Vec::new(),
            mode: mode,
            canonical_names: false,
        }
    }

    /// Returns a reference to the internal buffer
    pub fn into_bytes(self) -> &'a Vec<u8> {
        self.buffer
    }

    /// Returns the length of the buffer
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns `true` if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Returns the current offset into the buffer
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// sets the current offset to the new offset
    pub fn set_offset(&mut self, offset: usize) {
        self.offset = offset;
    }

    /// Returns the current Encoding mode
    pub fn mode(&self) -> EncodeMode {
        self.mode
    }

    /// If set to true, then names will be written into the buffer in canonical form
    pub fn set_canonical_names(&mut self, canonical_names: bool) {
        self.canonical_names = canonical_names;
    }

    /// Returns true if then encoder is writing in canonical form
    pub fn is_canonical_names(&self) -> bool {
        self.canonical_names
    }

    /// Reserve specified length in the internal buffer.
    pub fn reserve(&mut self, len: usize) {
        if self.buffer.capacity() - self.buffer.len() < len {
            self.buffer.reserve(512.max(len));
        }
    }

    /// trims to the current offset
    pub fn trim(&mut self) {
        let offset = self.offset;
        self.buffer.truncate(offset as usize);
        self.name_pointers.retain(|&(start, end)| start < offset && end <= offset);
    }

    /// Emit one byte into the buffer
    pub fn emit(&mut self, b: u8) -> ProtoResult<()> {
        if self.offset < self.buffer.len() {
            *self.buffer
                .get_mut(self.offset)
                .expect("could not get index at offset") = b;
        } else {
            self.buffer.push(b);
        }
        self.offset += 1;
        Ok(())
    }

    /// borrow a slice from the encoder
    pub fn slice_of(&self, start: usize, end: usize) -> &[u8] {
        assert!(start < self.offset);
        assert!(end <= self.buffer.len());
        &self.buffer[start..end]
    }

    /// Stores a label pointer to an already written label
    ///
    /// The location is the current position in the buffer
    ///  implicitly, it is expected that the name will be written to the stream after the current index.
    pub fn store_label_pointer(&mut self, start: usize, end: usize) {
        assert!(start <= (u16::max_value() as usize));
        assert!(end <= (u16::max_value() as usize));
        assert!(start <= end);
        if self.offset < 0x3FFF_usize {
            self.name_pointers.push((start, end)); // the next char will be at the len() location
        }
    }

    /// Looks up the index of an already written label
    pub fn get_label_pointer(&self, start: usize, end: usize) -> Option<u16> {
        let search = self.slice_of(start, end);

        for &(match_start, match_end) in &self.name_pointers {
            let matcher = self.slice_of(match_start as usize, match_end as usize);
            if matcher == search {
                assert!(match_start <= (u16::max_value() as usize)); 
                return Some(match_start as u16)
            }
        }
        
        None
    }

    /// matches description from above.
    ///
    /// ```
    /// use trust_dns_proto::serialize::binary::BinEncoder;
    ///
    /// let mut bytes: Vec<u8> = Vec::new();
    /// {
    ///   let mut encoder: BinEncoder = BinEncoder::new(&mut bytes);
    ///   encoder.emit_character_data("abc");
    /// }
    /// assert_eq!(bytes, vec![3,b'a',b'b',b'c']);
    /// ```
    pub fn emit_character_data<S: AsRef<[u8]>>(&mut self, char_data: S) -> ProtoResult<()> {
        let char_bytes = char_data.as_ref();
        if char_bytes.len() > 255 {
            return Err(ProtoErrorKind::CharacterDataTooLong(char_bytes.len()).into());
        }
        self.reserve(char_bytes.len() + 1); // reserve the full space for the string and length marker
        self.emit(char_bytes.len() as u8)?;
        self.write_slice(char_bytes);
        Ok(())
    }

    /// Emit one byte into the buffer
    pub fn emit_u8(&mut self, data: u8) -> ProtoResult<()> {
        self.emit(data)
    }

    /// Writes a u16 in network byte order to the buffer
    pub fn emit_u16(&mut self, data: u16) -> ProtoResult<()> {
        let mut bytes = [0; 2];
        {
            NetworkEndian::write_u16(&mut bytes, data);
        }
        self.write_slice(&bytes);
        Ok(())
    }

    /// Writes an i32 in network byte order to the buffer
    pub fn emit_i32(&mut self, data: i32) -> ProtoResult<()> {
        let mut bytes = [0; 4];
        {
            NetworkEndian::write_i32(&mut bytes, data);
        }
        self.write_slice(&bytes);
        Ok(())
    }

    /// Writes an u32 in network byte order to the buffer
    pub fn emit_u32(&mut self, data: u32) -> ProtoResult<()> {
        let mut bytes = [0; 4];
        {
            NetworkEndian::write_u32(&mut bytes, data);
        }
        self.write_slice(&bytes);
        Ok(())
    }

    fn write_slice(&mut self, data: &[u8]) {
        // replacement case, the necessary space should have been reserved already...
        if self.offset < self.buffer.len() {
            for b in data {
                *self.buffer
                  .get_mut(self.offset)
                  .expect("could not get index at offset for slice") = *b;
                self.offset += 1;
            }
        } else {
            self.buffer.extend_from_slice(data);
            self.offset += data.len();
        }
    }

    /// Writes the byte slice to the stream
    pub fn emit_vec(&mut self, data: &[u8]) -> ProtoResult<()> {
        self.write_slice(data);
        Ok(())
    }

    /// Emits all the elements of an Iterator to the encoder
    pub fn emit_all<'e, I: Iterator<Item = &'e E>, E: 'e + BinEncodable>(
        &mut self,
        iter: I,
    ) -> ProtoResult<()> {
        for i in iter {
            i.emit(self)?
        }
        Ok(())
    }

    /// Emits all the elements of an Iterator to the encoder
    pub fn emit_all_refs<'r, 'e, I, E>(&mut self, iter: I) -> ProtoResult<()>
    where
        'e: 'r,
        I: Iterator<Item = &'r &'e E>,
        E: 'r + 'e + BinEncodable,
    {
        for i in iter {
            i.emit(self)?
        }
        Ok(())
    }

    /// capture a location to write back to
    pub fn place<T: EncodedSize>(&mut self) -> Place<T> {
        let index = self.offset;
        let len = T::size_of();
 
        // resize the buffer
        self.buffer.resize(index + len, 0);

        // update the offset
        self.offset += len;

        Place {
            start_index: index,
            phantom: PhantomData,
        }
    }

    /// calculates the length of data written since the place was creating
    pub fn len_since_place<T: EncodedSize>(&self, place: &Place<T>) -> usize {
        (self.offset - place.start_index) - place.size_of()
    }

    /// write back to a previously captured location
    pub fn emit_at<T: EncodedSize>(&mut self, place: Place<T>, data: T) -> ProtoResult<()> {
        // preserve current index
        let current_index = self.offset;

        // reset the current index back to place before writing
        //   this is an assert because it's programming error for it to be wrong.
        assert!(place.start_index < current_index);
        self.offset = place.start_index;

        // emit the data to be written at this place
        let emit_result = data.emit(self);

        // double check that the current number of bytes were written
        //   this is an assert because it's programming error for it to be wrong.
        assert!((self.offset - place.start_index) == place.size_of());

        // reset to original location
        self.offset = current_index;

        emit_result
    }
}

/// A trait to return the size of a type as it will be encoded in DNS
///
/// it does not necessarily equal `std::mem::size_of`, though it might, especially for primitives
pub trait EncodedSize: BinEncodable {
    fn size_of() -> usize;
}

impl EncodedSize for u16 {
    fn size_of() -> usize {
        2
    }
}

#[must_use = "data must be written back to the place"]
pub struct Place<T: EncodedSize> {
    start_index: usize,
    phantom: PhantomData<T>,
}

impl<T: EncodedSize> Place<T> {
    pub fn replace(self, encoder: &mut BinEncoder, data: T) -> ProtoResult<()> {
        encoder.emit_at(self, data)
    }

    pub fn size_of(&self) -> usize {
        T::size_of()
    }
}

/// In the Verify mode there maybe some things which are encoded differently, e.g. SIG0 records
///  should not be included in the additional count and not in the encoded data when in Verify
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum EncodeMode {
    /// In signing mode records are written in canonical form
    Signing,
    /// Write records in standard format
    Normal,
}


#[cfg(test)]
mod tests {
    use op::Message;
    use serialize::binary::BinDecoder;
    use super::*;

    #[test]
    fn test_label_compression_regression() {
        // https://github.com/bluejekyll/trust-dns/issues/339
        /*
        ;; QUESTION SECTION:
        ;bluedot.is.autonavi.com.gds.alibabadns.com. IN AAAA

        ;; AUTHORITY SECTION:
        gds.alibabadns.com.     1799    IN      SOA     gdsns1.alibabadns.com. none. 2015080610 1800 600 3600 360
        */
        let data: Vec<u8> = vec![154, 50, 129, 128, 0, 1, 0, 0, 0, 1, 0, 1, 7, 98, 108, 117, 101, 100, 111, 116, 2, 105, 115, 8, 97, 117, 116, 111, 110, 97, 118, 105, 3, 99, 111, 109, 3, 103, 100, 115, 10, 97, 108, 105, 98, 97, 98, 97, 100, 110, 115, 3, 99, 111, 109, 0, 0, 28, 0, 1, 192, 36, 0, 6, 0, 1, 0, 0, 7, 7, 0, 35, 6, 103, 100, 115, 110, 115, 49, 192, 40, 4, 110, 111, 110, 101, 0, 120, 27, 176, 162, 0, 0, 7, 8, 0, 0, 2, 88, 0, 0, 14, 16, 0, 0, 1, 104, 0, 0, 41, 2, 0, 0, 0, 0, 0, 0, 0];

        let msg = Message::from_vec(&data).unwrap();
        msg.to_bytes().unwrap();
    }

    #[test]
    fn test_size_of() {
        assert_eq!(u16::size_of(), 2);
    }

    #[test]
    fn test_place() {
        let mut buf = vec![];
        {
            let mut encoder = BinEncoder::new(&mut buf);
            let place = encoder.place::<u16>();
            assert_eq!(place.size_of(), 2);
            assert_eq!(encoder.len_since_place(&place), 0);

            encoder.emit(42_u8).expect("failed 0");
            assert_eq!(encoder.len_since_place(&place), 1);

            encoder.emit(48_u8).expect("failed 1");
            assert_eq!(encoder.len_since_place(&place), 2);

            place
                .replace(&mut encoder, 4_u16)
                .expect("failed to replace");
            drop(encoder);
        }

        assert_eq!(buf.len(), 4);

        let mut decoder = BinDecoder::new(&buf);
        let written = decoder.read_u16().expect("cound not read u16");

        assert_eq!(written, 4);
    }
}
