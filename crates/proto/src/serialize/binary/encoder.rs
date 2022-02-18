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
use std::marker::PhantomData;

use crate::error::{ProtoErrorKind, ProtoResult};

use super::BinEncodable;
use crate::op::Header;

// this is private to make sure there is no accidental access to the inner buffer.
mod private {
    use crate::error::{ProtoErrorKind, ProtoResult};

    /// A wrapper for a buffer that guarantees writes never exceed a defined set of bytes
    pub(crate) struct MaximalBuf<'a> {
        max_size: usize,
        buffer: &'a mut Vec<u8>,
    }

    impl<'a> MaximalBuf<'a> {
        pub(crate) fn new(max_size: u16, buffer: &'a mut Vec<u8>) -> Self {
            MaximalBuf {
                max_size: max_size as usize,
                buffer,
            }
        }

        /// Sets the maximum size to enforce
        pub(crate) fn set_max_size(&mut self, max: u16) {
            self.max_size = max as usize;
        }

        /// returns an error if the maximum buffer size would be exceeded with the addition number of elements
        ///
        /// and reserves the additional space in the buffer
        pub(crate) fn enforced_write<F>(&mut self, additional: usize, writer: F) -> ProtoResult<()>
        where
            F: FnOnce(&mut Vec<u8>),
        {
            let expected_len = self.buffer.len() + additional;

            if expected_len > self.max_size {
                Err(ProtoErrorKind::MaxBufferSizeExceeded(self.max_size).into())
            } else {
                self.buffer.reserve(additional);
                writer(self.buffer);

                debug_assert_eq!(self.buffer.len(), expected_len);
                Ok(())
            }
        }

        /// truncates are always safe
        pub(crate) fn truncate(&mut self, len: usize) {
            self.buffer.truncate(len)
        }

        /// returns the length of the underlying buffer
        pub(crate) fn len(&self) -> usize {
            self.buffer.len()
        }

        /// Immutable reads are always safe
        pub(crate) fn buffer(&'a self) -> &'a [u8] {
            self.buffer as &'a [u8]
        }

        /// Returns a reference to the internal buffer
        pub(crate) fn into_bytes(self) -> &'a Vec<u8> {
            self.buffer
        }
    }
}

/// Encode DNS messages and resource record types.
pub struct BinEncoder<'a> {
    offset: usize,
    buffer: private::MaximalBuf<'a>,
    /// start of label pointers with their labels in fully decompressed form for easy comparison, smallvec here?
    name_pointers: Vec<(usize, Vec<u8>)>,
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
    /// * `mode` - In Signing mode, canonical forms of all data are encoded, otherwise format matches the source form
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
        if buf.capacity() < 512 {
            let reserve = 512 - buf.capacity();
            buf.reserve(reserve);
        }

        BinEncoder {
            offset: offset as usize,
            // TODO: add max_size to signature
            buffer: private::MaximalBuf::new(u16::max_value(), buf),
            name_pointers: Vec::new(),
            mode,
            canonical_names: false,
        }
    }

    // TODO: move to constructor (kept for backward compatibility)
    /// Sets the maximum size of the buffer
    ///
    /// DNS message lens must be smaller than u16::max_value due to hard limits in the protocol
    ///
    /// *this method will move to the constructor in a future release*
    pub fn set_max_size(&mut self, max: u16) {
        self.buffer.set_max_size(max);
    }

    /// Returns a reference to the internal buffer
    pub fn into_bytes(self) -> &'a Vec<u8> {
        self.buffer.into_bytes()
    }

    /// Returns the length of the buffer
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns `true` if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.buffer().is_empty()
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

    /// Emit all names in canonical form, useful for <https://tools.ietf.org/html/rfc3597>
    pub fn with_canonical_names<F: FnOnce(&mut Self) -> ProtoResult<()>>(
        &mut self,
        f: F,
    ) -> ProtoResult<()> {
        let was_canonical = self.is_canonical_names();
        self.set_canonical_names(true);

        let res = f(self);
        self.set_canonical_names(was_canonical);

        res
    }

    // TODO: deprecate this...
    /// Reserve specified additional length in the internal buffer.
    pub fn reserve(&mut self, _additional: usize) -> ProtoResult<()> {
        Ok(())
    }

    /// trims to the current offset
    pub fn trim(&mut self) {
        let offset = self.offset;
        self.buffer.truncate(offset);
        self.name_pointers.retain(|&(start, _)| start < offset);
    }

    // /// returns an error if the maximum buffer size would be exceeded with the addition number of elements
    // ///
    // /// and reserves the additional space in the buffer
    // fn enforce_size(&mut self, additional: usize) -> ProtoResult<()> {
    //     if (self.buffer.len() + additional) > self.max_size {
    //         Err(ProtoErrorKind::MaxBufferSizeExceeded(self.max_size).into())
    //     } else {
    //         self.reserve(additional);
    //         Ok(())
    //     }
    // }

    /// borrow a slice from the encoder
    pub fn slice_of(&self, start: usize, end: usize) -> &[u8] {
        assert!(start < self.offset);
        assert!(end <= self.buffer.len());
        &self.buffer.buffer()[start..end]
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
            self.name_pointers
                .push((start, self.slice_of(start, end).to_vec())); // the next char will be at the len() location
        }
    }

    /// Looks up the index of an already written label
    pub fn get_label_pointer(&self, start: usize, end: usize) -> Option<u16> {
        let search = self.slice_of(start, end);

        for (match_start, matcher) in &self.name_pointers {
            if matcher.as_slice() == search {
                assert!(match_start <= &(u16::max_value() as usize));
                return Some(*match_start as u16);
            }
        }

        None
    }

    /// Emit one byte into the buffer
    pub fn emit(&mut self, b: u8) -> ProtoResult<()> {
        if self.offset < self.buffer.len() {
            let offset = self.offset;
            self.buffer.enforced_write(0, |buffer| {
                *buffer
                    .get_mut(offset)
                    .expect("could not get index at offset") = b
            })?;
        } else {
            self.buffer.enforced_write(1, |buffer| buffer.push(b))?;
        }
        self.offset += 1;
        Ok(())
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
            return Err(ProtoErrorKind::CharacterDataTooLong {
                max: 255,
                len: char_bytes.len(),
            }
            .into());
        }

        // first the length is written
        self.emit(char_bytes.len() as u8)?;
        self.write_slice(char_bytes)
    }

    /// Emit one byte into the buffer
    pub fn emit_u8(&mut self, data: u8) -> ProtoResult<()> {
        self.emit(data)
    }

    /// Writes a u16 in network byte order to the buffer
    pub fn emit_u16(&mut self, data: u16) -> ProtoResult<()> {
        self.write_slice(&data.to_be_bytes())
    }

    /// Writes an i32 in network byte order to the buffer
    pub fn emit_i32(&mut self, data: i32) -> ProtoResult<()> {
        self.write_slice(&data.to_be_bytes())
    }

    /// Writes an u32 in network byte order to the buffer
    pub fn emit_u32(&mut self, data: u32) -> ProtoResult<()> {
        self.write_slice(&data.to_be_bytes())
    }

    fn write_slice(&mut self, data: &[u8]) -> ProtoResult<()> {
        // replacement case, the necessary space should have been reserved already...
        if self.offset < self.buffer.len() {
            let offset = self.offset;

            self.buffer.enforced_write(0, |buffer| {
                let mut offset = offset;
                for b in data {
                    *buffer
                        .get_mut(offset)
                        .expect("could not get index at offset for slice") = *b;
                    offset += 1;
                }
            })?;
        } else {
            self.buffer
                .enforced_write(data.len(), |buffer| buffer.extend_from_slice(data))?;
        }

        self.offset += data.len();

        Ok(())
    }

    /// Writes the byte slice to the stream
    pub fn emit_vec(&mut self, data: &[u8]) -> ProtoResult<()> {
        self.write_slice(data)
    }

    /// Emits all the elements of an Iterator to the encoder
    pub fn emit_all<'e, I: Iterator<Item = &'e E>, E: 'e + BinEncodable>(
        &mut self,
        mut iter: I,
    ) -> ProtoResult<usize> {
        self.emit_iter(&mut iter)
    }

    // TODO: dedup with above emit_all
    /// Emits all the elements of an Iterator to the encoder
    pub fn emit_all_refs<'r, 'e, I, E>(&mut self, iter: I) -> ProtoResult<usize>
    where
        'e: 'r,
        I: Iterator<Item = &'r &'e E>,
        E: 'r + 'e + BinEncodable,
    {
        let mut iter = iter.cloned();
        self.emit_iter(&mut iter)
    }

    /// emits all items in the iterator, return the number emitted
    #[allow(clippy::needless_return)]
    pub fn emit_iter<'e, I: Iterator<Item = &'e E>, E: 'e + BinEncodable>(
        &mut self,
        iter: &mut I,
    ) -> ProtoResult<usize> {
        let mut count = 0;
        for i in iter {
            let rollback = self.set_rollback();
            i.emit(self).map_err(|e| {
                if let ProtoErrorKind::MaxBufferSizeExceeded(_) = e.kind() {
                    rollback.rollback(self);
                    return ProtoErrorKind::NotAllRecordsWritten { count }.into();
                } else {
                    return e;
                }
            })?;
            count += 1;
        }
        Ok(count)
    }

    /// capture a location to write back to
    pub fn place<T: EncodedSize>(&mut self) -> ProtoResult<Place<T>> {
        let index = self.offset;
        let len = T::size_of();

        // resize the buffer
        self.buffer
            .enforced_write(len, |buffer| buffer.resize(index + len, 0))?;

        // update the offset
        self.offset += len;

        Ok(Place {
            start_index: index,
            phantom: PhantomData,
        })
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

    fn set_rollback(&self) -> Rollback {
        Rollback {
            rollback_index: self.offset(),
        }
    }
}

/// A trait to return the size of a type as it will be encoded in DNS
///
/// it does not necessarily equal `std::mem::size_of`, though it might, especially for primitives
pub trait EncodedSize: BinEncodable {
    /// Return the size in bytes of the
    fn size_of() -> usize;
}

impl EncodedSize for u16 {
    fn size_of() -> usize {
        2
    }
}

impl EncodedSize for Header {
    fn size_of() -> usize {
        Self::len()
    }
}

#[derive(Debug)]
#[must_use = "data must be written back to the place"]
pub struct Place<T: EncodedSize> {
    start_index: usize,
    phantom: PhantomData<T>,
}

impl<T: EncodedSize> Place<T> {
    pub fn replace(self, encoder: &mut BinEncoder<'_>, data: T) -> ProtoResult<()> {
        encoder.emit_at(self, data)
    }

    pub fn size_of(&self) -> usize {
        T::size_of()
    }
}

/// A type representing a rollback point in a stream
pub(crate) struct Rollback {
    rollback_index: usize,
}

impl Rollback {
    pub(crate) fn rollback(self, encoder: &mut BinEncoder<'_>) {
        encoder.set_offset(self.rollback_index)
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
    use std::str::FromStr;

    use super::*;
    use crate::{
        op::{Message, Query},
        rr::{rdata::SRV, RData, Record, RecordType},
    };
    use crate::{rr::Name, serialize::binary::BinDecoder};

    #[test]
    fn test_label_compression_regression() {
        // https://github.com/bluejekyll/trust-dns/issues/339
        /*
        ;; QUESTION SECTION:
        ;bluedot.is.autonavi.com.gds.alibabadns.com. IN AAAA

        ;; AUTHORITY SECTION:
        gds.alibabadns.com.     1799    IN      SOA     gdsns1.alibabadns.com. none. 2015080610 1800 600 3600 360
        */
        let data: Vec<u8> = vec![
            154, 50, 129, 128, 0, 1, 0, 0, 0, 1, 0, 1, 7, 98, 108, 117, 101, 100, 111, 116, 2, 105,
            115, 8, 97, 117, 116, 111, 110, 97, 118, 105, 3, 99, 111, 109, 3, 103, 100, 115, 10,
            97, 108, 105, 98, 97, 98, 97, 100, 110, 115, 3, 99, 111, 109, 0, 0, 28, 0, 1, 192, 36,
            0, 6, 0, 1, 0, 0, 7, 7, 0, 35, 6, 103, 100, 115, 110, 115, 49, 192, 40, 4, 110, 111,
            110, 101, 0, 120, 27, 176, 162, 0, 0, 7, 8, 0, 0, 2, 88, 0, 0, 14, 16, 0, 0, 1, 104, 0,
            0, 41, 2, 0, 0, 0, 0, 0, 0, 0,
        ];

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
            let place = encoder.place::<u16>().unwrap();
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
        let written = decoder.read_u16().expect("cound not read u16").unverified();

        assert_eq!(written, 4);
    }

    #[test]
    fn test_max_size() {
        let mut buf = vec![];
        let mut encoder = BinEncoder::new(&mut buf);

        encoder.set_max_size(5);
        encoder.emit(0).expect("failed to write");
        encoder.emit(1).expect("failed to write");
        encoder.emit(2).expect("failed to write");
        encoder.emit(3).expect("failed to write");
        encoder.emit(4).expect("failed to write");
        let error = encoder.emit(5).unwrap_err();

        match *error.kind() {
            ProtoErrorKind::MaxBufferSizeExceeded(_) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn test_max_size_0() {
        let mut buf = vec![];
        let mut encoder = BinEncoder::new(&mut buf);

        encoder.set_max_size(0);
        let error = encoder.emit(0).unwrap_err();

        match *error.kind() {
            ProtoErrorKind::MaxBufferSizeExceeded(_) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn test_max_size_place() {
        let mut buf = vec![];
        let mut encoder = BinEncoder::new(&mut buf);

        encoder.set_max_size(2);
        let place = encoder.place::<u16>().expect("place failed");
        place.replace(&mut encoder, 16).expect("placeback failed");

        let error = encoder.place::<u16>().unwrap_err();

        match *error.kind() {
            ProtoErrorKind::MaxBufferSizeExceeded(_) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn test_target_compression() {
        let mut msg = Message::new();
        msg.add_query(Query::query(
            Name::from_str("www.google.com.").unwrap(),
            RecordType::A,
        ))
        .add_answer(Record::from_rdata(
            Name::from_str("www.google.com.").unwrap(),
            0,
            RData::SRV(SRV::new(
                0,
                0,
                0,
                Name::from_str("www.compressme.com").unwrap(),
            )),
        ))
        .add_additional(Record::from_rdata(
            Name::from_str("www.google.com.").unwrap(),
            0,
            RData::SRV(SRV::new(
                0,
                0,
                0,
                Name::from_str("www.compressme.com").unwrap(),
            )),
        ))
        // name here should use compressed label from target in previous records
        .add_answer(Record::from_rdata(
            Name::from_str("www.compressme.com").unwrap(),
            0,
            RData::CNAME(Name::from_str("www.foo.com").unwrap()),
        ));

        let bytes = msg.to_vec().unwrap();
        // label is compressed pointing to target, would be 145 otherwise
        assert_eq!(bytes.len(), 130);
        // check re-serializing
        assert!(Message::from_vec(&bytes).is_ok());
    }
}
