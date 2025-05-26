// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use alloc::vec::Vec;

use crate::{
    ProtoError,
    error::{ProtoErrorKind, ProtoResult},
    op::Header,
};

use super::BinEncodable;

// this is private to make sure there is no accidental access to the inner buffer.
mod private {
    use alloc::vec::Vec;

    use crate::error::{ProtoErrorKind, ProtoResult};

    /// A wrapper for a buffer that guarantees writes never exceed a defined set of bytes
    pub(super) struct MaximalBuf<'a> {
        max_size: usize,
        buffer: &'a mut Vec<u8>,
    }

    impl<'a> MaximalBuf<'a> {
        pub(super) fn new(max_size: u16, buffer: &'a mut Vec<u8>) -> Self {
            MaximalBuf {
                max_size: max_size as usize,
                buffer,
            }
        }

        /// Sets the maximum size to enforce
        pub(super) fn set_max_size(&mut self, max: u16) {
            self.max_size = max as usize;
        }

        pub(super) fn write(&mut self, offset: usize, data: &[u8]) -> ProtoResult<()> {
            debug_assert!(offset <= self.buffer.len());
            if offset + data.len() > self.max_size {
                return Err(ProtoErrorKind::MaxBufferSizeExceeded(self.max_size).into());
            }

            if offset == self.buffer.len() {
                self.buffer.extend(data);
                return Ok(());
            }

            let end = offset + data.len();
            if end > self.buffer.len() {
                self.buffer.resize(end, 0);
            }

            self.buffer[offset..end].copy_from_slice(data);
            Ok(())
        }

        pub(super) fn reserve(&mut self, offset: usize, len: usize) -> ProtoResult<()> {
            let end = offset + len;
            if end > self.max_size {
                return Err(ProtoErrorKind::MaxBufferSizeExceeded(self.max_size).into());
            }

            self.buffer.resize(end, 0);
            Ok(())
        }

        /// truncates are always safe
        pub(super) fn truncate(&mut self, len: usize) {
            self.buffer.truncate(len)
        }

        /// returns the length of the underlying buffer
        pub(super) fn len(&self) -> usize {
            self.buffer.len()
        }

        /// Immutable reads are always safe
        pub(super) fn buffer(&'a self) -> &'a [u8] {
            self.buffer as &'a [u8]
        }

        /// Returns a reference to the internal buffer
        pub(super) fn into_bytes(self) -> &'a Vec<u8> {
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
    /// Whether the encoder should use the DNSSEC canonical form for RDATA.
    canonical_form: bool,
    /// How names should be encoded.
    name_encoding: NameEncoding,
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
            buffer: private::MaximalBuf::new(u16::MAX, buf),
            name_pointers: Vec::new(),
            mode,
            canonical_form: false,
            name_encoding: NameEncoding::Compressed,
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

    /// If set to true, then records will be written into the buffer in DNSSEC canonical form
    pub fn set_canonical_form(&mut self, canonical_form: bool) {
        self.canonical_form = canonical_form;
    }

    /// Returns true if the encoder is writing in DNSSEC canonical form
    pub fn is_canonical_form(&self) -> bool {
        self.canonical_form
    }

    /// Select how names are encoded
    pub fn set_name_encoding(&mut self, name_encoding: NameEncoding) {
        self.name_encoding = name_encoding;
    }

    /// Returns the current name encoding mode
    pub fn name_encoding(&self) -> NameEncoding {
        self.name_encoding
    }

    /// Returns a guard type that uses a different name encoding mode.
    pub fn with_name_encoding<'e>(
        &'e mut self,
        name_encoding: NameEncoding,
    ) -> ModalEncoder<'a, 'e> {
        let previous_name_encoding = self.name_encoding();

        self.set_name_encoding(name_encoding);

        ModalEncoder {
            previous_name_encoding,
            inner: self,
        }
    }

    /// Returns a guard type that uses a different name encoding mode, for RDATA.
    ///
    /// If the encoder is using canonical form, name compression will not be used. Otherwise, name
    /// compression will be used for standard record types.
    ///
    /// If the encoder is using canonical form, the case of names will depend on the record type.
    /// Otherwise, the case will be unchanged.
    pub fn with_rdata_behavior<'e>(
        &'e mut self,
        rdata_encoding: RDataEncoding,
    ) -> ModalEncoder<'a, 'e> {
        let previous_name_encoding = self.name_encoding();

        match (rdata_encoding, self.is_canonical_form()) {
            (RDataEncoding::StandardRecord, true) | (RDataEncoding::Canonical, true) => {
                self.set_name_encoding(NameEncoding::UncompressedLowercase)
            }
            (RDataEncoding::StandardRecord, false) => {}
            (RDataEncoding::Canonical, false)
            | (RDataEncoding::Other, true)
            | (RDataEncoding::Other, false) => self.set_name_encoding(NameEncoding::Uncompressed),
        }

        ModalEncoder {
            previous_name_encoding,
            inner: self,
        }
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
        assert!(start <= (u16::MAX as usize));
        assert!(end <= (u16::MAX as usize));
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
                assert!(match_start <= &(u16::MAX as usize));
                return Some(*match_start as u16);
            }
        }

        None
    }

    /// Emit one byte into the buffer
    pub fn emit(&mut self, b: u8) -> ProtoResult<()> {
        self.buffer.write(self.offset, &[b])?;
        self.offset += 1;
        Ok(())
    }

    /// matches description from above.
    ///
    /// ```
    /// use hickory_proto::serialize::binary::BinEncoder;
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

        self.emit_character_data_unrestricted(char_data)
    }

    /// Emit character data of unrestricted length
    ///
    /// Although character strings are typically restricted to being no longer than 255 characters,
    /// some modern standards allow longer strings to be encoded.
    pub fn emit_character_data_unrestricted<S: AsRef<[u8]>>(&mut self, data: S) -> ProtoResult<()> {
        // first the length is written
        let data = data.as_ref();
        self.emit(data.len() as u8)?;
        self.write_slice(data)
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
        self.buffer.write(self.offset, data)?;
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
    pub fn emit_iter<'e, I: Iterator<Item = &'e E>, E: 'e + BinEncodable>(
        &mut self,
        iter: &mut I,
    ) -> ProtoResult<usize> {
        let mut count = 0;
        for i in iter {
            let rollback = self.set_rollback();
            if let Err(e) = i.emit(self) {
                return Err(match e.kind() {
                    ProtoErrorKind::MaxBufferSizeExceeded(_) => {
                        rollback.rollback(self);
                        ProtoError::from(ProtoErrorKind::NotAllRecordsWritten { count })
                    }
                    _ => e,
                });
            }

            count += 1;
        }
        Ok(count)
    }

    /// capture a location to write back to
    pub fn place<T: EncodedSize>(&mut self) -> ProtoResult<Place<T>> {
        let index = self.offset;

        // resize the buffer
        self.buffer.reserve(self.offset, T::LEN)?;

        // update the offset
        self.offset += T::LEN;

        Ok(Place {
            start_index: index,
            phantom: PhantomData,
        })
    }

    /// calculates the length of data written since the place was creating
    pub fn len_since_place<T: EncodedSize>(&self, place: &Place<T>) -> usize {
        (self.offset - place.start_index) - T::LEN
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
        assert!((self.offset - place.start_index) == T::LEN);

        // reset to original location
        self.offset = current_index;

        emit_result
    }

    fn set_rollback(&self) -> Rollback {
        Rollback {
            offset: self.offset(),
            pointers: self.name_pointers.len(),
        }
    }
}

/// Selects how names should be encoded.
#[derive(Clone, Copy)]
pub enum NameEncoding {
    /// Encode names with compression enabled. The case of the name is unchanged.
    Compressed,
    /// Encode names without compression. The case of the name is unchanged.
    Uncompressed,
    /// Encode names transformed to lowercase and without compression.
    UncompressedLowercase,
}

/// Determines how names inside RDATA are encoded, depending on the record type and whether DNSSEC
/// canonical form is used.
#[derive(Clone, Copy)]
pub enum RDataEncoding {
    /// Applicable to standard record types defined in [RFC 1035 section
    /// 3.3](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3).
    ///
    /// Names in the RDATA may be compressed, since these record types are well-known. When encoding
    /// in DNSSEC canonical form, compression is not used, and names are transformed to lowercase.
    /// Note that all standard types that contain names in the RDATA are also on the list in [RFC
    /// 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
    StandardRecord,
    /// Applicable to record types that were defined after RFC 1035, for which the DNSSEC canonical
    /// form of the RDATA has names transformed to lowercase. Compression is never used.
    ///
    /// This applies to the list of record types defined in [RFC 4034 section
    /// 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2) and modified by [RFC 6840,
    /// section 5.1](https://datatracker.ietf.org/doc/html/rfc6840#section-5.1).
    Canonical,
    /// Applicable to record types for which names in the RDATA are never compressed and never
    /// transformed to lowercase.
    ///
    /// All newly defined record types must have this behavior, per [RFC 3597 section
    /// 4](https://datatracker.ietf.org/doc/html/rfc3597#section-4) and [section
    /// 7](https://datatracker.ietf.org/doc/html/rfc3597#section-7).
    Other,
}

/// This wraps a [BinEncoder] and applies different name encoding options.
///
/// Original name encoding options will be restored when this is dropped.
pub struct ModalEncoder<'a, 'e> {
    previous_name_encoding: NameEncoding,
    inner: &'e mut BinEncoder<'a>,
}

impl<'a> Deref for ModalEncoder<'a, '_> {
    type Target = BinEncoder<'a>;

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

impl DerefMut for ModalEncoder<'_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner
    }
}

impl Drop for ModalEncoder<'_, '_> {
    fn drop(&mut self) {
        self.inner.set_name_encoding(self.previous_name_encoding);
    }
}

/// A trait to return the size of a type as it will be encoded in DNS
///
/// it does not necessarily equal `core::mem::size_of`, though it might, especially for primitives
pub trait EncodedSize: BinEncodable {
    const LEN: usize;
}

impl EncodedSize for u16 {
    const LEN: usize = 2;
}

impl EncodedSize for Header {
    const LEN: usize = 12;
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
}

/// A type representing a rollback point in a stream
pub(crate) struct Rollback {
    offset: usize,
    pointers: usize,
}

impl Rollback {
    pub(crate) fn rollback(self, encoder: &mut BinEncoder<'_>) {
        let Self { offset, pointers } = self;
        encoder.set_offset(offset);
        encoder.name_pointers.truncate(pointers);
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
    #[cfg(any(feature = "std", feature = "no-std-rand"))]
    use core::str::FromStr;

    use super::*;
    use crate::{
        op::Message,
        serialize::binary::{BinDecodable, BinDecoder},
    };
    #[cfg(any(feature = "std", feature = "no-std-rand"))]
    use crate::{
        op::Query,
        rr::Name,
        rr::{
            RData, Record, RecordType,
            rdata::{CNAME, SRV},
        },
    };

    #[test]
    fn test_label_compression_regression() {
        // https://github.com/hickory-dns/hickory-dns/issues/339
        /*
        ;; QUESTION SECTION:
        ;bluedot.is.autonavi.com.gds.alibabadns.com. IN AAAA

        ;; AUTHORITY SECTION:
        gds.alibabadns.com.     1799    IN      SOA     gdsns1.alibabadns.com. none. 2015080610 1800 600 3600 360
        */
        let data = vec![
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
    fn test_place() {
        let mut buf = vec![];
        {
            let mut encoder = BinEncoder::new(&mut buf);
            let place = encoder.place::<u16>().unwrap();
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

        match error.kind() {
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

        match error.kind() {
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

        match error.kind() {
            ProtoErrorKind::MaxBufferSizeExceeded(_) => (),
            _ => panic!(),
        }
    }

    #[cfg(any(feature = "std", feature = "no-std-rand"))]
    #[test]
    fn test_target_compression() {
        let mut msg = Message::query();
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
                Name::from_str("www.compressme.com.").unwrap(),
            )),
        ))
        .add_additional(Record::from_rdata(
            Name::from_str("www.google.com.").unwrap(),
            0,
            RData::SRV(SRV::new(
                0,
                0,
                0,
                Name::from_str("www.compressme.com.").unwrap(),
            )),
        ))
        // name here should use compressed label from target in previous records
        .add_answer(Record::from_rdata(
            Name::from_str("www.compressme.com.").unwrap(),
            0,
            RData::CNAME(CNAME(Name::from_str("www.foo.com.").unwrap())),
        ));

        let bytes = msg.to_vec().unwrap();
        // label is compressed pointing to target, would be 145 otherwise
        assert_eq!(bytes.len(), 130);
        // check re-serializing
        assert!(Message::from_vec(&bytes).is_ok());
    }

    #[test]
    fn test_fuzzed() {
        const MESSAGE: &[u8] = include_bytes!("../../../tests/test-data/fuzz-long.rdata");
        let msg = Message::from_bytes(MESSAGE).unwrap();
        msg.to_bytes().unwrap();
    }
}
