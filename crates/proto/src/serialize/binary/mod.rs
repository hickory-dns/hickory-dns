// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Binary serialization types

mod decoder;
mod encoder;
mod restrict;

use alloc::vec::Vec;

pub use self::decoder::{BinDecoder, DecodeError};
pub use self::encoder::BinEncoder;
pub use self::encoder::EncodeMode;
pub use self::restrict::{Restrict, RestrictedMath, Verified};

#[cfg(test)]
pub(crate) mod bin_tests;

use crate::error::*;

/// A type which can be encoded into a DNS binary format
pub trait BinEncodable {
    /// Write the type to the stream
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()>;

    /// Returns the object in binary form
    fn to_bytes(&self) -> ProtoResult<Vec<u8>> {
        let mut bytes = Vec::<u8>::new();
        {
            let mut encoder = BinEncoder::new(&mut bytes);
            self.emit(&mut encoder)?;
        }

        Ok(bytes)
    }
}

/// A trait for types which are serializable to and from DNS binary formats
pub trait BinDecodable<'r>: Sized {
    /// Read the type from the stream
    fn read(decoder: &mut BinDecoder<'r>) -> ProtoResult<Self>;

    /// Returns the object in binary form
    fn from_bytes(bytes: &'r [u8]) -> ProtoResult<Self> {
        let mut decoder = BinDecoder::new(bytes);
        Self::read(&mut decoder)
    }
}

impl BinEncodable for u16 {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.emit_u16(*self)
    }
}

impl BinDecodable<'_> for u16 {
    fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<Self> {
        decoder
            .read_u16()
            .map(Restrict::unverified)
            .map_err(Into::into)
    }
}

impl BinEncodable for i32 {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.emit_i32(*self)
    }
}

impl<'r> BinDecodable<'r> for i32 {
    fn read(decoder: &mut BinDecoder<'r>) -> ProtoResult<Self> {
        decoder
            .read_i32()
            .map(Restrict::unverified)
            .map_err(Into::into)
    }
}

impl BinEncodable for u32 {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.emit_u32(*self)
    }
}

impl BinDecodable<'_> for u32 {
    fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<Self> {
        decoder
            .read_u32()
            .map(Restrict::unverified)
            .map_err(Into::into)
    }
}

impl BinEncodable for Vec<u8> {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.emit_vec(self)
    }
}
