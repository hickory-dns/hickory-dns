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

//! Binary serialization types

mod decoder;
mod encoder;
mod restrict;

use std::net::{Ipv4Addr, Ipv6Addr};

pub use self::decoder::{BinDecoder, DecodeError};
pub use self::encoder::BinEncoder;
pub use self::encoder::EncodeMode;
pub use self::restrict::{Restrict, RestrictedMath, Verified};

#[cfg(test)]
pub mod bin_tests;

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

impl<'r> BinDecodable<'r> for u16 {
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
    fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<Self> {
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

impl<'r> BinDecodable<'r> for u32 {
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

impl BinEncodable for Ipv4Addr {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        crate::rr::rdata::a::emit(encoder, *self)
    }
}

impl<'r> BinDecodable<'r> for Ipv4Addr {
    fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<Self> {
        crate::rr::rdata::a::read(decoder)
    }
}

impl BinEncodable for Ipv6Addr {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        crate::rr::rdata::aaaa::emit(encoder, self)
    }
}

impl<'r> BinDecodable<'r> for Ipv6Addr {
    fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<Self> {
        crate::rr::rdata::aaaa::read(decoder)
    }
}
