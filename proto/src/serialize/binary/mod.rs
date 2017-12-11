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

use super::Label;

pub use self::decoder::BinDecoder;
pub use self::encoder::BinEncoder;
pub use self::encoder::EncodeMode;

#[cfg(test)]
pub mod bin_tests;

use error::*;

/// A trait for types which are serializable
pub trait BinSerializable<S: Sized> {
    /// Read the type from the stream
    fn read(decoder: &mut BinDecoder) -> ProtoResult<S>;

    /// Write the type to the stream
    fn emit(&self, encoder: &mut BinEncoder) -> ProtoResult<()>;
}

impl BinSerializable<u16> for u16 {
    fn read(decoder: &mut BinDecoder) -> ProtoResult<u16> {
        decoder.read_u16()
    }

    fn emit(&self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        encoder.emit_u16(*self)
    }
}

impl BinSerializable<i32> for i32 {
    fn read(decoder: &mut BinDecoder) -> ProtoResult<i32> {
        decoder.read_i32()
    }

    fn emit(&self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        encoder.emit_i32(*self)
    }
}

impl BinSerializable<u32> for u32 {
    fn read(decoder: &mut BinDecoder) -> ProtoResult<u32> {
        decoder.read_u32()
    }

    fn emit(&self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        encoder.emit_u32(*self)
    }
}

impl BinSerializable<Vec<u8>> for Vec<u8> {
    fn read(_: &mut BinDecoder) -> ProtoResult<Vec<u8>> {
        panic!("do not know amount to read in this context")
    }

    fn emit(&self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        encoder.emit_vec(self)
    }
}
