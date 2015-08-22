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
pub mod decoder;
pub mod encoder;

pub use self::decoder::BinDecoder;
pub use self::encoder::BinEncoder;

#[cfg(test)]
pub mod bin_tests;

use ::error::*;

pub trait BinSerializable {
  fn read(decoder: &mut BinDecoder) -> DecodeResult<Self>;
  fn emit(&self, encoder: &mut BinEncoder) -> EncodeResult;
}
