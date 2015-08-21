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
