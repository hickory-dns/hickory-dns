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
use ::serialize::txt::*;
use ::serialize::binary::*;
use ::error::*;

// 3.3.10. NULL RDATA format (EXPERIMENTAL)
//
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                  <anything>                   /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// Anything at all may be in the RDATA field so long as it is 65535 octets
// or less.
//
// NULL records cause no additional section processing.  NULL RRs are not
// allowed in master files.  NULLs are used as placeholders in some
// experimental extensions of the DNS.
//
// NULL { anything: Vec<u8> },
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct NULL { anything: Option<Vec<u8>> }

impl NULL {
  pub fn new() -> NULL {
    NULL { anything: None }
  }

  pub fn with(anything: Vec<u8>) -> NULL {
    NULL { anything: Some(anything) }
  }

  pub fn get_anything(&self) -> Option<&Vec<u8>> {
    self.anything.as_ref()
  }
}

// TODO: length should be stored in the decoder, and guaranteed everywhere, right?
// TODO: use this for unknown record types in caching...
pub fn read(decoder: &mut BinDecoder, rdata_length: u16) -> DecodeResult<NULL> {
  if rdata_length > 0 {
    let mut anything: Vec<u8> = Vec::with_capacity(rdata_length as usize);
    for _ in 0..rdata_length {
      if let Ok(byte) = decoder.pop() {
        anything.push(byte);
      } else {
        return Err(DecodeError::EOF);
      }
    }

    Ok(NULL::with(anything))
  } else {
    Ok(NULL::new())
  }
}

pub fn emit(encoder: &mut BinEncoder, nil: &NULL) -> EncodeResult {
  if let Some(ref anything) = nil.get_anything() {
    for b in anything.iter() {
      try!(encoder.emit(*b));
    }
  }

  Ok(())
}

#[allow(unused)]
pub fn parse(tokens: &Vec<Token>) -> ParseResult<NULL> {
  unimplemented!()
}

#[test]
pub fn test() {
  let rdata = NULL::with(vec![0,1,2,3,4,5,6,7]);

  let mut bytes = Vec::new();
  let mut encoder: BinEncoder = BinEncoder::new(&mut bytes);
  assert!(emit(&mut encoder, &rdata).is_ok());
  let bytes = encoder.as_bytes();

  println!("bytes: {:?}", bytes);

  let mut decoder: BinDecoder = BinDecoder::new(bytes);
  let read_rdata = read(&mut decoder, bytes.len() as u16);
  assert!(read_rdata.is_ok(), format!("error decoding: {:?}", read_rdata.unwrap_err()));
  assert_eq!(rdata, read_rdata.unwrap());
}
