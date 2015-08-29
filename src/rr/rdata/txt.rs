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
use ::rr::record_data::RData;

// 3.3.14. TXT RDATA format
//
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                   TXT-DATA                    /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// where:
//
// TXT-DATA        One or more <character-string>s.
//
// TXT RRs are used to hold descriptive text.  The semantics of the text
// depends on the domain where it is found.
//
// TXT { txt_data: Vec<String> }
pub fn read(decoder: &mut BinDecoder) -> DecodeResult<RData> {
  let length = try!(decoder.rdata_length().ok_or(DecodeError::NoRecordDataLength));
  let data_len = decoder.len();
  let mut strings = Vec::with_capacity(1);

  while data_len - decoder.len() < length as usize {
    strings.push(try!(decoder.read_character_data()));
  }
  Ok(RData::TXT{ txt_data: strings })
}

pub fn emit(encoder: &mut BinEncoder, txt: &RData) -> EncodeResult {
  if let RData::TXT { ref txt_data } = *txt {
    for s in txt_data {
      try!(encoder.emit_character_data(s));
    }
    Ok(())
  } else {
    panic!("wrong type here {:?}", txt);
  }
}

pub fn parse(tokens: Vec<Token>) -> ParseResult<RData> {
  unimplemented!()
}
