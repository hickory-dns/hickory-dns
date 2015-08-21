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
