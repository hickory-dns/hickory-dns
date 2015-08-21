use ::serialize::binary::*;
use ::error::*;
use ::rr::record_data::RData;

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
// TODO: length should be stored in the decoder, and guaranteed everywhere, right?
pub fn read(decoder: &mut BinDecoder) -> DecodeResult<RData> {
  let length = try!(decoder.rdata_length().ok_or(DecodeError::NoRecordDataLength));
  let mut anything: Vec<u8> = Vec::with_capacity(length as usize);
  for _ in 0..length {
    if let Ok(byte) = decoder.pop() {
      anything.push(byte);
    } else {
      return Err(DecodeError::EOF);
    }
  }

  Ok(RData::NULL{ anything: anything })
}

pub fn emit(encoder: &mut BinEncoder, nil: &RData) -> EncodeResult {
  if let RData::NULL{ref anything} = *nil {
    for b in anything {
      try!(encoder.emit(*b));
    }

    Ok(())
  } else {
    panic!("wrong type here {:?}", nil);
  }
}
