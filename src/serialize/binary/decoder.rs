use ::error::{DecodeError, DecodeResult};
use ::rr::record_type::RecordType;

/// This is non-destructive to the inner buffer, b/c for pointer types we need to perform a reverse
///  seek to lookup names
///
/// A note on serialization, there was a thought to have this implement the rustc-serialization,
///  but given that this is such a small subset of all the serialization which that performs
///  this is a simpler implementation without the cruft, at least for serializing to/from the
///  binary DNS protocols. rustc-serialization will be used for other coms, e.g. json over http
pub struct BinDecoder {
  buffer: Vec<u8>,
  index: usize,
  record_type: Option<RecordType>,
  rdata_length: Option<u16>,
}

impl BinDecoder {
  pub fn new(buffer: Vec<u8>) -> Self {
    BinDecoder { buffer: buffer, index: 0, record_type: None, rdata_length: None }
  }

  pub fn set_record_type(&mut self, record_type: RecordType) { self.record_type = Some(record_type); }
  pub fn set_rdata_length(&mut self, rdata_length: u16) { self.rdata_length = Some(rdata_length); }

  pub fn record_type(&self) -> Option<RecordType> { self.record_type }
  pub fn rdata_length(&self) -> Option<u16> { self.rdata_length }

  pub fn pop(&mut self) -> DecodeResult<u8> {
    if self.index < self.buffer.len() {
      let byte = self.buffer[self.index];
      self.index += 1;
      Ok(byte)
    } else {
      Err(DecodeError::EOF)
    }
  }

  pub fn len(&self) -> usize {
    self.buffer.len() - self.index
  }

  pub fn peek(&self) -> Option<u8> {
    if self.index < self.buffer.len() {
      Some(self.buffer[self.index])
    } else {
      None
    }
  }

  ///<character-string> is a single
  /// length octet followed by that number of characters.  <character-string>
  /// is treated as binary information, and can be up to 256 characters in
  /// length (including the length octet).
  ///
  /// the vector should be reversed before calling.
  pub fn read_character_data(&mut self) -> DecodeResult<String> {
    let length: u8 = try!(self.pop());

    // TODO once Drain stabalizes on Vec, this should be replaced...
    let mut label_vec: Vec<u8> = Vec::with_capacity(length as usize);
    for _ in 0..length as usize {
      label_vec.push(try!(self.pop()))
    }

    // translate bytes to string, then lowercase...
    Ok(try!(String::from_utf8(label_vec)).to_lowercase())
  }

  /// parses the next 2 bytes into u16. This performs a byte-by-byte manipulation, there
  ///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
  ///
  /// the vector should be reversed before calling.
  pub fn read_u16(&mut self) -> DecodeResult<u16> {
    let b1: u8 = try!(self.pop());
    let b2: u8 = try!(self.pop());

    // translate from network byte order, i.e. big endian
    Ok(((b1 as u16) << 8) + (b2 as u16))
  }

  /// parses the next four bytes into i32. This performs a byte-by-byte manipulation, there
  ///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
  ///
  /// the vector should be reversed before calling.
  pub fn read_i32(&mut self) -> DecodeResult<i32> {
    // TODO should this use a default rather than the panic! that will happen in the None case?
    let b1: u8 = try!(self.pop());
    let b2: u8 = try!(self.pop());
    let b3: u8 = try!(self.pop());
    let b4: u8 = try!(self.pop());

    // translate from network byte order, i.e. big endian
    Ok(((b1 as i32) << 24) + ((b2 as i32) << 16) + ((b3 as i32) << 8) + (b4 as i32))
  }

  /// parses the next four bytes into u32. This performs a byte-by-byte manipulation, there
  ///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
  ///
  /// the vector should be reversed before calling.
  pub fn read_u32(&mut self) -> DecodeResult<u32> {
    // TODO should this use a default rather than the panic! that will happen in the None case?
    let b1: u8 = try!(self.pop());
    let b2: u8 = try!(self.pop());
    let b3: u8 = try!(self.pop());
    let b4: u8 = try!(self.pop());

    // translate from network byte order, i.e. big endian
    Ok(((b1 as u32) << 24) + ((b2 as u32) << 16) + ((b3 as u32) << 8) + (b4 as u32))
  }
}
