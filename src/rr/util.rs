use std::string::FromUtf8Error;

///<character-string> is a single
/// length octet followed by that number of characters.  <character-string>
/// is treated as binary information, and can be up to 256 characters in
/// length (including the length octet).
///
/// the vector should be reversed before calling.
pub fn parse_character_data(data: &mut Vec<u8>) -> Result<String, FromUtf8Error> {
  let length: u8 = data.pop().unwrap_or(0);
  parse_label(data, length)
}

/// parse a label of a particular length (it's a portion of the vector)
/// the vector should be reversed before calling.
///```
/// assert_eq(parse_lable(b"bbbaaa", 6).ok().unwrap(), "aaabbb".to_string());
///```
pub fn parse_label(data: &mut Vec<u8>, length: u8) -> Result<String, FromUtf8Error> {
  // TODO once Drain stabalizes on Vec, this should be replaced...
  let mut label_vec: Vec<u8> = Vec::with_capacity(length as usize);
  for _ in 0..length as usize {
    match data.pop() {
      Some(n) => label_vec.push(n),
      None => break,
    }
  }

  // translate bytes to string, then lowercase...
  Ok(try!(String::from_utf8(label_vec)).to_lowercase())
}


/// parses the next 2 bytes into u16. This performs a byte-by-byte manipulation, there
///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
///
/// the vector should be reversed before calling.
pub fn parse_u16(data: &mut Vec<u8>) -> u16 {
  // TODO should this use a default rather than the panic! that will happen in the None case?
  let b1: u8 = data.pop().unwrap();
  let b2: u8 = data.pop().unwrap();

  // translate from network byte order, i.e. big endian
  ((b1 as u16) << 8) + (b2 as u16)
}

/// parses the next four bytes into i32. This performs a byte-by-byte manipulation, there
///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
///
/// the vector should be reversed before calling.
pub fn parse_i32(data: &mut Vec<u8>) -> i32 {
  // TODO should this use a default rather than the panic! that will happen in the None case?
  let b1: u8 = data.pop().unwrap();
  let b2: u8 = data.pop().unwrap();
  let b3: u8 = data.pop().unwrap();
  let b4: u8 = data.pop().unwrap();

  // translate from network byte order, i.e. big endian
  ((b1 as i32) << 24) + ((b2 as i32) << 16) + ((b3 as i32) << 8) + (b4 as i32)
}

/// parses the next four bytes into u32. This performs a byte-by-byte manipulation, there
///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
///
/// the vector should be reversed before calling.
pub fn parse_u32(data: &mut Vec<u8>) -> u32 {
  // TODO should this use a default rather than the panic! that will happen in the None case?
  let b1: u8 = data.pop().unwrap();
  let b2: u8 = data.pop().unwrap();
  let b3: u8 = data.pop().unwrap();
  let b4: u8 = data.pop().unwrap();

  // translate from network byte order, i.e. big endian
  ((b1 as u32) << 24) + ((b2 as u32) << 16) + ((b3 as u32) << 8) + (b4 as u32)
}

#[cfg(test)]
mod tests {
  #[test]
  fn parse_character_data() {
    let data: Vec<(Vec<u8>, String)> = vec![
      (vec![0], "".to_string()), // base case, only the root
      (vec![1,b'a'], "a".to_string()), // a single 'a' label
      (vec![2,b'b',b'c'], "bc".to_string()), // two labels, 'a.bc'
      (vec![3,0xE2,0x99,0xA5], "♥".to_string()), // two labels utf8, 'a.♥'
      (vec![1,b'A'], "a".to_string()), // a single 'a' label, lowercased
    ];

    let mut test_num = 0;
    for (mut binary, expect) in data {
      test_num += 1;
      println!("test: {}", test_num);
      binary.reverse();
      assert_eq!(super::parse_character_data(&mut binary).ok().unwrap(), expect);
    }
  }

  #[test]
  fn parse_u16() {
    let data: Vec<(Vec<u8>, u16)> = vec![
      (vec![0x00,0x00], 0),
      (vec![0x00,0x01], 1),
      (vec![0x01,0x00], 256),
      (vec![0xFF,0xFF], u16::max_value()),
    ];

    let mut test_num = 0;
    for (mut binary, expect) in data {
      test_num += 1;
      println!("test: {}", test_num);
      binary.reverse();
      assert_eq!(super::parse_u16(&mut binary), expect);
    }
  }

  #[test]
  fn parse_i32() {
    let data: Vec<(Vec<u8>, i32)> = vec![
      (vec![0x00,0x00,0x00,0x00], 0),
      (vec![0x00,0x00,0x00,0x01], 1),
      (vec![0x00,0x00,0x01,0x00], 256),
      (vec![0x00,0x01,0x00,0x00], 256*256),
      (vec![0x01,0x00,0x00,0x00], 256*256*256),
      (vec![0xFF,0xFF,0xFF,0xFF], -1),
      (vec![0x80,0x00,0x00,0x00], i32::min_value()),
      (vec![0x7F,0xFF,0xFF,0xFF], i32::max_value()),
    ];

    let mut test_num = 0;
    for (mut binary, expect) in data {
      test_num += 1;
      println!("test: {}", test_num);
      binary.reverse();
      assert_eq!(super::parse_i32(&mut binary), expect);
    }
  }

  #[test]
  fn parse_u32() {
    let data: Vec<(Vec<u8>, u32)> = vec![
      (vec![0x00,0x00,0x00,0x00], 0),
      (vec![0x00,0x00,0x00,0x01], 1),
      (vec![0x00,0x00,0x01,0x00], 256),
      (vec![0x00,0x01,0x00,0x00], 256*256),
      (vec![0x01,0x00,0x00,0x00], 256*256*256),
      (vec![0xFF,0xFF,0xFF,0xFF], u32::max_value()),
      (vec![0x80,0x00,0x00,0x00], u32::min_value()),
      (vec![0x7F,0xFF,0xFF,0xFF], u32::max_value()),
    ];

    let mut test_num = 0;
    for (mut binary, expect) in data {
      test_num += 1;
      println!("test: {}", test_num);
      binary.reverse();
      assert_eq!(super::parse_i32(&mut binary), expect);
    }
  }
}
