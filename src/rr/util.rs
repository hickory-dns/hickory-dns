use std::string::FromUtf8Error;

// TODO: !!! Need to convert to an internally stored [] and not destroy on read,
//   so that "pointer" types can be handled

///<character-string> is a single
/// length octet followed by that number of characters.  <character-string>
/// is treated as binary information, and can be up to 256 characters in
/// length (including the length octet).
///
/// the vector should be reversed before calling.
pub fn parse_character_data(data: &mut Vec<u8>) -> String {
  let length: u8 = data.pop().unwrap();
  assert!(length <= 255u8);
  // TODO once Drain stabalizes on Vec, this should be replaced...
  let mut label_vec: Vec<u8> = Vec::with_capacity(length as usize);
  for _ in 0..length as usize {
    match data.pop() {
      Some(n) => label_vec.push(n),
      None => break,
    }
  }

  // translate bytes to string, then lowercase...
  String::from_utf8(label_vec).unwrap().to_lowercase()
}

/// matches description from above.
///
/// ```
/// use trust_dns::rr::util;
///
/// let mut buf: Vec<u8> = Vec::new();
/// util::write_character_data_to(&mut buf, "abc");
/// assert_eq!(buf, vec![3,b'a',b'b',b'c']);
/// ```
pub fn write_character_data_to(buf: &mut Vec<u8>, char_data: &str) {
  let char_bytes = char_data.as_bytes();
  assert!(char_bytes.len() < 256);

  buf.reserve(char_bytes.len()+1); // reserve the full space for the string
  buf.push(char_bytes.len() as u8);

  // a separate writer isn't necessary for label since it's the same first byte that's being written

  // TODO use append() once it stabalizes
  for b in char_bytes {
    buf.push(*b);
  }
}

/// parses the next 2 bytes into u16. This performs a byte-by-byte manipulation, there
///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
///
/// the vector should be reversed before calling.
pub fn parse_u16(data: &mut Vec<u8>) -> u16 {
  let b1: u8 = data.pop().unwrap();
  let b2: u8 = data.pop().unwrap();

  // translate from network byte order, i.e. big endian
  ((b1 as u16) << 8) + (b2 as u16)
}

pub fn write_u16_to(buf: &mut Vec<u8>, data: u16) {
  buf.reserve(2); // two bytes coming

  let b1: u8 = (data >> 8 & 0xFF) as u8;
  let b2: u8 = (data & 0xFF) as u8;

  buf.push(b1);
  buf.push(b2);
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

pub fn write_i32_to(buf: &mut Vec<u8>, data: i32) {
  buf.reserve(4); // four bytes coming...

  let b1: u8 = (data >> 24 & 0xFF) as u8;
  let b2: u8 = (data >> 16 & 0xFF) as u8;
  let b3: u8 = (data >> 8 & 0xFF) as u8;
  let b4: u8 = (data & 0xFF) as u8;

  buf.push(b1);
  buf.push(b2);
  buf.push(b3);
  buf.push(b4);
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

pub fn write_u32_to(buf: &mut Vec<u8>, data: u32) {
  buf.reserve(4); // four bytes coming...

  let b1: u8 = (data >> 24 & 0xFF) as u8;
  let b2: u8 = (data >> 16 & 0xFF) as u8;
  let b3: u8 = (data >> 8 & 0xFF) as u8;
  let b4: u8 = (data & 0xFF) as u8;

  buf.push(b1);
  buf.push(b2);
  buf.push(b3);
  buf.push(b4);
}

#[cfg(test)]
pub mod tests {
  use std::fmt::Debug;

  fn get_character_data() -> Vec<(String, Vec<u8>)> {
    vec![
      ("".to_string(), vec![0]), // base case, only the root
      ("a".to_string(), vec![1,b'a']), // a single 'a' label
      ("bc".to_string(), vec![2,b'b',b'c']), // two labels, 'a.bc'
      ("♥".to_string(), vec![3,0xE2,0x99,0xA5]), // two labels utf8, 'a.♥'
    ]
  }

  #[test]
  fn parse_character_data() {
    test_parse_data_set(get_character_data(), |b| super::parse_character_data(b));
  }

  #[test]
  fn write_character_data() {
    test_write_data_set_to(get_character_data(), |b, d| super::write_character_data_to(b,&d));
  }

  fn get_u16_data() -> Vec<(u16, Vec<u8>)> {
    vec![
      (0, vec![0x00,0x00]),
      (1, vec![0x00,0x01]),
      (256, vec![0x01,0x00]),
      (u16::max_value(), vec![0xFF,0xFF]),
    ]
  }

  #[test]
  fn parse_u16() {
    test_parse_data_set(get_u16_data(), |b| super::parse_u16(b));
  }

  #[test]
  fn write_u16() {
    test_write_data_set_to(get_u16_data(), |b, d| super::write_u16_to(b,d));
  }

  fn get_i32_data() -> Vec<(i32, Vec<u8>)> {
    vec![
      (0, vec![0x00,0x00,0x00,0x00]),
      (1, vec![0x00,0x00,0x00,0x01]),
      (256, vec![0x00,0x00,0x01,0x00]),
      (256*256, vec![0x00,0x01,0x00,0x00]),
      (256*256*256, vec![0x01,0x00,0x00,0x00]),
      (-1, vec![0xFF,0xFF,0xFF,0xFF]),
      (i32::min_value(), vec![0x80,0x00,0x00,0x00]),
      (i32::max_value(), vec![0x7F,0xFF,0xFF,0xFF]),
    ]
  }

  #[test]
  fn parse_i32() {
    test_parse_data_set(get_i32_data(), |b| super::parse_i32(b));
  }

  #[test]
  fn write_i32() {
    test_write_data_set_to(get_i32_data(), |b, d| super::write_i32_to(b,d));
  }

  fn get_u32_data() -> Vec<(u32, Vec<u8>)> {
    vec![
      (0, vec![0x00,0x00,0x00,0x00]),
      (1, vec![0x00,0x00,0x00,0x01]),
      (256, vec![0x00,0x00,0x01,0x00]),
      (256*256, vec![0x00,0x01,0x00,0x00]),
      (256*256*256, vec![0x01,0x00,0x00,0x00]),
      (u32::max_value(), vec![0xFF,0xFF,0xFF,0xFF]),
      (2147483648, vec![0x80,0x00,0x00,0x00]),
      (i32::max_value() as u32, vec![0x7F,0xFF,0xFF,0xFF]),
    ]
  }

  #[test]
  fn parse_u32() {
    test_parse_data_set(get_u32_data(), |b| super::parse_u32(b));
  }

  #[test]
  fn write_u32() {
    test_write_data_set_to(get_u32_data(), |b, d| super::write_u32_to(b,d));
  }


  pub fn test_parse_data_set<E, F>(data_set: Vec<(E, Vec<u8>)>, parse_func: F)
  where E: PartialEq<E> + Debug, F: Fn(&mut Vec<u8>) -> E {
    let mut test_pass = 0;
    for (expect, mut binary) in data_set {
      test_pass += 1;
      println!("test {}: {:?}", test_pass, binary);
      binary.reverse();
      assert_eq!(parse_func(&mut binary), expect);
    }
  }

  pub fn test_write_data_set_to<S, F>(data_set: Vec<(S, Vec<u8>)>, write_func: F)
  where F: Fn(&mut Vec<u8>, S), S: Debug {
    let mut test_pass = 0;

    for (data, expect) in data_set {
      test_pass += 1;
      println!("test {}: {:?}", test_pass, data);
      let mut buf: Vec<u8> = Vec::with_capacity(expect.len());
      write_func(&mut buf, data);
      assert_eq!(buf, expect);
    }
  }
}
