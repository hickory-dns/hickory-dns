use std::ops::Index;

use ::serialize::binary::*;
use ::error::*;

#[derive(Debug, PartialEq, Clone)]
pub struct Name {
  labels: Vec<String>
}

impl Name {
  pub fn new() -> Self {
    Name { labels: Vec::new() }
  }

  pub fn with_labels(labels: Vec<String>) -> Self {
    Name { labels: labels }
  }

  pub fn add_label(&mut self, label: String) -> &mut Self {
    self.labels.push(label);
    self
  }
}

impl BinSerializable for Name {
  /// parses the chain of labels
  ///  this has a max of 255 octets, with each label being less than 63.
  ///  all names will be stored lowercase internally.
  /// This will consume the portions of the Vec which it is reading...
  fn read(decoder: &mut BinDecoder) -> DecodeResult<Name> {
    let mut state: LabelParseState = LabelParseState::LabelLengthOrPointer;
    let mut labels: Vec<String> = Vec::with_capacity(3); // most labels will be around three, e.g. www.example.com

    // assume all chars are utf-8. We're doing byte-by-byte operations, no endianess issues...
    // reserved: (1000 0000 aka 0800) && (0100 0000 aka 0400)
    // pointer: (slice == 1100 0000 aka C0) & C0 == true, then 03FF & slice = offset
    // label: 03FF & slice = length; slice.next(length) = label
    // root: 0000
    loop {
      state = match state {
        LabelParseState::LabelLengthOrPointer => {
          // determine what the next label is
          match decoder.peek() {
            Some(0) | None => LabelParseState::Root,
            Some(byte) if byte & 0xC0 == 0xC0 => LabelParseState::Pointer,
            Some(byte) if byte <= 0x3F        => LabelParseState::Label,
            _ => unimplemented!(),
          }
        },
        LabelParseState::Label => {
          labels.push(try!(decoder.read_character_data()));

          // reset to collect more data
          LabelParseState::LabelLengthOrPointer
        },
        //         4.1.4. Message compression
        //
        // In order to reduce the size of messages, the domain system utilizes a
        // compression scheme which eliminates the repetition of domain names in a
        // message.  In this scheme, an entire domain name or a list of labels at
        // the end of a domain name is replaced with a pointer to a prior occurance
        // of the same name.
        //
        // The pointer takes the form of a two octet sequence:
        //
        //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //     | 1  1|                OFFSET                   |
        //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //
        // The first two bits are ones.  This allows a pointer to be distinguished
        // from a label, since the label must begin with two zero bits because
        // labels are restricted to 63 octets or less.  (The 10 and 01 combinations
        // are reserved for future use.)  The OFFSET field specifies an offset from
        // the start of the message (i.e., the first octet of the ID field in the
        // domain header).  A zero offset specifies the first byte of the ID field,
        // etc.
        LabelParseState::Pointer => {
          let location = try!(decoder.read_u16()) & 0x3FFF; // get rid of the two high order bits
          let mut pointer = decoder.clone(location);
          let pointed = try!(Name::read(&mut pointer));

          for l in pointed.labels {
            labels.push(l);
          }

          // Pointers always finish the name, break like Root.
          break;
        },
        LabelParseState::Root => {
          // need to pop() the 0 off the stack...
          try!(decoder.pop());
          break;
        }
      }
    }

    println!("found name: {:?}", labels);

    Ok(Name { labels: labels })
  }

  fn emit(&self, encoder: &mut BinEncoder) -> EncodeResult {

    let buf_len = encoder.len(); // lazily assert the size is less than 255...
    for label in &self.labels {
      let label_len = encoder.len();
      try!(encoder.emit_character_data(label));

      // individual labels must be shorter than 63.
      let length = encoder.len() - label_len;
      if length > 63 { return Err(EncodeError::LabelBytesTooLong(length)); }
    }

    // the end of the list of names
    try!(encoder.emit(0));

     // the entire name needs to be less than 256.
    let length = encoder.len() - buf_len;
    if length > 255 { return Err(EncodeError::DomainNameTooLong(length)); }

    Ok(())
  }
}

impl Index<usize> for Name {
    type Output = String;

    fn index<'a>(&'a self, _index: usize) -> &'a String {
        &self.labels[_index]
    }
}

/// This is the list of states for the label parsing state machine
enum LabelParseState {
  LabelLengthOrPointer, // basically the start of the FSM
  Label,   // storing length of the label, must be < 63
  Pointer, // location of pointer in slice,
  Root,    // root is the end of the labels list, aka null
}

#[cfg(test)]
mod tests {
  use super::*;
  use ::serialize::binary::bin_tests::{test_read_data_set, test_emit_data_set};
  use ::serialize::binary::*;

  fn get_data() -> Vec<(Name, Vec<u8>)> {
    vec![
      (Name { labels: vec![] }, vec![0]), // base case, only the root
      (Name { labels: vec!["a".to_string()] }, vec![1,b'a',0]), // a single 'a' label
      (Name { labels: vec!["a".to_string(), "bc".to_string()] }, vec![1,b'a',2,b'b',b'c',0]), // two labels, 'a.bc'
      (Name { labels: vec!["a".to_string(), "♥".to_string()] }, vec![1,b'a',3,0xE2,0x99,0xA5,0]), // two labels utf8, 'a.♥'
    ]
  }

  #[test]
  fn parse() {
    test_read_data_set(get_data(), |ref mut d| Name::read(d));
  }

  #[test]
  fn write_to() {
    test_emit_data_set(get_data(), |e, n| n.emit(e));
  }
}
