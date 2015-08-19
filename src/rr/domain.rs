use std::string::FromUtf8Error;
use std::ops::Index;

use super::util;

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

  /// parses the chain of labels
  ///  this has a max of 255 octets, with each label being less than 63.
  ///  all names will be stored lowercase internally.
  /// This will consume the portions of the Vec which it is reading...
  pub fn parse(slice: &mut Vec<u8>) -> Name {
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
          match slice.last() {
            Some(&0) | None => LabelParseState::Root,
            Some(&byte) if byte & 0xC0 == 0xC0 => LabelParseState::Pointer,
            Some(&byte) if byte <= 0x3F        => LabelParseState::Label,
            _ => unimplemented!(),
          }
        },
        LabelParseState::Label => {
          labels.push(util::parse_character_data(slice));

          // reset to collect more data
          LabelParseState::LabelLengthOrPointer
        },
        LabelParseState::Pointer => {
          // lookup in the hashmap the label to use
          unimplemented!()
        },
        LabelParseState::Root => {
          // need to pop() the 0 off the stack...
          slice.pop();
          break;
        }
      }
    }

    Name { labels: labels }
  }

  pub fn write_to(&self, buf: &mut Vec<u8>) {
    let buf_len = buf.len(); // lazily assert the size is less than 255...
    for label in &self.labels {
      util::write_character_data_to(buf, label);
      assert!((buf.len() - buf_len) <= 63); // individual labels must be shorter than 63.
    }

    // the end of the list of names
    buf.push(0);
    assert!((buf.len() - buf_len) <= 255); // the entire name needs to be less than 256.
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
  use super::super::util::tests::{test_parse_data_set, test_write_data_set_to};

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
    test_parse_data_set(get_data(), |b| Name::parse(b));
  }

  #[test]
  fn write_to() {
    test_write_data_set_to(get_data(), |b, n| n.write_to(b));
  }
}
