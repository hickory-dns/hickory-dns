//use std::collections::HashMap;
//use std::error::Error;
use std::string::FromUtf8Error;

use super::record_type::RecordType;
use super::dns_class::DNSClass;

// labels          63 octets or less
// names           255 octets or less
// TTL             positive values of a signed 32 bit number.
// UDP messages    512 octets or less
pub struct Record {
  rr_type: RecordType,
  dns_class: DNSClass,
  name_labels: Vec<String>,
}

impl Record {

  /// parse a resource record line example:
  ///
  ///
  //fn parse(line: &str) -> Record {


    // tokenize the string
    //let mut tokens = line.words();
  //}

  /// parses the chain of labels
  ///  this has a max of 255 octets, with each label being less than 63.
  ///  all names will be stored lowercase internally.
  fn parse_labels(slice: &[u8]) -> Result<Vec<String>, FromUtf8Error> {
    let mut state: LabelParseState = LabelParseState::LabelLengthOrPointer;
    let mut labels: Vec<String> = Vec::with_capacity(3); // most labels will be around three, e.g. www.example.com

    let mut cur_slice = slice;

    // assume all chars are utf-8. We're doing byte-by-byte operations, no endianess issues...
    // reserved: (1000 0000 aka 0800) && (0100 0000 aka 0400)
    // pointer: (slice == 1100 0000 aka C0) & C0 == true, then 03FF & slice = offset
    // label: 03FF & slice = length; slice.next(length) = label
    // root: 0000
    loop {
      state = match state {
        LabelParseState::LabelLengthOrPointer => {
          //let byte: u8 = *iter.take(1).next().unwrap(); // could default to zero, but it's an error if this doesn't exist, perhaps try! instead
          let (first, tmp_slice) = cur_slice.split_at(1);
          cur_slice = tmp_slice;

          match first.first() {
            Some(&0) | None => LabelParseState::Root,
            Some(&byte) if byte & 0xC0 == 0xC0 => LabelParseState::Pointer(byte & 0x3F),
            Some(&byte) if byte <= 0x3F        => LabelParseState::Label(byte),
            _ => unimplemented!(),
          }
          },
        LabelParseState::Label(count) => {
          //let label_iter: Take<Iter<u8>> = iter.take(count as usize);
          //let arr: Vec<&u8> = label_iter.collect();
          //let arr2: Vec<u8> = arr.to_vec();
          let (label_slice, tmp_slice) = cur_slice.split_at(count as usize);
          cur_slice = tmp_slice;

          // using lossy, this is safe, but can end up with junk in the name...
          // TODO other option
          let label = try!(String::from_utf8(label_slice.into()));
          labels.push(label);

          // reset to collect more data
          LabelParseState::LabelLengthOrPointer
          },
        LabelParseState::Pointer(offset) => {
          // lookup in the hashmap the label to use
          unimplemented!()
        },
        LabelParseState::Root => {
          // technically could return here...
          break;
        }
      }
    }

    return Ok(labels);
  }
}

/// This is the list of states for the state machine
enum LabelParseState {
  LabelLengthOrPointer, // basically the start of the FSM
  Label(u8),   // storing length of the label, must be < 63
  Pointer(u8), // location of pointer in slice,
  Root,        // root is the end of the labels list, aka null
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parse_labels() {
    let data: Vec<(Vec<u8>, Vec<String>)> = vec![
      (vec![0 as u8], vec![String::new()]), // base case, only the root
    ];

    for (binary, result) in data {
      assert_eq!(Record::parse_labels(binary.as_slice()).ok().unwrap(), result);
    }
  }
}
