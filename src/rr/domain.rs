use std::string::FromUtf8Error;

pub struct Name {
  labels: Vec<String>
}

impl Name {
  /// parses the chain of labels
  ///  this has a max of 255 octets, with each label being less than 63.
  ///  all names will be stored lowercase internally.
  /// This will consume the portions of the Vec which it is reading...
  pub fn parse(slice: &mut Vec<u8>) -> Result<Name, FromUtf8Error> {
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
          match slice.remove(0) {
            0 => LabelParseState::Root,
            byte if byte & 0xC0 == 0xC0 => LabelParseState::Pointer(byte & 0x3F),
            byte if byte <= 0x3F        => LabelParseState::Label(byte),
            _ => unimplemented!(),
          }
        },
        LabelParseState::Label(count) => {
          //let label_slice: &mut [u8] = &mut Vec::with_capacity(count as usize)[..];
          //let mut label_slice = Vec::with_capacity(count as usize);
          //let mut label_vec: Vec<u8> = iter::FromIterator::from_iter(iter::repeat(0).take(count as usize));
          //let mut label_slice: &mut [u8] = &mut label_vec[..];

          // TODO once Drain stabalizes on Vec, this should be replaced...
          let mut label_slice: Vec<u8> = Vec::with_capacity(count as usize);
          for i in 0..count as usize {
            label_slice.push(slice.remove(i-i)); // get rid of the unused i warning...
          }

          //println!("count: {} slice: {} label_slice: {}", count, slice.len(), label_slice.len());
          //let label_slice: Vec<u8> = iter::FromIterator::from_iter(iter.take(count as usize).map(|&i| i).collect::<Vec<u8>>());
          //assert_eq!((&*slice).read(label_slice).ok().unwrap(), count as usize);
          println!("count: {} slice: {} label_slice: {}", count, slice.len(), label_slice.len());

          // translate bytes to string, then lowercase...
          //let label_slice = &*label_slice;
          //let label = try!(String::from_utf8(label_slice.into())).to_lowercase();
          let label = try!(String::from_utf8(label_slice)).to_lowercase();
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

    Ok(Name { labels: labels })
  }
}

/// This is the list of states for the label parsing state machine
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
  fn parse() {
    let data: Vec<(Vec<u8>, Vec<String>)> = vec![
      (vec![0], vec![]), // base case, only the root
      (vec![1,b'a',0], vec!["a".to_string()]), // a single 'a' label
      (vec![1,b'a',2,b'b',b'c',0], vec!["a".to_string(), "bc".to_string()]), // two labels, 'a.bc'
      (vec![1,b'a',3,0xE2,0x99,0xA5,0], vec!["a".to_string(), "♥".to_string()]), // two labels utf8, 'a.♥'
      (vec![1,b'A',0], vec!["a".to_string()]), // a single 'a' label, lowercased
    ];

    let mut test_num = 0;
    for (mut binary, expect) in data {
      test_num += 1;
      println!("test: {}", test_num);
      assert_eq!(Name::parse(&mut binary).ok().unwrap().labels, expect);
    }
  }
}
