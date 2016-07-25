// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
const PADDING_MARKER: u8 = 0x80_u8;

/// pads the given message using the described method below.
///
/// ```text
/// 3. Padding for client queries over UDP
/// --------------------------------------
///
/// Prior to encryption, queries are padded using the ISO/IEC 7816-4
/// format. The padding starts with a byte valued 0x80 followed by a
/// variable number of NUL bytes.
///
/// <client-query> <client-query-pad> must be at least <min-query-len>
/// bytes. If the length of the client query is less than <min-query-len>,
/// the padding length must be adjusted in order to satisfy this
/// requirement.
///
/// <min-query-len> is a variable length, initially set to 256 bytes, and
/// must be a multiple of 64 bytes.
/// ```
pub fn pad(message: &[u8], minimum: usize, boundary: usize) -> Vec<u8> {
  let padded_len = message.len() + 1;

  // determine the padding length
  let padding = if padded_len < minimum {
    // padding up to MIN_LENGTH
    minimum - padded_len
  } else {
    let bound_mod = padded_len % boundary;
    if bound_mod != 0 {
      // padding to get us to a the byte BOUNDARY
      boundary - bound_mod
    } else {
      0
    }
  };

  // copy over the old message
  let mut padded = Vec::with_capacity(padded_len + padding);
  padded.extend_from_slice(message);

  // add the padding, marker is always required
  padded.push(PADDING_MARKER);
  for _ in 0..padding {
    padded.push(0_u8)
  }

  padded
}

pub fn strip(message: &[u8]) -> Vec<u8> {
  // TODO: throw error on no 0x80 found...
  let mut skipped: Vec<u8> = message.iter()
                                    .rev()
                                    .skip_while(|b| **b == 0 && **b != PADDING_MARKER)
                                    .skip(1)
                                    .cloned()
                                    .collect();
  skipped.reverse();
  skipped
}

#[test]
fn test_pad_iso_iec_7816_4_0() {
  // nothing padded
  let message = vec![];
  let padded = pad(&message, 256, 64);

  assert_eq!(padded.len(), 256);
  assert_eq!(padded[0], PADDING_MARKER);
  assert_eq!(strip(&padded), message);
}

#[test]
fn test_pad_iso_iec_7816_4_1() {
  // 1 padded to 256
  let message = vec![1];
  let padded = pad(&message, 256, 64);

  assert_eq!(padded.len(), 256);
  assert_eq!(padded[0], 1);
  assert_eq!(padded[1], PADDING_MARKER);
  assert_eq!(strip(&padded), message);
}

#[test]
fn test_pad_iso_iec_7816_4_many() {
  // 1 padded to 256
  let mut message = vec![];
  for i in 0..256 {
    message.push(i as u8);
  }

  let padded = pad(&message, 256, 64);

  assert_eq!(padded.len(), 256 + 64);
  assert_eq!(padded[255], 255);
  assert_eq!(padded[256], PADDING_MARKER);
  assert_eq!(strip(&padded), message);
}

#[test]
fn test_pad_iso_iec_7816_4_many_many() {
  // modula is proper
  let mut message = vec![];
  for i in 0..(256 + 63) {
    message.push(i as u8);
  }

  let padded = pad(&message, 256, 64);

  assert_eq!(padded.len(), 256 + 64);
  assert_eq!(padded[256 + 63], PADDING_MARKER);
  assert_eq!(strip(&padded), message);
}
