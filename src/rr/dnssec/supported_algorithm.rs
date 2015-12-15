/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::convert::From;

use ::rr::dnssec::Algorithm;

#[derive(Debug, PartialOrd, PartialEq)]
pub struct SupportedAlgorithms {
  // right now the number of Algorithms supported are fewer than 16..
  bit_map: u8
}

impl SupportedAlgorithms {
  pub fn new() -> Self {
    SupportedAlgorithms{ bit_map: 0 }
  }

  fn pos(&self, algorithm: Algorithm) -> u8 {
    // not using the values from the RFC's to keep the bit_map space condensed
    let bit_pos: u8 = match algorithm {
      Algorithm::RSASHA1 => 0,
      Algorithm::RSASHA256 => 1,
      Algorithm::RSASHA1_NSEC3_SHA1 => 2,
      Algorithm::RSASHA512 => 3,
      // ECDSAP256SHA256 => 4,
      // ECDSAP384SHA384 => 5,
    };

    assert!(bit_pos <= u8::max_value());
    bit_pos
  }

  pub fn set(&mut self, algorithm: Algorithm) {
    let bit_pos: u8 = self.pos(algorithm);
    self.bit_map |= 1u8 << bit_pos;
  }

  pub fn has(&self, algorithm: Algorithm) -> bool {
    let bit_pos: u8 = self.pos(algorithm);
    (bit_pos & self.bit_map) == bit_pos
  }
}

impl<'a> From<&'a [u8]> for SupportedAlgorithms {
  fn from(value: &'a [u8]) -> Self {
    let mut supported = SupportedAlgorithms::new();

    for i in value.iter().map(|i|Algorithm::from_u8(*i)) {
      if i.is_ok() {
        supported.set(i.unwrap());
      } else {
        warn!("unrecognized algorithm: {}", i.unwrap_err());
      }
    }

    supported
  }
}

#[test]
fn test_has() {
  let mut supported = SupportedAlgorithms::new();

  supported.set(Algorithm::RSASHA1);

  assert!(supported.has(Algorithm::RSASHA1));
  assert!(!supported.has(Algorithm::RSASHA1_NSEC3_SHA1));

  supported.set(Algorithm::RSASHA256);
  assert!(supported.has(Algorithm::RSASHA1));
  assert!(!supported.has(Algorithm::RSASHA1_NSEC3_SHA1));
  assert!(supported.has(Algorithm::RSASHA256));
}
