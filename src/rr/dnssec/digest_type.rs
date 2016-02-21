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
use ::error::*;

// 0	Reserved	-	[RFC3658]
// 1	SHA-1	MANDATORY	[RFC3658]
// 2	SHA-256	MANDATORY	[RFC4509]
// 3	GOST R 34.11-94	OPTIONAL	[RFC5933]
// 4	SHA-384	OPTIONAL	[RFC6605]
// 5-255	Unassigned	-
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum DigestType {
  SHA1, // [RFC3658]
  SHA256, // [RFC4509]
  // GOSTR34_11_94, // [RFC5933]
  SHA384, // [RFC6605]
}

impl DigestType {
  /// http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
  pub fn from_u8(value: u8) -> DecodeResult<Self> {
    match value {
      1  => Ok(DigestType::SHA1),
      2  => Ok(DigestType::SHA256),
      //  3  => Ok(DigestType::GOSTR34_11_94),
      4  => Ok(DigestType::SHA384),
      _ => Err(DecodeError::UnknownAlgorithmTypeValue(value)),
    }
  }
}


impl From<DigestType> for u8 {
  fn from(a: DigestType) -> u8 {
    match a {
      DigestType::SHA1 => 1,
      DigestType::SHA256 => 2,
      // DigestType::GOSTR34_11_94 => 3,
      DigestType::SHA384 => 4,
    }
  }
}
