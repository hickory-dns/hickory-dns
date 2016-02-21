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

// RFC 5155                         NSEC3                        March 2008
//
// 11.  IANA Considerations
//
//    Although the NSEC3 and NSEC3PARAM RR formats include a hash algorithm
//    parameter, this document does not define a particular mechanism for
//    safely transitioning from one NSEC3 hash algorithm to another.  When
//    specifying a new hash algorithm for use with NSEC3, a transition
//    mechanism MUST also be defined.
//
//    This document updates the IANA registry "DOMAIN NAME SYSTEM
//    PARAMETERS" (http://www.iana.org/assignments/dns-parameters) in sub-
//    registry "TYPES", by defining two new types.  Section 3 defines the
//    NSEC3 RR type 50.  Section 4 defines the NSEC3PARAM RR type 51.
//
//    This document updates the IANA registry "DNS SECURITY ALGORITHM
//    NUMBERS -- per [RFC4035]"
//    (http://www.iana.org/assignments/dns-sec-alg-numbers).  Section 2
//    defines the aliases DSA-NSEC3-SHA1 (6) and RSASHA1-NSEC3-SHA1 (7) for
//    respectively existing registrations DSA and RSASHA1 in combination
//    with NSEC3 hash algorithm SHA1.
//
//    Since these algorithm numbers are aliases for existing DNSKEY
//    algorithm numbers, the flags that exist for the original algorithm
//    are valid for the alias algorithm.
//
//    This document creates a new IANA registry for NSEC3 flags.  This
//    registry is named "DNSSEC NSEC3 Flags".  The initial contents of this
//    registry are:
//
//      0   1   2   3   4   5   6   7
//    +---+---+---+---+---+---+---+---+
//    |   |   |   |   |   |   |   |Opt|
//    |   |   |   |   |   |   |   |Out|
//    +---+---+---+---+---+---+---+---+
//
//       bit 7 is the Opt-Out flag.
//
//       bits 0 - 6 are available for assignment.
//
//    Assignment of additional NSEC3 Flags in this registry requires IETF
//    Standards Action [RFC2434].
//
//    This document creates a new IANA registry for NSEC3PARAM flags.  This
//    registry is named "DNSSEC NSEC3PARAM Flags".  The initial contents of
//    this registry are:
//
//
//
// Laurie, et al.              Standards Track                    [Page 29]
//
//
//
//      0   1   2   3   4   5   6   7
//    +---+---+---+---+---+---+---+---+
//    |   |   |   |   |   |   |   | 0 |
//    +---+---+---+---+---+---+---+---+
//
//       bit 7 is reserved and must be 0.
//
//       bits 0 - 6 are available for assignment.
//
//    Assignment of additional NSEC3PARAM Flags in this registry requires
//    IETF Standards Action [RFC2434].
//
//    Finally, this document creates a new IANA registry for NSEC3 hash
//    algorithms.  This registry is named "DNSSEC NSEC3 Hash Algorithms".
//    The initial contents of this registry are:
//
//       0 is Reserved.
//
//       1 is SHA-1.
//
//       2-255 Available for assignment.
//
//    Assignment of additional NSEC3 hash algorithms in this registry
//    requires IETF Standards Action [RFC2434].
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Nsec3HashAlgorithm {
  SHA1,
}

impl Nsec3HashAlgorithm {
  /// http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
  pub fn from_u8(value: u8) -> DecodeResult<Self> {
    match value {
      1  => Ok(Nsec3HashAlgorithm::SHA1),
      // TODO: where/when is SHA2?
      _ => Err(DecodeError::UnknownAlgorithmTypeValue(value)),
    }
  }
}


impl From<Nsec3HashAlgorithm> for u8 {
  fn from(a: Nsec3HashAlgorithm) -> u8 {
    match a {
      Nsec3HashAlgorithm::SHA1 => 1,
    }
  }
}
