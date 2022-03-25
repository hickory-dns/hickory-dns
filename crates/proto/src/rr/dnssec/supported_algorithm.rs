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

//! bitmap for expressing the set of supported algorithms in edns.

use std::convert::From;
use std::fmt;
use std::fmt::{Display, Formatter};

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use tracing::warn;

use crate::error::*;
use crate::rr::dnssec::Algorithm;
use crate::serialize::binary::{BinEncodable, BinEncoder};

/// Used to specify the set of SupportedAlgorithms between a client and server
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialOrd, PartialEq, Eq, Clone, Copy, Hash)]
pub struct SupportedAlgorithms {
    // right now the number of Algorithms supported are fewer than 16..
    bit_map: u8,
}

impl SupportedAlgorithms {
    /// Return a new set of Supported algorithms
    pub fn new() -> Self {
        Self { bit_map: 0 }
    }

    /// Specify the entire set is supported
    pub fn all() -> Self {
        Self {
            bit_map: 0b0111_1111,
        }
    }

    /// Based on the set of Algorithms, return the supported set
    pub fn from_vec(algorithms: &[Algorithm]) -> Self {
        let mut supported = Self::new();

        for a in algorithms {
            supported.set(*a);
        }

        supported
    }

    fn pos(algorithm: Algorithm) -> Option<u8> {
        // not using the values from the RFC's to keep the bit_map space condensed
        #[allow(deprecated)]
        let bit_pos: Option<u8> = match algorithm {
            Algorithm::RSASHA1 => Some(0),
            Algorithm::RSASHA256 => Some(1),
            Algorithm::RSASHA1NSEC3SHA1 => Some(2),
            Algorithm::RSASHA512 => Some(3),
            Algorithm::ECDSAP256SHA256 => Some(4),
            Algorithm::ECDSAP384SHA384 => Some(5),
            Algorithm::ED25519 => Some(6),
            Algorithm::RSAMD5 | Algorithm::DSA | Algorithm::Unknown(_) => None,
        };

        bit_pos.map(|b| 1u8 << b)
    }

    fn from_pos(pos: u8) -> Option<Algorithm> {
        // TODO: should build a code generator or possibly a macro for deriving these inversions
        #[allow(deprecated)]
        match pos {
            0 => Some(Algorithm::RSASHA1),
            1 => Some(Algorithm::RSASHA256),
            2 => Some(Algorithm::RSASHA1NSEC3SHA1),
            3 => Some(Algorithm::RSASHA512),
            4 => Some(Algorithm::ECDSAP256SHA256),
            5 => Some(Algorithm::ECDSAP384SHA384),
            6 => Some(Algorithm::ED25519),
            _ => None,
        }
    }

    /// Set the specified algorithm as supported
    pub fn set(&mut self, algorithm: Algorithm) {
        if let Some(bit_pos) = Self::pos(algorithm) {
            self.bit_map |= bit_pos;
        }
    }

    /// Returns true if the algorithm is supported
    pub fn has(self, algorithm: Algorithm) -> bool {
        if let Some(bit_pos) = Self::pos(algorithm) {
            (bit_pos & self.bit_map) == bit_pos
        } else {
            false
        }
    }

    /// Return an Iterator over the supported set.
    pub fn iter(&self) -> SupportedAlgorithmsIter<'_> {
        SupportedAlgorithmsIter::new(self)
    }

    /// Return the count of supported algorithms
    pub fn len(self) -> u16 {
        // this is pretty much guaranteed to be less that u16::max_value()
        self.iter().count() as u16
    }

    /// Return true if no SupportedAlgorithms are set, this implies the option is not supported
    pub fn is_empty(self) -> bool {
        self.bit_map == 0
    }
}

impl Default for SupportedAlgorithms {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for SupportedAlgorithms {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        for a in self.iter() {
            a.fmt(f)?;
            f.write_str(", ")?;
        }

        Ok(())
    }
}

impl<'a> From<&'a [u8]> for SupportedAlgorithms {
    fn from(values: &'a [u8]) -> Self {
        let mut supported = Self::new();

        for a in values.iter().map(|i| Algorithm::from_u8(*i)) {
            match a {
                Algorithm::Unknown(v) => warn!("unrecognized algorithm: {}", v),
                a => supported.set(a),
            }
        }

        supported
    }
}

impl<'a> From<&'a SupportedAlgorithms> for Vec<u8> {
    fn from(value: &'a SupportedAlgorithms) -> Self {
        let mut bytes = Self::with_capacity(8); // today this is less than 8

        for a in value.iter() {
            bytes.push(a.into());
        }

        bytes.shrink_to_fit();
        bytes
    }
}

impl From<Algorithm> for SupportedAlgorithms {
    fn from(algorithm: Algorithm) -> Self {
        Self::from_vec(&[algorithm])
    }
}

pub struct SupportedAlgorithmsIter<'a> {
    algorithms: &'a SupportedAlgorithms,
    current: usize,
}

impl<'a> SupportedAlgorithmsIter<'a> {
    pub fn new(algorithms: &'a SupportedAlgorithms) -> Self {
        SupportedAlgorithmsIter {
            algorithms,
            current: 0,
        }
    }
}

impl<'a> Iterator for SupportedAlgorithmsIter<'a> {
    type Item = Algorithm;
    fn next(&mut self) -> Option<Self::Item> {
        // some quick bounds checking
        if self.current > u8::max_value() as usize {
            return None;
        }

        while let Some(algorithm) = SupportedAlgorithms::from_pos(self.current as u8) {
            self.current += 1;
            if self.algorithms.has(algorithm) {
                return Some(algorithm);
            }
        }

        None
    }
}

impl BinEncodable for SupportedAlgorithms {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        for a in self.iter() {
            encoder.emit_u8(a.into())?;
        }
        Ok(())
    }
}

#[test]
#[allow(deprecated)]
fn test_has() {
    let mut supported = SupportedAlgorithms::new();

    supported.set(Algorithm::RSASHA1);

    assert!(supported.has(Algorithm::RSASHA1));
    assert!(!supported.has(Algorithm::RSASHA1NSEC3SHA1));

    let mut supported = SupportedAlgorithms::new();

    supported.set(Algorithm::RSASHA256);
    assert!(!supported.has(Algorithm::RSASHA1));
    assert!(!supported.has(Algorithm::RSASHA1NSEC3SHA1));
    assert!(supported.has(Algorithm::RSASHA256));
}

#[test]
#[allow(deprecated)]

fn test_iterator() {
    let supported = SupportedAlgorithms::all();
    assert_eq!(supported.iter().count(), 7);

    // it just so happens that the iterator has a fixed order...
    let supported = SupportedAlgorithms::all();
    let mut iter = supported.iter();
    assert_eq!(iter.next(), Some(Algorithm::RSASHA1));
    assert_eq!(iter.next(), Some(Algorithm::RSASHA256));
    assert_eq!(iter.next(), Some(Algorithm::RSASHA1NSEC3SHA1));
    assert_eq!(iter.next(), Some(Algorithm::RSASHA512));
    assert_eq!(iter.next(), Some(Algorithm::ECDSAP256SHA256));
    assert_eq!(iter.next(), Some(Algorithm::ECDSAP384SHA384));
    assert_eq!(iter.next(), Some(Algorithm::ED25519));

    let mut supported = SupportedAlgorithms::new();
    supported.set(Algorithm::RSASHA256);
    supported.set(Algorithm::RSASHA512);

    let mut iter = supported.iter();
    assert_eq!(iter.next(), Some(Algorithm::RSASHA256));
    assert_eq!(iter.next(), Some(Algorithm::RSASHA512));
}

#[test]
#[allow(deprecated)]
fn test_vec() {
    let supported = SupportedAlgorithms::all();
    let array: Vec<u8> = (&supported).into();
    let decoded: SupportedAlgorithms = (&array as &[_]).into();

    assert_eq!(supported, decoded);

    let mut supported = SupportedAlgorithms::new();
    supported.set(Algorithm::RSASHA256);
    supported.set(Algorithm::ECDSAP256SHA256);
    supported.set(Algorithm::ECDSAP384SHA384);
    supported.set(Algorithm::ED25519);
    let array: Vec<u8> = (&supported).into();
    let decoded: SupportedAlgorithms = (&array as &[_]).into();

    assert_eq!(supported, decoded);
    assert!(!supported.has(Algorithm::RSASHA1));
    assert!(!supported.has(Algorithm::RSASHA1NSEC3SHA1));
    assert!(supported.has(Algorithm::RSASHA256));
    assert!(supported.has(Algorithm::ECDSAP256SHA256));
    assert!(supported.has(Algorithm::ECDSAP384SHA384));
    assert!(supported.has(Algorithm::ED25519));
}
