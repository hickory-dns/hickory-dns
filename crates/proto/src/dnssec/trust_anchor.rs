/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Allows for the root trust_anchor to either be added to or replaced for dns_sec validation.

use alloc::{borrow::ToOwned, vec::Vec};
#[cfg(feature = "text-parsing")]
use core::str::FromStr;
#[cfg(feature = "text-parsing")]
use std::{fs, path::Path};

use crate::dnssec::PublicKey;
#[cfg(feature = "text-parsing")]
use crate::serialize::txt::ParseError;
#[cfg(feature = "text-parsing")]
use crate::serialize::txt::trust_anchor::{self, Entry};

#[cfg(feature = "text-parsing")]
use super::Verifier;
use super::{Algorithm, PublicKeyBuf};

const ROOT_ANCHOR_2018: &[u8] = include_bytes!("roots/20326.rsa");
const ROOT_ANCHOR_2024: &[u8] = include_bytes!("roots/38696.rsa");

/// The root set of trust anchors for validating DNSSEC, anything in this set will be trusted
#[derive(Clone)]
pub struct TrustAnchors {
    // TODO: these should also store some information, or more specifically, metadata from the signed
    //  public certificate.
    pkeys: Vec<PublicKeyBuf>,
}

impl TrustAnchors {
    /// loads a trust anchor from a file of DNSKEY records
    #[cfg(feature = "text-parsing")]
    pub fn from_file(path: &Path) -> Result<Self, ParseError> {
        Self::from_str(&fs::read_to_string(path)?)
    }

    /// Creates a new empty trust anchor set
    ///
    /// If you want to use the default root anchors, use `TrustAnchor::default()`.
    pub fn empty() -> Self {
        Self { pkeys: vec![] }
    }

    /// determines if the key is in the trust anchor set
    pub fn contains<P: PublicKey + ?Sized>(&self, other_key: &P) -> bool {
        self.pkeys.iter().any(|k| {
            other_key.public_bytes() == k.public_bytes() && other_key.algorithm() == k.algorithm()
        })
    }

    /// inserts the trust_anchor to the trusted chain
    pub fn insert<P: PublicKey + ?Sized>(&mut self, public_key: &P) -> bool {
        if self.contains(public_key) {
            return false;
        }

        self.pkeys.push(PublicKeyBuf::new(
            public_key.public_bytes().to_vec(),
            public_key.algorithm(),
        ));
        true
    }

    /// get the trust anchor at the specified index
    pub fn get(&self, idx: usize) -> Option<&PublicKeyBuf> {
        self.pkeys.get(idx)
    }

    /// number of keys in trust_anchor
    pub fn len(&self) -> usize {
        self.pkeys.len()
    }

    /// returns true if there are no keys in the trust_anchor
    pub fn is_empty(&self) -> bool {
        self.pkeys.is_empty()
    }
}

#[cfg(feature = "text-parsing")]
impl FromStr for TrustAnchors {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let parser = trust_anchor::Parser::new(input);
        let entries = parser.parse()?;

        let mut pkeys = Vec::new();
        for entry in entries {
            let Entry::DNSKEY(record) = entry;
            let dnskey = record.data();
            let key = dnskey.key()?;
            pkeys.push(PublicKeyBuf::new(
                key.public_bytes().to_vec(),
                dnskey.algorithm(),
            ));
        }

        Ok(Self { pkeys })
    }
}

impl Default for TrustAnchors {
    fn default() -> Self {
        Self {
            pkeys: vec![
                PublicKeyBuf::new(ROOT_ANCHOR_2018.to_owned(), Algorithm::RSASHA256),
                PublicKeyBuf::new(ROOT_ANCHOR_2024.to_owned(), Algorithm::RSASHA256),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::dnssec::{
        Algorithm, PublicKey, PublicKeyBuf,
        trust_anchor::{ROOT_ANCHOR_2024, TrustAnchors},
    };
    use alloc::borrow::ToOwned;

    #[test]
    fn test_contains_dnskey_bytes() {
        let trust = TrustAnchors::default();
        assert_eq!(trust.get(1).unwrap().public_bytes(), ROOT_ANCHOR_2024);
        let pub_key = PublicKeyBuf::new(ROOT_ANCHOR_2024.to_owned(), Algorithm::RSASHA256);
        assert!(trust.contains(&pub_key));
    }

    #[test]
    #[cfg(feature = "text-parsing")]
    fn can_load_trust_anchor_file() {
        let input = include_str!("../../tests/test-data/root.key");

        let trust_anchor = input.parse::<TrustAnchors>().unwrap();
        assert_eq!(3, trust_anchor.len());
    }
}
