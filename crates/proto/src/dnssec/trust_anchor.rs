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

#[cfg(feature = "text-parsing")]
use alloc::string::{String, ToString};
use alloc::{borrow::ToOwned, vec::Vec};
#[cfg(feature = "text-parsing")]
use core::str::FromStr;
#[cfg(feature = "text-parsing")]
use std::{fs, path::Path};

use crate::dnssec::PublicKey;
#[cfg(feature = "text-parsing")]
use crate::serialize::txt::trust_anchor::{self, Entry};

#[cfg(feature = "text-parsing")]
use super::Verifier;
use super::{Algorithm, PublicKeyBuf};

const ROOT_ANCHOR_2018: &[u8] = include_bytes!("roots/20326.rsa");
const ROOT_ANCHOR_2024: &[u8] = include_bytes!("roots/38696.rsa");

/// The root set of trust anchors for validating DNSSEC, anything in this set will be trusted
#[derive(Clone)]
pub struct TrustAnchor {
    // TODO: these should also store some information, or more specifically, metadata from the signed
    //  public certificate.
    pkeys: Vec<PublicKeyBuf>,
}

impl Default for TrustAnchor {
    fn default() -> Self {
        Self {
            pkeys: vec![
                PublicKeyBuf::new(ROOT_ANCHOR_2018.to_owned(), Algorithm::RSASHA256),
                PublicKeyBuf::new(ROOT_ANCHOR_2024.to_owned(), Algorithm::RSASHA256),
            ],
        }
    }
}

impl TrustAnchor {
    /// Creates a new empty trust anchor set
    pub fn new() -> Self {
        Self { pkeys: vec![] }
    }

    /// determines if the key is in the trust anchor set with the raw dnskey bytes
    ///
    /// # Arguments
    ///
    /// * `other_key` - The raw dnskey in bytes
    /// * `algorithm` - The key's algorithm
    pub fn contains_dnskey_bytes(&self, other_key: &[u8], algorithm: Algorithm) -> bool {
        self.pkeys
            .iter()
            .any(|k| other_key == k.public_bytes() && algorithm == k.algorithm())
    }

    /// determines if the key is in the trust anchor set
    pub fn contains<P: PublicKey + ?Sized>(&self, other_key: &P) -> bool {
        self.contains_dnskey_bytes(other_key.public_bytes(), other_key.algorithm())
    }

    /// inserts the trust_anchor to the trusted chain
    pub fn insert_trust_anchor<P: PublicKey + ?Sized>(&mut self, public_key: &P) {
        if !self.contains(public_key) {
            self.pkeys.push(PublicKeyBuf::new(
                public_key.public_bytes().to_vec(),
                public_key.algorithm(),
            ))
        }
    }

    /// get the trust anchor at the specified index
    pub fn get(&self, idx: usize) -> &PublicKeyBuf {
        &self.pkeys[idx]
    }

    /// number of keys in trust_anchor
    pub fn len(&self) -> usize {
        self.pkeys.len()
    }

    /// returns true if there are no keys in the trust_anchor
    pub fn is_empty(&self) -> bool {
        self.pkeys.is_empty()
    }

    /// loads a trust anchor from a file of DNSKEY records
    #[cfg(feature = "text-parsing")]
    pub fn read_from_file(path: &Path) -> Result<Self, String> {
        let contents = fs::read_to_string(path).map_err(|e| e.to_string())?;
        contents.parse()
    }
}

#[cfg(feature = "text-parsing")]
impl FromStr for TrustAnchor {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, String> {
        let parser = trust_anchor::Parser::new(input);
        let entries = parser.parse().map_err(|e| e.to_string())?;

        let mut trust_anchor = Self::new();
        for entry in entries {
            let Entry::DNSKEY(record) = entry;
            let dnskey = record.data();
            let key = dnskey.key()?;
            trust_anchor.insert_trust_anchor(&*key);
        }

        Ok(trust_anchor)
    }
}

#[cfg(test)]
mod tests {
    use crate::dnssec::{
        Algorithm, PublicKey,
        trust_anchor::{ROOT_ANCHOR_2024, TrustAnchor},
    };

    #[test]
    fn test_contains_dnskey_bytes() {
        let trust = TrustAnchor::default();
        assert_eq!(trust.get(1).public_bytes(), ROOT_ANCHOR_2024);
        assert!(trust.contains_dnskey_bytes(ROOT_ANCHOR_2024, Algorithm::RSASHA256));
    }

    #[test]
    #[cfg(feature = "text-parsing")]
    fn can_load_trust_anchor_file() {
        let input = include_str!("../../tests/test-data/root.key");

        let trust_anchor = input.parse::<TrustAnchor>().unwrap();
        assert_eq!(3, trust_anchor.len());
    }
}
