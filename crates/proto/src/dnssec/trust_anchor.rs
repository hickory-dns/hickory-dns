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
use core::str::FromStr;
use std::{fs, path::Path};

use crate::dnssec::PublicKey;
use crate::rr::{LowerName, Name};
use crate::serialize::txt::ParseError;
use crate::serialize::txt::trust_anchor::{self, Entry};

use super::Verifier;
use super::{Algorithm, PublicKeyBuf};

const ROOT_ANCHOR_2018: &[u8] = include_bytes!("roots/20326.rsa");
const ROOT_ANCHOR_2024: &[u8] = include_bytes!("roots/38696.rsa");

/// The root set of trust anchors for validating DNSSEC, anything in this set will be trusted
#[derive(Clone)]
pub struct TrustAnchors {
    public_keys: Vec<(LowerName, PublicKeyBuf)>,
}

impl TrustAnchors {
    /// Loads a trust anchor from a file of DNSKEY records.
    pub fn from_file(path: &Path) -> Result<Self, ParseError> {
        Self::from_str(&fs::read_to_string(path)?)
    }

    /// Creates a new empty trust anchor set
    ///
    /// If you want to use the default root anchors, use `TrustAnchor::default()`.
    pub fn empty() -> Self {
        Self {
            public_keys: vec![],
        }
    }

    /// Determines if the key and name is in the trust anchor set.
    pub fn contains<P: PublicKey + ?Sized>(&self, public_key: &P, name: &LowerName) -> bool {
        self.public_keys
            .iter()
            .any(|(trust_anchor_name, trust_anchor_public_key)| {
                trust_anchor_name == name
                    && trust_anchor_public_key.public_bytes() == public_key.public_bytes()
                    && trust_anchor_public_key.algorithm() == public_key.algorithm()
            })
    }

    /// Inserts a public key as a trust anchor.
    pub fn insert<P: PublicKey + ?Sized>(&mut self, public_key: &P, name: LowerName) -> bool {
        if self.contains(public_key, &name) {
            return false;
        }

        self.public_keys.push((
            name,
            PublicKeyBuf::new(public_key.public_bytes().to_vec(), public_key.algorithm()),
        ));
        true
    }

    /// Number of keys.
    pub fn len(&self) -> usize {
        self.public_keys.len()
    }

    /// Returns true if there are no keys.
    pub fn is_empty(&self) -> bool {
        self.public_keys.is_empty()
    }
}

impl FromStr for TrustAnchors {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let parser = trust_anchor::Parser::new(input);
        let entries = parser.parse()?;

        let mut public_keys = Vec::new();
        for entry in entries {
            let Entry::DNSKEY(record) = entry;
            let dnskey = record.data();
            let key = dnskey.key()?;
            let public_key_buf = PublicKeyBuf::new(key.public_bytes().to_vec(), dnskey.algorithm());
            public_keys.push((record.name().into(), public_key_buf));
        }

        Ok(Self { public_keys })
    }
}

impl Default for TrustAnchors {
    fn default() -> Self {
        Self {
            public_keys: vec![
                (
                    Name::root().into(),
                    PublicKeyBuf::new(ROOT_ANCHOR_2018.to_owned(), Algorithm::RSASHA256),
                ),
                (
                    Name::root().into(),
                    PublicKeyBuf::new(ROOT_ANCHOR_2024.to_owned(), Algorithm::RSASHA256),
                ),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        dnssec::{
            Algorithm, PublicKeyBuf,
            trust_anchor::{ROOT_ANCHOR_2024, TrustAnchors},
        },
        rr::Name,
    };
    use alloc::borrow::ToOwned;

    #[test]
    fn test_contains_dnskey_bytes() {
        let trust = TrustAnchors::default();
        let pub_key = PublicKeyBuf::new(ROOT_ANCHOR_2024.to_owned(), Algorithm::RSASHA256);
        assert!(trust.contains(&pub_key, &Name::root().into()));
    }

    #[test]
    fn can_load_trust_anchor_file() {
        let input = include_str!("../../tests/test-data/root.key");

        let trust_anchor = input.parse::<TrustAnchors>().unwrap();
        assert_eq!(3, trust_anchor.len());
    }
}
