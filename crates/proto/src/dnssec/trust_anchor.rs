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

use alloc::{borrow::ToOwned, format, vec::Vec};
use core::str::FromStr;
use std::{fs, path::Path};

use crate::dnssec::PublicKey;
use crate::rr::{LowerName, Name};
use crate::serialize::txt::ParseError;
use crate::serialize::txt::trust_anchor::{self, Entry};

use super::Verifier;
use super::rdata::DS;
use super::{Algorithm, DnsSecError, PublicKeyBuf};

const ROOT_ANCHOR_2018: &[u8] = include_bytes!("roots/20326.rsa");
const ROOT_ANCHOR_2024: &[u8] = include_bytes!("roots/38696.rsa");

/// The root set of trust anchors for validating DNSSEC, anything in this set will be trusted
#[derive(Clone)]
pub struct TrustAnchors {
    public_keys: Vec<(LowerName, PublicKeyBuf)>,
    ds_records: Vec<(LowerName, DS)>,
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
            ds_records: vec![],
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

    /// Determines if a DS record is in the set.
    pub fn contains_ds(&self, ds: &DS, name: &LowerName) -> bool {
        self.ds_records.iter().any(|(n, d)| n == name && d == ds)
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

    /// Inserts a DS record as a trust anchor.
    ///
    /// Returns `Ok(false)` if the DS record is already in the set.
    ///
    /// # Errors
    ///
    /// Returns an error if the DS record uses an unsupported algorithm or digest type. Such a
    /// record can never authenticate a DNSKEY, so anchoring a zone with it would only make the
    /// zone unverifiable.
    pub fn insert_ds(&mut self, ds: DS, name: LowerName) -> Result<bool, DnsSecError> {
        if !ds.algorithm().is_supported() {
            return Err(format!(
                "unsupported algorithm in DS trust anchor for {name}: {}",
                ds.algorithm()
            )
            .into());
        }

        if !ds.digest_type().is_supported() {
            return Err(format!(
                "unsupported digest type in DS trust anchor for {name}: {:?}",
                ds.digest_type()
            )
            .into());
        }

        if self.contains_ds(&ds, &name) {
            return Ok(false);
        }
        self.ds_records.push((name, ds));
        Ok(true)
    }

    /// Looks up DS records for a name.
    pub fn lookup_ds<'a>(&'a self, name: &'a LowerName) -> impl Iterator<Item = &'a DS> + 'a {
        self.ds_records
            .iter()
            .filter(move |(n, _)| n == name)
            .map(|(_, d)| d)
    }

    /// Number of keys and DS records.
    pub fn len(&self) -> usize {
        self.public_keys.len() + self.ds_records.len()
    }

    /// Returns true if there are no keys or DS records.
    pub fn is_empty(&self) -> bool {
        self.public_keys.is_empty() && self.ds_records.is_empty()
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

        Ok(Self {
            public_keys,
            ds_records: vec![],
        })
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
            ds_records: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        dnssec::{
            Algorithm, DigestType, PublicKeyBuf,
            rdata::DS,
            trust_anchor::{ROOT_ANCHOR_2024, TrustAnchors},
        },
        rr::{LowerName, Name},
    };
    use alloc::{borrow::ToOwned, vec, vec::Vec};

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

    #[test]
    fn insert_ds() {
        let mut trust = TrustAnchors::empty();
        assert!(trust.is_empty());

        let name = LowerName::from(Name::from_ascii("example.com.").unwrap());
        let ds = DS::new(1, Algorithm::ED25519, DigestType::SHA256, vec![0; 32]);
        assert!(trust.insert_ds(ds.clone(), name.clone()).unwrap());
        assert!(
            !trust.insert_ds(ds.clone(), name.clone()).unwrap(),
            "duplicate"
        );

        assert!(!trust.is_empty(), "DS-only anchors must not be empty");
        assert_eq!(1, trust.len());
        assert!(trust.contains_ds(&ds, &name));
        assert_eq!(vec![&ds], trust.lookup_ds(&name).collect::<Vec<_>>());

        let other = LowerName::from(Name::from_ascii("example.net.").unwrap());
        assert!(!trust.contains_ds(&ds, &other));
        assert_eq!(0, trust.lookup_ds(&other).count());
    }

    /// A DS record that can never authenticate a DNSKEY must not become a trust anchor: the
    /// validator would otherwise treat the anchored zone as insecure.
    #[test]
    fn insert_ds_rejects_unsupported() {
        let mut trust = TrustAnchors::empty();
        let name = LowerName::from(Name::from_ascii("example.com.").unwrap());

        let unknown_digest = DS::new(1, Algorithm::ED25519, DigestType::Unknown(255), vec![0; 32]);
        assert!(trust.insert_ds(unknown_digest, name.clone()).is_err());

        let unknown_algorithm =
            DS::new(1, Algorithm::Unknown(255), DigestType::SHA256, vec![0; 32]);
        assert!(trust.insert_ds(unknown_algorithm, name.clone()).is_err());

        assert!(trust.is_empty());
        assert_eq!(0, trust.lookup_ds(&name).count());
    }
}
