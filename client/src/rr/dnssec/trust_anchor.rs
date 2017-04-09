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

//! Allows for the root trust_anchor to either be added to or replaced for dns_sec validation.

use std::default::Default;

#[cfg(feature = "openssl")]
use openssl::rsa::Rsa;

use rr::dnssec::KeyPair;

#[cfg(feature = "openssl")]
const ROOT_ANCHOR: &'static str = include_str!("Kjqmt7v.pem");

/// The root set of trust anchors for validating DNSSec, anything in this set will be trusted
pub struct TrustAnchor {
    // TODO: these should also store some information, or more specifically, metadata from the signed
    //  public certificate.
    pkeys: Vec<Vec<u8>>,
}

impl Default for TrustAnchor {
    #[cfg(feature = "openssl")]
    fn default() -> TrustAnchor {
        let rsa =
            Rsa::public_key_from_pem(ROOT_ANCHOR.as_bytes()).expect("Error parsing Kjqmt7v.pem");
        let key = KeyPair::from_rsa(rsa).expect("Error creating KeyPair from RSA key");

        TrustAnchor {
            pkeys: vec![key.to_public_bytes()
                            .expect("could not convert key to bytes")],
        }
    }

    #[cfg(not(feature = "openssl"))]
    fn default() -> TrustAnchor {
        TrustAnchor { pkeys: vec![] }
    }
}

impl TrustAnchor {
    /// Creates a new empty trust anchor set
    pub fn new() -> TrustAnchor {
        TrustAnchor { pkeys: vec![] }
    }

    /// determines if the key is in the trust anchor set
    pub fn contains(&self, other_key: &[u8]) -> bool {
        self.pkeys.iter().any(|k| other_key == k as &[u8])
    }

    /// inserts the trust_anchor to the trusted chain
    pub fn insert_trust_anchor(&mut self, public_key: Vec<u8>) {
        if !self.contains(&public_key) {
            self.pkeys.push(public_key)
        }
    }

    /// get the trust anchor at the specified index
    pub fn get(&self, idx: usize) -> &[u8] {
        &self.pkeys[idx]
    }
}

#[test]
#[cfg(feature = "openssl")]
fn test_kjqmt7v() {
    let trust = TrustAnchor::default();
    let test_kjqmt7v: Vec<u8> =
        vec![3, 1, 0, 1, 168, 0, 32, 169, 85, 102, 186, 66, 232, 134, 187, 128, 76, 218, 132, 228,
             126, 245, 109, 189, 122, 236, 97, 38, 21, 85, 44, 236, 144, 109, 33, 22, 208, 239,
             32, 112, 40, 197, 21, 84, 20, 77, 254, 175, 231, 199, 203, 143, 0, 93, 209, 130, 52,
             19, 58, 192, 113, 10, 129, 24, 44, 225, 253, 20, 173, 34, 131, 188, 131, 67, 95, 157,
             242, 246, 49, 50, 81, 147, 26, 23, 109, 240, 218, 81, 229, 79, 66, 230, 4, 134, 13,
             251, 53, 149, 128, 37, 15, 85, 156, 197, 67, 196, 255, 213, 28, 190, 61, 232, 207,
             208, 103, 25, 35, 127, 159, 196, 126, 231, 41, 218, 6, 131, 95, 164, 82, 232, 37,
             233, 161, 142, 188, 46, 203, 207, 86, 52, 116, 101, 44, 51, 207, 86, 169, 3, 59, 205,
             245, 217, 115, 18, 23, 151, 236, 128, 137, 4, 27, 110, 3, 161, 183, 45, 10, 115, 91,
             152, 78, 3, 104, 115, 9, 51, 35, 36, 242, 124, 45, 186, 133, 233, 219, 21, 232, 58,
             1, 67, 56, 46, 151, 75, 6, 33, 193, 142, 98, 94, 206, 201, 7, 87, 125, 158, 123, 173,
             233, 82, 65, 168, 30, 187, 232, 169, 1, 212, 211, 39, 110, 64, 177, 20, 192, 162,
             230, 252, 56, 209, 156, 46, 106, 171, 2, 100, 75, 40, 19, 245, 117, 252, 33, 96, 30,
             13, 238, 73, 205, 158, 233, 106, 67, 16, 62, 82, 77, 98, 135, 61];

    assert_eq!(trust.get(0), &test_kjqmt7v as &[u8]);
    assert!(trust.contains(&test_kjqmt7v));
}
