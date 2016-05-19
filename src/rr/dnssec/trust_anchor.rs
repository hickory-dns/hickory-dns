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
use std::io::Cursor;
use std::default::Default;

use openssl::crypto::pkey::{PKey, Role};

use ::rr::dnssec::Algorithm;

const ROOT_ANCHOR: &'static str = include_str!("Kjqmt7v.pem");

// TODO: these should also store some information, or more specifically, metadata from the signed
//  public certificate.
pub struct TrustAnchor {
  pkeys: Vec<Vec<u8>>
}

impl Default for TrustAnchor {
  fn default() -> TrustAnchor {
    let mut cursor = Cursor::new(ROOT_ANCHOR);
    let pkey = PKey::public_key_from_pem(&mut cursor).expect("Error parsing Kjqmt7v.pem");
    assert!(pkey.can(Role::Verify));
    assert!(pkey.can(Role::Encrypt));

    let alg = Algorithm::RSASHA256;

    TrustAnchor{ pkeys: vec![alg.public_key_to_vec(&pkey)] }
  }
}

impl TrustAnchor {
  pub fn new() -> TrustAnchor {
    TrustAnchor { pkeys: vec![] }
  }

  pub fn contains(&self, other_key: &[u8]) -> bool {
    self.pkeys.iter().any(|k|other_key == k as &[u8])
  }

  /// inserts the trust_anchor to the trusted chain
  pub fn insert_trust_anchor(&mut self, public_key: Vec<u8>) {
    if !self.contains(&public_key) {
      self.pkeys.push(public_key)
    }
  }
}
