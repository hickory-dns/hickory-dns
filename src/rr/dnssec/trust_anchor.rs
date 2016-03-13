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

use openssl::crypto::pkey::{PKey, Role};

use ::rr::dnssec::Algorithm;

const ROOT_ANCHOR: &'static str = include_str!("Kjqmt7v.pem");

pub struct TrustAnchor {
  pkey: Vec<u8>
}

impl TrustAnchor {
  pub fn new() -> TrustAnchor {
    let mut cursor = Cursor::new(ROOT_ANCHOR);
    let pkey = PKey::public_key_from_pem(&mut cursor).expect("Error parsing Kjqmt7v.pem");
    assert!(pkey.can(Role::Verify));
    assert!(pkey.can(Role::Encrypt));

    let alg = Algorithm::RSASHA256;

    TrustAnchor{ pkey: alg.public_key_to_vec(&pkey) }
  }

  pub fn contains(&self, other_key: &[u8]) -> bool {
    self.pkey == other_key
  }
}
