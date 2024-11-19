// Copyright 2017 Brian Smith <brian@briansmith.org>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::error::*;

pub(crate) struct RSAPublicKey {
    n: Vec<u8>,
    e: Vec<u8>,
}

impl RSAPublicKey {
    pub(crate) fn try_from(encoded: &[u8]) -> ProtoResult<Self> {
        let (e_len_len, e_len) = match encoded.first() {
            Some(&0) if encoded.len() >= 3 => {
                (3, (usize::from(encoded[1]) << 8) | usize::from(encoded[2]))
            }
            Some(e_len) if *e_len != 0 => (1, usize::from(*e_len)),
            _ => {
                return Err("bad public key".into());
            }
        };

        if encoded.len() < e_len_len + e_len {
            return Err("bad public key".into());
        };

        let (e, n) = encoded[e_len_len..].split_at(e_len);

        Ok(Self {
            n: n.to_vec(),
            e: e.to_vec(),
        })
    }

    pub(crate) fn n(&self) -> &[u8] {
        &self.n
    }
    pub(crate) fn e(&self) -> &[u8] {
        &self.e
    }
}
