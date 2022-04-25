// Copyright 2017 Brian Smith <brian@briansmith.org>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use super::Algorithm;
use crate::error::*;

#[allow(unreachable_pub)]
#[derive(Clone, Copy, PartialEq)]
pub struct ECPublicKey {
    buf: [u8; MAX_LEN],
    len: usize,
}

// The length of the longest supported EC public key (P-384).
const MAX_LEN: usize = 1 + (2 * 48);

#[allow(unreachable_pub)]
impl ECPublicKey {
    // DNSSEC encodes uncompressed EC public keys without the standard 0x04
    // prefix that indicates they are uncompressed, but crypto libraries
    // require that prefix.
    pub fn from_unprefixed(without_prefix: &[u8], algorithm: Algorithm) -> ProtoResult<Self> {
        let field_len = match algorithm {
            Algorithm::ECDSAP256SHA256 => 32,
            Algorithm::ECDSAP384SHA384 => 48,
            _ => return Err("only ECDSAP256SHA256 and ECDSAP384SHA384 are supported by Ec".into()),
        };
        let len = 1 + (2 * field_len);
        if len - 1 != without_prefix.len() {
            return Err("EC public key is the wrong length".into());
        }
        let mut buf = [0x04u8; MAX_LEN];
        buf[1..len].copy_from_slice(without_prefix);
        Ok(Self { buf, len })
    }

    pub fn prefixed_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    #[cfg(feature = "ring")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ring")))]
    pub fn unprefixed_bytes(&self) -> &[u8] {
        &self.buf[1..self.len]
    }
}
