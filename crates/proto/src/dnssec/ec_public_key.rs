// Copyright 2017 Brian Smith <brian@briansmith.org>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use super::{Algorithm, PublicKey, ring_like::signature};
use crate::error::{ProtoError, ProtoResult};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ECPublicKey {
    buf: [u8; MAX_LEN],
    len: usize,
    pub(crate) algorithm: Algorithm,
}

// The length of the longest supported EC public key (P-384).
const MAX_LEN: usize = 1 + (2 * 48);

impl ECPublicKey {
    /// ```text
    /// RFC 6605                    ECDSA for DNSSEC                  April 2012
    ///
    ///   4.  DNSKEY and RRSIG Resource Records for ECDSA
    ///
    ///   ECDSA public keys consist of a single value, called "Q" in FIPS
    ///   186-3.  In DNSSEC keys, Q is a simple bit string that represents the
    ///   uncompressed form of a curve point, "x | y".
    ///
    ///   The ECDSA signature is the combination of two non-negative integers,
    ///   called "r" and "s" in FIPS 186-3.  The two integers, each of which is
    ///   formatted as a simple octet string, are combined into a single longer
    ///   octet string for DNSSEC as the concatenation "r | s".  (Conversion of
    ///   the integers to bit strings is described in Section C.2 of FIPS
    ///   186-3.)  For P-256, each integer MUST be encoded as 32 octets; for
    ///   P-384, each integer MUST be encoded as 48 octets.
    ///
    ///   The algorithm numbers associated with the DNSKEY and RRSIG resource
    ///   records are fully defined in the IANA Considerations section.  They
    ///   are:
    ///
    ///   o  DNSKEY and RRSIG RRs signifying ECDSA with the P-256 curve and
    ///      SHA-256 use the algorithm number 13.
    ///
    ///   o  DNSKEY and RRSIG RRs signifying ECDSA with the P-384 curve and
    ///      SHA-384 use the algorithm number 14.
    ///
    ///   Conformant implementations that create records to be put into the DNS
    ///   MUST implement signing and verification for both of the above
    ///   algorithms.  Conformant DNSSEC verifiers MUST implement verification
    ///   for both of the above algorithms.
    /// ```
    pub(super) fn from_public_bytes(public_key: &[u8], algorithm: Algorithm) -> ProtoResult<Self> {
        Self::from_unprefixed(public_key, algorithm)
    }

    // DNSSEC encodes uncompressed EC public keys without the standard 0x04
    // prefix that indicates they are uncompressed, but crypto libraries
    // require that prefix.
    pub(super) fn from_unprefixed(
        without_prefix: &[u8],
        algorithm: Algorithm,
    ) -> ProtoResult<Self> {
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
        Ok(Self {
            buf,
            len,
            algorithm,
        })
    }

    pub(super) fn prefixed_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub(super) fn unprefixed_bytes(&self) -> &[u8] {
        &self.buf[1..self.len]
    }
}

impl PublicKey for ECPublicKey {
    fn public_bytes(&self) -> &[u8] {
        self.unprefixed_bytes()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> ProtoResult<()> {
        // TODO: assert_eq!(algorithm, self.algorithm); once *ring* allows this.
        let alg = match self.algorithm {
            Algorithm::ECDSAP256SHA256 => &signature::ECDSA_P256_SHA256_FIXED,
            Algorithm::ECDSAP384SHA384 => &signature::ECDSA_P384_SHA384_FIXED,
            _ => return Err("only ECDSAP256SHA256 and ECDSAP384SHA384 are supported by Ec".into()),
        };
        let public_key = signature::UnparsedPublicKey::new(alg, self.prefixed_bytes());
        public_key
            .verify(message, signature)
            .map_err(|_| ProtoError::Crypto("ECDSA signature verification failed"))
    }

    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}
