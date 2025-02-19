// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Verifier is a structure for performing many of the signing processes of the DNSSEC specification

use alloc::sync::Arc;

use super::{
    Algorithm, PublicKey,
    rdata::{RRSIG, SIG},
    tbs::{self, TBS},
};
use crate::{
    error::ProtoResult,
    rr::{DNSClass, Name, Record},
    serialize::binary::BinEncodable,
};

/// Types which are able to verify DNS based signatures
pub trait Verifier {
    /// Return the algorithm which this Verifier covers
    fn algorithm(&self) -> Algorithm;

    /// Return the public key associated with this verifier
    fn key(&self) -> ProtoResult<Arc<dyn PublicKey + '_>>;

    /// Verifies the hash matches the signature with the current `key`.
    ///
    /// # Arguments
    ///
    /// * `hash` - the hash to be validated, see `rrset_tbs`
    /// * `signature` - the signature to use to verify the hash, extracted from an `RData::RRSIG`
    ///                 for example.
    ///
    /// # Return value
    ///
    /// True if and only if the signature is valid for the hash.
    /// false if the `key`.
    fn verify(&self, hash: &[u8], signature: &[u8]) -> ProtoResult<()> {
        self.key()?.verify(hash, signature)
    }

    /// Verifies a message with the against the given signature, i.e. SIG0
    ///
    /// # Arguments
    ///
    /// * `message` - the message to verify
    /// * `signature` - the signature to use for validation
    ///
    /// # Return value
    ///
    /// `true` if the message could be validated against the signature, `false` otherwise
    fn verify_message<M: BinEncodable>(
        &self,
        message: &M,
        signature: &[u8],
        sig0: &SIG,
    ) -> ProtoResult<()> {
        tbs::message_tbs(message, sig0).and_then(|tbs| self.verify(tbs.as_ref(), signature))
    }

    /// Verifies an RRSig with the associated key, e.g. DNSKEY
    ///
    /// # Arguments
    ///
    /// * `name` - name associated with the rrsig being validated
    /// * `dns_class` - DNSClass of the records, generally IN
    /// * `sig` - signature record being validated
    /// * `records` - Records covered by SIG
    fn verify_rrsig<'a>(
        &self,
        name: &Name,
        dns_class: DNSClass,
        sig: &RRSIG,
        records: impl Iterator<Item = &'a Record>,
    ) -> ProtoResult<()> {
        let rrset_tbs = TBS::from_sig(name, dns_class, sig, records)?;
        self.verify(rrset_tbs.as_ref(), sig.sig())
    }
}
