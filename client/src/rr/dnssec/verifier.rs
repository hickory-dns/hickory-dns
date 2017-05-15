//! Verifier is a structure for performing many of the signing processes of the DNSSec specification

#[cfg(any(feature = "openssl", feature = "ring"))]
use chrono::Duration;

#[cfg(any(feature = "openssl", feature = "ring"))]
use op::Message;
#[cfg(any(feature = "openssl", feature = "ring"))]
use rr::{DNSClass, Name, Record, RecordType, RData};
#[cfg(any(feature = "openssl", feature = "ring"))]
use rr::dnssec::{Algorithm, DnsSecErrorKind, DnsSecResult, KeyPair};
use rr::dnssec::{PublicKey, PublicKeyEnum};
#[cfg(any(feature = "openssl", feature = "ring"))]
use rr::rdata::{DNSKEY, KEY, sig, SIG};
#[cfg(any(feature = "openssl", feature = "ring"))]
use serialize::binary::{BinEncoder, BinSerializable, EncodeMode};


/// Types which are able to verify DNS based signatures
pub trait Verifier {
    /// Return the algorithm which this Verifier covers
    fn algorithm(&self) -> Algorithm;

    /// Return the public key associated with this verifier
    fn key<'k>(&'k self) -> DnsSecResult<PublicKeyEnum<'k>>;

    /// Verifies the hash matches the signature with the current `key`.
    ///
    /// # Arguments
    ///
    /// * `hash` - the hash to be validated, see `hash_rrset`
    /// * `signature` - the signature to use to verify the hash, extracted from an `RData::RRSIG`
    ///                 for example.
    ///
    /// # Return value
    ///
    /// True if and only if the signature is valid for the hash.
    /// false if the `key`.
    fn verify(&self, hash: &[u8], signature: &[u8]) -> DnsSecResult<()> {
        self.key()?.verify(self.algorithm(), hash, signature)
    }
}

impl Verifier for DNSKEY {
    fn algorithm(&self) -> Algorithm {
        self.algorithm()
    }

    fn key<'k>(&'k self) -> DnsSecResult<PublicKeyEnum<'k>> {
        PublicKeyEnum::from_public_bytes(self.public_key(), self.algorithm())
    }
}

impl Verifier for KEY {
    fn algorithm(&self) -> Algorithm {
        self.algorithm()
    }

    fn key<'k>(&'k self) -> DnsSecResult<PublicKeyEnum<'k>> {
        PublicKeyEnum::from_public_bytes(self.public_key(), self.algorithm())
    }
}
