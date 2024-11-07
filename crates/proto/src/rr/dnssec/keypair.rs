// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[cfg(feature = "dnssec-openssl")]
use openssl::ec::{EcGroup, EcKey};
#[cfg(feature = "dnssec-openssl")]
use openssl::nid::Nid;
#[cfg(feature = "dnssec-openssl")]
use openssl::pkey::{PKey, Private};
#[cfg(feature = "dnssec-openssl")]
use openssl::rsa::Rsa as OpenSslRsa;
#[cfg(feature = "dnssec-openssl")]
use openssl::sign::Signer;

#[cfg(feature = "dnssec-ring")]
use ring::{
    rand::{self, SystemRandom},
    signature::{
        EcdsaKeyPair, Ed25519KeyPair, KeyPair as RingKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING,
        ECDSA_P384_SHA384_FIXED_SIGNING,
    },
};

use super::KeyFormat;
use crate::error::{DnsSecErrorKind, DnsSecResult};
#[cfg(feature = "dnssec-openssl")]
use crate::rr::dnssec::DigestType;
use crate::rr::dnssec::{Algorithm, PublicKeyBuf, TBS};

/// Decode private key
#[allow(unused, clippy::match_single_binding)]
pub fn decode_key(
    bytes: &[u8],
    password: Option<&str>,
    algorithm: Algorithm,
    format: KeyFormat,
) -> DnsSecResult<KeyPair> {
    //  empty string prevents openssl from triggering a read from stdin...
    let password = password.unwrap_or("");
    let password = password.as_bytes();

    #[allow(deprecated)]
    match algorithm {
        Algorithm::Unknown(v) => Err(format!("unknown algorithm: {v}").into()),
        #[cfg(feature = "dnssec-openssl")]
        e @ Algorithm::RSASHA1 | e @ Algorithm::RSASHA1NSEC3SHA1 => {
            Err(format!("unsupported Algorithm (insecure): {e:?}").into())
        }
        #[cfg(feature = "dnssec-openssl")]
        Algorithm::RSASHA256 | Algorithm::RSASHA512 => {
            let key = match format {
                KeyFormat::Der => OpenSslRsa::private_key_from_der(bytes)
                    .map_err(|e| format!("error reading RSA as DER: {e}"))?,
                KeyFormat::Pem => {
                    let key = OpenSslRsa::private_key_from_pem_passphrase(bytes, password);

                    key.map_err(|e| format!("could not decode RSA from PEM, bad password?: {e}"))?
                }
                e => {
                    return Err(format!(
                        "unsupported key format with RSA (DER or PEM only): \
                         {e:?}"
                    )
                    .into())
                }
            };

            Ok(KeyPair::from_rsa(key, algorithm)
                .map_err(|e| format!("could not translate RSA to KeyPair: {e}"))?)
        }
        Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => match format {
            #[cfg(feature = "dnssec-openssl")]
            KeyFormat::Der => {
                let key = EcKey::private_key_from_der(bytes)
                    .map_err(|e| format!("error reading EC as DER: {e}"))?;

                Ok(KeyPair::from_ec_key(key, algorithm)
                    .map_err(|e| format!("could not translate RSA to KeyPair: {e}"))?)
            }
            #[cfg(feature = "dnssec-openssl")]
            KeyFormat::Pem => {
                let key = EcKey::private_key_from_pem_passphrase(bytes, password)
                    .map_err(|e| format!("could not decode EC from PEM, bad password?: {e}"))?;

                Ok(KeyPair::from_ec_key(key, algorithm)
                    .map_err(|e| format!("could not translate RSA to KeyPair: {e}"))?)
            }
            #[cfg(feature = "dnssec-ring")]
            KeyFormat::Pkcs8 => {
                let rng = SystemRandom::new();
                let ring_algorithm = if algorithm == Algorithm::ECDSAP256SHA256 {
                    &ECDSA_P256_SHA256_FIXED_SIGNING
                } else {
                    &ECDSA_P384_SHA384_FIXED_SIGNING
                };
                let key = EcdsaKeyPair::from_pkcs8(ring_algorithm, bytes, &rng)?;

                Ok(KeyPair::from_ecdsa(key))
            }
            e => Err(format!("unsupported key format with EC: {e:?}").into()),
        },
        Algorithm::ED25519 => match format {
            #[cfg(feature = "dnssec-ring")]
            KeyFormat::Pkcs8 => {
                let key = Ed25519KeyPair::from_pkcs8(bytes)?;

                Ok(KeyPair::from_ed25519(key))
            }
            e => Err(
                format!("unsupported key format with ED25519 (only Pkcs8 supported): {e:?}").into(),
            ),
        },
        e => Err(format!("unsupported Algorithm, enable openssl or ring feature: {e:?}").into()),
    }
}

/// A public and private key pair, the private portion is not required.
///
/// This supports all the various public/private keys which Hickory DNS is capable of using. Given
///  differing features, some key types may not be available. The `openssl` feature will enable RSA and EC
///  (P256 and P384). The `ring` feature enables ED25519, in the future, Ring will also be used for other keys.
#[allow(clippy::large_enum_variant)]
pub enum KeyPair {
    /// RSA keypair, supported by OpenSSL
    #[cfg(feature = "dnssec-openssl")]
    RSA(PKey<Private>, Algorithm),
    /// Elliptic curve keypair, supported by OpenSSL
    #[cfg(feature = "dnssec-openssl")]
    EC(PKey<Private>, Algorithm),
    /// *ring* ECDSA keypair
    #[cfg(feature = "dnssec-ring")]
    ECDSA(EcdsaKeyPair),
    /// ED25519 encryption and hash defined keypair
    #[cfg(feature = "dnssec-ring")]
    ED25519(Ed25519KeyPair),
}

impl KeyPair {
    /// Creates an RSA type keypair.
    ///
    /// Errors unless the given algorithm is one of the following:
    ///
    /// - [`Algorithm::RSASHA1`]
    /// - [`Algorithm::RSASHA1NSEC3SHA1`]
    /// - [`Algorithm::RSASHA256`]
    /// - [`Algorithm::RSASHA512`]
    #[cfg(feature = "dnssec-openssl")]
    pub fn from_rsa(rsa: OpenSslRsa<Private>, algorithm: Algorithm) -> DnsSecResult<Self> {
        Self::from_rsa_pkey(PKey::from_rsa(rsa)?, algorithm)
    }

    /// Given a known pkey of an RSA key, return the wrapped keypair.
    ///
    /// Errors unless the given algorithm is one of the following:
    ///
    /// - [`Algorithm::RSASHA1`]
    /// - [`Algorithm::RSASHA1NSEC3SHA1`]
    /// - [`Algorithm::RSASHA256`]
    /// - [`Algorithm::RSASHA512`]
    #[cfg(feature = "dnssec-openssl")]
    pub fn from_rsa_pkey(pkey: PKey<Private>, algorithm: Algorithm) -> DnsSecResult<Self> {
        match algorithm {
            #[allow(deprecated)]
            Algorithm::RSASHA1
            | Algorithm::RSASHA1NSEC3SHA1
            | Algorithm::RSASHA256
            | Algorithm::RSASHA512 => Ok(Self::RSA(pkey, algorithm)),
            _ => Err(DnsSecErrorKind::Message("unsupported signing algorithm").into()),
        }
    }

    /// Creates an EC, elliptic curve, type keypair, only P256 or P384 are supported.
    #[cfg(feature = "dnssec-openssl")]
    pub fn from_ec_key(ec_key: EcKey<Private>, algorithm: Algorithm) -> DnsSecResult<Self> {
        Self::from_ec_pkey(PKey::from_ec_key(ec_key)?, algorithm)
    }

    /// Given a known pkey of an EC key, return the wrapped keypair
    #[cfg(feature = "dnssec-openssl")]
    pub fn from_ec_pkey(pkey: PKey<Private>, algorithm: Algorithm) -> DnsSecResult<Self> {
        match algorithm {
            Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => {
                Ok(Self::EC(pkey, algorithm))
            }
            _ => Err(DnsSecErrorKind::Message("unsupported signing algorithm").into()),
        }
    }

    /// Creates an ECDSA keypair with ring.
    #[cfg(feature = "dnssec-ring")]
    pub fn from_ecdsa(ec_key: EcdsaKeyPair) -> Self {
        Self::ECDSA(ec_key)
    }

    /// Creates an ED25519 keypair.
    #[cfg(feature = "dnssec-ring")]
    pub fn from_ed25519(ed_key: Ed25519KeyPair) -> Self {
        Self::ED25519(ed_key)
    }

    /// Converts this keypair to the DNS binary form of the public_key.
    ///
    /// If there is a private key associated with this keypair, it will not be included in this
    ///  format. Only the public key material will be included.
    fn to_public_bytes(&self) -> DnsSecResult<Vec<u8>> {
        #[allow(unreachable_patterns)]
        match self {
            // see from_vec() RSA sections for reference
            #[cfg(feature = "dnssec-openssl")]
            Self::RSA(pkey, _) => {
                // TODO: make these expects a try! and Err()
                let rsa = pkey
                    .rsa()
                    .expect("pkey should have been initialized with RSA");
                Ok(PublicKeyBuf::from_rsa(&rsa).into_inner())
            }
            // see from_vec() ECDSA sections for reference
            #[cfg(feature = "dnssec-openssl")]
            Self::EC(pkey, _) => {
                // TODO: make these expects a try! and Err()
                let ec_key = pkey
                    .ec_key()
                    .expect("pkey should have been initialized with EC");
                Ok(PublicKeyBuf::from_ec(&ec_key)?.into_inner())
            }
            #[cfg(feature = "dnssec-ring")]
            Self::ECDSA(ec_key) => {
                let mut bytes: Vec<u8> = ec_key.public_key().as_ref().to_vec();
                bytes.remove(0);
                Ok(bytes)
            }
            #[cfg(feature = "dnssec-ring")]
            Self::ED25519(ed_key) => Ok(ed_key.public_key().as_ref().to_vec()),
            #[cfg(not(any(feature = "dnssec-openssl", feature = "dnssec-ring")))]
            _ => Err(DnsSecErrorKind::Message("openssl or ring feature(s) not enabled").into()),
        }
    }

    /// Signs a hash.
    ///
    /// This will panic if the `key` is not a private key and can be used for signing.
    ///
    /// # Arguments
    ///
    /// * `message` - the message bytes to be signed, see `rrset_tbs`.
    ///
    /// # Return value
    ///
    /// The signature, ready to be stored in an `RData::RRSIG`.
    fn sign(&self, tbs: &TBS) -> DnsSecResult<Vec<u8>> {
        use std::iter;

        match self {
            #[cfg(feature = "dnssec-openssl")]
            Self::RSA(pkey, algorithm) | Self::EC(pkey, algorithm) => {
                let digest_type = DigestType::from(*algorithm).to_openssl_digest()?;
                let mut signer = Signer::new(digest_type, pkey)?;
                signer.update(tbs.as_ref())?;
                signer.sign_to_vec().map_err(Into::into).and_then(|bytes| {
                    if let Self::RSA(_, _) = self {
                        return Ok(bytes);
                    }

                    // Convert DER signature to raw signature (see RFC 6605 Section 4)
                    if bytes.len() < 8 {
                        return Err("unexpected signature format (length too short)".into());
                    }
                    let expect = |pos: usize, expected: u8| -> DnsSecResult<()> {
                        if bytes[pos] != expected {
                            return Err(format!(
                                "unexpected signature format ({pos}, {expected}))"
                            )
                            .into());
                        }
                        Ok(())
                    };
                    // Sanity checks
                    expect(0, 0x30)?;
                    expect(1, (bytes.len() - 2) as u8)?;
                    expect(2, 0x02)?;
                    let p1_len = bytes[3] as usize;
                    let p2_pos = 4 + p1_len;
                    expect(p2_pos, 0x02)?;
                    let p2_len = bytes[p2_pos + 1] as usize;
                    if p2_pos + 2 + p2_len > bytes.len() {
                        return Err("unexpected signature format (invalid length)".into());
                    }

                    let p1 = &bytes[4..p2_pos];
                    let p2 = &bytes[p2_pos + 2..p2_pos + 2 + p2_len];

                    // For P-256, each integer MUST be encoded as 32 octets;
                    // for P-384, each integer MUST be encoded as 48 octets.
                    let part_len = match algorithm {
                        Algorithm::ECDSAP256SHA256 => 32,
                        Algorithm::ECDSAP384SHA384 => 48,
                        _ => return Err("unexpected algorithm".into()),
                    };
                    let mut ret = Vec::<u8>::new();
                    {
                        let mut write_part = |mut part: &[u8]| -> DnsSecResult<()> {
                            // We need to pad or trim the octet string to expected length
                            if part.len() > part_len + 1 {
                                return Err("invalid signature data".into());
                            }
                            if part.len() == part_len + 1 {
                                // Trim leading zero
                                if part[0] != 0x00 {
                                    return Err("invalid signature data".into());
                                }
                                part = &part[1..];
                            }

                            // Pad with zeros. All numbers are big-endian here.
                            ret.extend(iter::repeat(0x00).take(part_len - part.len()));
                            ret.extend(part);
                            Ok(())
                        };
                        write_part(p1)?;
                        write_part(p2)?;
                    }
                    assert_eq!(ret.len(), part_len * 2);
                    Ok(ret)
                })
            }
            #[cfg(feature = "dnssec-ring")]
            Self::ECDSA(ec_key) => {
                let rng = rand::SystemRandom::new();
                Ok(ec_key.sign(&rng, tbs.as_ref())?.as_ref().to_vec())
            }
            #[cfg(feature = "dnssec-ring")]
            Self::ED25519(ed_key) => Ok(ed_key.sign(tbs.as_ref()).as_ref().to_vec()),
            #[cfg(not(any(feature = "dnssec-openssl", feature = "dnssec-ring")))]
            _ => Err(DnsSecErrorKind::Message("openssl nor ring feature(s) not enabled").into()),
        }
    }

    /// Generates a new private and public key pair for the specified algorithm.
    ///
    /// RSA keys are hardcoded to 2048bits at the moment. Other keys have predefined sizes.
    pub fn generate(algorithm: Algorithm) -> DnsSecResult<Self> {
        #[allow(deprecated)]
        match algorithm {
            Algorithm::Unknown(_) => Err(DnsSecErrorKind::Message("unknown algorithm").into()),
            #[cfg(feature = "dnssec-openssl")]
            Algorithm::RSASHA1
            | Algorithm::RSASHA1NSEC3SHA1
            | Algorithm::RSASHA256
            | Algorithm::RSASHA512 => {
                // TODO: the only keysize right now, would be better for people to use other algorithms...
                let inner = OpenSslRsa::generate(2_048)?;
                Self::from_rsa(inner, algorithm)
            }
            #[cfg(feature = "dnssec-openssl")]
            Algorithm::ECDSAP256SHA256 => {
                let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
                let inner = EcKey::generate(&group)?;
                Self::from_ec_key(inner, algorithm)
            }
            #[cfg(feature = "dnssec-openssl")]
            Algorithm::ECDSAP384SHA384 => {
                let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
                let inner = EcKey::generate(&group)?;
                Self::from_ec_key(inner, algorithm)
            }
            #[cfg(feature = "dnssec-ring")]
            Algorithm::ED25519 => Err(DnsSecErrorKind::Message(
                "use generate_pkcs8 for generating private key and encoding",
            )
            .into()),
            _ => Err(DnsSecErrorKind::Message("openssl nor ring feature(s) not enabled").into()),
        }
    }

    /// Generates a key, securing it with pkcs8
    #[cfg(feature = "dnssec-ring")]
    pub fn generate_pkcs8(algorithm: Algorithm) -> DnsSecResult<Vec<u8>> {
        #[allow(deprecated)]
        match algorithm {
            Algorithm::Unknown(_) => Err(DnsSecErrorKind::Message("unknown algorithm").into()),
            #[cfg(feature = "dnssec-openssl")]
            Algorithm::RSASHA1
            | Algorithm::RSASHA1NSEC3SHA1
            | Algorithm::RSASHA256
            | Algorithm::RSASHA512 => {
                Err(DnsSecErrorKind::Message("openssl does not yet support pkcs8").into())
            }
            #[cfg(feature = "dnssec-ring")]
            Algorithm::ECDSAP256SHA256 => {
                let rng = rand::SystemRandom::new();
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                    .map_err(Into::into)
                    .map(|pkcs8_bytes| pkcs8_bytes.as_ref().to_vec())
            }
            #[cfg(feature = "dnssec-ring")]
            Algorithm::ECDSAP384SHA384 => {
                let rng = rand::SystemRandom::new();
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng)
                    .map_err(Into::into)
                    .map(|pkcs8_bytes| pkcs8_bytes.as_ref().to_vec())
            }
            #[cfg(feature = "dnssec-ring")]
            Algorithm::ED25519 => {
                let rng = rand::SystemRandom::new();
                Ed25519KeyPair::generate_pkcs8(&rng)
                    .map_err(Into::into)
                    .map(|pkcs8_bytes| pkcs8_bytes.as_ref().to_vec())
            }
            _ => Err(DnsSecErrorKind::Message("openssl nor ring feature(s) not enabled").into()),
        }
    }
}

impl SigningKey for KeyPair {
    fn sign(&self, tbs: &TBS) -> DnsSecResult<Vec<u8>> {
        self.sign(tbs)
    }

    fn to_public_key(&self) -> DnsSecResult<PublicKeyBuf> {
        Ok(PublicKeyBuf::new(self.to_public_bytes()?))
    }
}

/// A key that can be used to sign records.
pub trait SigningKey: Send + Sync + 'static {
    /// Sign DNS records.
    ///
    /// # Return value
    ///
    /// The signature, ready to be stored in an `RData::RRSIG`.
    fn sign(&self, tbs: &TBS) -> DnsSecResult<Vec<u8>>;

    /// Returns a [`PublicKeyBuf`] for this [`SigningKey`].
    fn to_public_key(&self) -> DnsSecResult<PublicKeyBuf>;
}

#[cfg(any(feature = "dnssec-openssl", feature = "dnssec-ring"))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rr::dnssec::{PublicKey, Verifier};

    #[cfg(feature = "dnssec-openssl")]
    #[test]
    fn test_rsa() {
        public_key_test(Algorithm::RSASHA256, KeyFormat::Der);
        hash_test(Algorithm::RSASHA256, KeyFormat::Der);
    }

    #[cfg(feature = "dnssec-openssl")]
    #[test]
    fn test_ec_p256() {
        public_key_test(Algorithm::ECDSAP256SHA256, KeyFormat::Der);
        hash_test(Algorithm::ECDSAP256SHA256, KeyFormat::Der);
    }

    #[cfg(feature = "dnssec-ring")]
    #[test]
    fn test_ec_p256_pkcs8() {
        public_key_test(Algorithm::ECDSAP256SHA256, KeyFormat::Pkcs8);
        hash_test(Algorithm::ECDSAP256SHA256, KeyFormat::Pkcs8);
    }

    #[cfg(feature = "dnssec-openssl")]
    #[test]
    fn test_ec_p384() {
        public_key_test(Algorithm::ECDSAP384SHA384, KeyFormat::Der);
        hash_test(Algorithm::ECDSAP384SHA384, KeyFormat::Der);
    }

    #[cfg(feature = "dnssec-ring")]
    #[test]
    fn test_ec_p384_pkcs8() {
        public_key_test(Algorithm::ECDSAP384SHA384, KeyFormat::Pkcs8);
        hash_test(Algorithm::ECDSAP384SHA384, KeyFormat::Pkcs8);
    }

    #[cfg(feature = "dnssec-ring")]
    #[test]
    fn test_ed25519() {
        public_key_test(Algorithm::ED25519, KeyFormat::Pkcs8);
        hash_test(Algorithm::ED25519, KeyFormat::Pkcs8);
    }

    #[allow(clippy::uninlined_format_args)]
    fn public_key_test(algorithm: Algorithm, key_format: KeyFormat) {
        let key = decode_key(
            &key_format.generate_and_encode(algorithm, None).unwrap(),
            None,
            algorithm,
            key_format,
        )
        .unwrap();
        let pk = key.to_public_key().unwrap();

        let tbs = TBS::from(&b"www.example.com"[..]);
        let mut sig = key.sign(&tbs).unwrap();
        assert!(
            pk.verify(algorithm, tbs.as_ref(), &sig).is_ok(),
            "algorithm: {:?} (public key)",
            algorithm
        );
        sig[10] = !sig[10];
        assert!(
            pk.verify(algorithm, tbs.as_ref(), &sig).is_err(),
            "algorithm: {:?} (public key, neg)",
            algorithm
        );
    }

    #[allow(clippy::uninlined_format_args)]
    fn hash_test(algorithm: Algorithm, key_format: KeyFormat) {
        let tbs = TBS::from(&b"www.example.com"[..]);

        // TODO: convert to stored keys...
        let key = decode_key(
            &key_format.generate_and_encode(algorithm, None).unwrap(),
            None,
            algorithm,
            key_format,
        )
        .unwrap();
        let pub_key = key.to_public_key().unwrap();

        let neg = decode_key(
            &key_format.generate_and_encode(algorithm, None).unwrap(),
            None,
            algorithm,
            key_format,
        )
        .unwrap();
        let neg_pub_key = neg.to_public_key().unwrap();

        let sig = key.sign(&tbs).unwrap();
        assert!(
            pub_key.verify(algorithm, tbs.as_ref(), &sig).is_ok(),
            "algorithm: {:?}",
            algorithm
        );
        assert!(
            key.to_public_key()
                .unwrap()
                .to_dnskey(algorithm)
                .verify(tbs.as_ref(), &sig)
                .is_ok(),
            "algorithm: {:?} (dnskey)",
            algorithm
        );
        assert!(
            neg_pub_key.verify(algorithm, tbs.as_ref(), &sig).is_err(),
            "algorithm: {:?} (neg)",
            algorithm
        );
        assert!(
            neg.to_public_key()
                .unwrap()
                .to_dnskey(algorithm)
                .verify(tbs.as_ref(), &sig)
                .is_err(),
            "algorithm: {:?} (dnskey, neg)",
            algorithm
        );
    }
}
