use std::borrow::Cow;

use ring::{
    rand::{self, SystemRandom},
    signature::{
        self, EcdsaKeyPair, Ed25519KeyPair, KeyPair as RingKeyPair,
        ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, ED25519_PUBLIC_KEY_LEN,
    },
};

use super::{
    ec_public_key::ECPublicKey, rsa_public_key::RSAPublicKey, Algorithm, PublicKey, PublicKeyBuf,
    SigningKey, TBS,
};
use crate::error::{DnsSecErrorKind, DnsSecResult, ProtoResult};

/// An ECDSA signing key pair (backed by ring).
pub struct EcdsaSigningKey {
    inner: EcdsaKeyPair,
    algorithm: Algorithm,
}

impl EcdsaSigningKey {
    /// Decode signing key pair from DER-encoded PKCS#8 bytes.
    ///
    /// Errors unless the given algorithm is one of the following:
    ///
    /// - [`Algorithm::ECDSAP256SHA256`]
    /// - [`Algorithm::ECDSAP384SHA384`]
    pub fn from_pkcs8(bytes: &[u8], algorithm: Algorithm) -> DnsSecResult<Self> {
        let rng = SystemRandom::new();
        let ring_algorithm = if algorithm == Algorithm::ECDSAP256SHA256 {
            &ECDSA_P256_SHA256_FIXED_SIGNING
        } else if algorithm == Algorithm::ECDSAP384SHA384 {
            &ECDSA_P384_SHA384_FIXED_SIGNING
        } else {
            return Err(DnsSecErrorKind::Message("unsupported algorithm").into());
        };

        Ok(Self {
            inner: EcdsaKeyPair::from_pkcs8(ring_algorithm, bytes, &rng)?,
            algorithm,
        })
    }

    /// Creates an ECDSA key pair with ring.
    pub fn from_ecdsa(inner: EcdsaKeyPair, algorithm: Algorithm) -> Self {
        Self { inner, algorithm }
    }

    /// Generate signing key pair and return the DER-encoded PKCS#8 bytes.
    ///
    /// Errors unless the given algorithm is one of the following:
    ///
    /// - [`Algorithm::ECDSAP256SHA256`]
    /// - [`Algorithm::ECDSAP384SHA384`]
    pub fn generate_pkcs8(algorithm: Algorithm) -> DnsSecResult<Vec<u8>> {
        let rng = SystemRandom::new();
        let alg = if algorithm == Algorithm::ECDSAP256SHA256 {
            &ECDSA_P256_SHA256_FIXED_SIGNING
        } else if algorithm == Algorithm::ECDSAP384SHA384 {
            &ECDSA_P384_SHA384_FIXED_SIGNING
        } else {
            return Err(DnsSecErrorKind::Message("unsupported algorithm").into());
        };

        let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng)?;
        Ok(pkcs8.as_ref().to_vec())
    }
}

impl SigningKey for EcdsaSigningKey {
    fn sign(&self, tbs: &TBS) -> DnsSecResult<Vec<u8>> {
        let rng = rand::SystemRandom::new();
        Ok(self.inner.sign(&rng, tbs.as_ref())?.as_ref().to_vec())
    }

    fn to_public_key(&self) -> DnsSecResult<PublicKeyBuf> {
        let mut bytes = self.inner.public_key().as_ref().to_vec();
        bytes.remove(0);
        Ok(PublicKeyBuf::new(bytes, self.algorithm))
    }
}

/// An Ed25519 signing key pair (backed by ring).
pub struct Ed25519SigningKey {
    inner: Ed25519KeyPair,
}

impl Ed25519SigningKey {
    /// Decode signing key pair from DER-encoded PKCS#8 bytes.
    pub fn from_pkcs8(bytes: &[u8]) -> DnsSecResult<Self> {
        Ok(Self {
            inner: Ed25519KeyPair::from_pkcs8(bytes)?,
        })
    }

    /// Creates an Ed25519 keypair.
    pub fn from_ed25519(inner: Ed25519KeyPair) -> Self {
        Self { inner }
    }

    /// Generate signing key pair and return the DER-encoded PKCS#8 bytes.
    pub fn generate_pkcs8() -> DnsSecResult<Vec<u8>> {
        let rng = rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)?;
        Ok(pkcs8.as_ref().to_vec())
    }
}

impl SigningKey for Ed25519SigningKey {
    fn sign(&self, tbs: &TBS) -> DnsSecResult<Vec<u8>> {
        Ok(self.inner.sign(tbs.as_ref()).as_ref().to_vec())
    }

    fn to_public_key(&self) -> DnsSecResult<PublicKeyBuf> {
        Ok(PublicKeyBuf::new(
            self.inner.public_key().as_ref().to_vec(),
            Algorithm::ED25519,
        ))
    }
}

/// Elyptic Curve public key type
pub type Ec = ECPublicKey;

impl Ec {
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
    pub fn from_public_bytes(public_key: &[u8], algorithm: Algorithm) -> ProtoResult<Self> {
        Self::from_unprefixed(public_key, algorithm)
    }
}

#[cfg(feature = "dnssec-ring")]
impl PublicKey for Ec {
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
        public_key.verify(message, signature).map_err(Into::into)
    }

    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

/// Ed25519 Public key
pub struct Ed25519<'k> {
    raw: Cow<'k, [u8]>,
}

impl<'k> Ed25519<'k> {
    /// ```text
    ///  Internet-Draft              EdDSA for DNSSEC               December 2016
    ///
    ///  An Ed25519 public key consists of a 32-octet value, which is encoded
    ///  into the Public Key field of a DNSKEY resource record as a simple bit
    ///  string.  The generation of a public key is defined in Section 5.1.5
    ///  in [RFC 8032]. Breaking tradition, the keys are encoded in little-
    ///  endian byte order.
    /// ```
    pub fn from_public_bytes(public_key: Cow<'k, [u8]>) -> ProtoResult<Self> {
        if public_key.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(format!(
                "expected {} byte public_key: {}",
                ED25519_PUBLIC_KEY_LEN,
                public_key.len()
            )
            .into());
        }

        Ok(Self { raw: public_key })
    }
}

impl PublicKey for Ed25519<'_> {
    // TODO: just store reference to public key bytes in ctor...
    fn public_bytes(&self) -> &[u8] {
        self.raw.as_ref()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> ProtoResult<()> {
        let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, self.raw.as_ref());
        public_key.verify(message, signature).map_err(Into::into)
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::ED25519
    }
}

/// Rsa public key
pub struct Rsa<'k> {
    raw: &'k [u8],
    pkey: RSAPublicKey<'k>,
    algorithm: Algorithm,
}

impl<'k> Rsa<'k> {
    /// ```text
    /// RFC 3110              RSA SIGs and KEYs in the DNS              May 2001
    ///
    ///       2. RSA Public KEY Resource Records
    ///
    ///  RSA public keys are stored in the DNS as KEY RRs using algorithm
    ///  number 5 [RFC2535].  The structure of the algorithm specific portion
    ///  of the RDATA part of such RRs is as shown below.
    ///
    ///        Field             Size
    ///        -----             ----
    ///        exponent length   1 or 3 octets (see text)
    ///        exponent          as specified by length field
    ///        modulus           remaining space
    ///
    ///  For interoperability, the exponent and modulus are each limited to
    ///  4096 bits in length.  The public key exponent is a variable length
    ///  unsigned integer.  Its length in octets is represented as one octet
    ///  if it is in the range of 1 to 255 and by a zero octet followed by a
    ///  two octet unsigned length if it is longer than 255 bytes.  The public
    ///  key modulus field is a multiprecision unsigned integer.  The length
    ///  of the modulus can be determined from the RDLENGTH and the preceding
    ///  RDATA fields including the exponent.  Leading zero octets are
    ///  prohibited in the exponent and modulus.
    ///
    ///  Note: KEY RRs for use with RSA/SHA1 DNS signatures MUST use this
    ///  algorithm number (rather than the algorithm number specified in the
    ///  obsoleted RFC 2537).
    ///
    ///  Note: This changes the algorithm number for RSA KEY RRs to be the
    ///  same as the new algorithm number for RSA/SHA1 SIGs.
    /// ```
    pub fn from_public_bytes(raw: &'k [u8], algorithm: Algorithm) -> ProtoResult<Self> {
        let pkey = RSAPublicKey::try_from(raw)?;
        Ok(Self {
            raw,
            pkey,
            algorithm,
        })
    }
}

impl PublicKey for Rsa<'_> {
    fn public_bytes(&self) -> &[u8] {
        self.raw
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> ProtoResult<()> {
        #[allow(deprecated)]
        let alg = match self.algorithm {
            Algorithm::RSASHA256 => &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
            Algorithm::RSASHA512 => &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
            Algorithm::RSASHA1 => &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
            Algorithm::RSASHA1NSEC3SHA1 => {
                return Err("*ring* doesn't support RSASHA1NSEC3SHA1 yet".into())
            }
            _ => unreachable!("non-RSA algorithm passed to RSA verify()"),
        };
        let public_key = signature::RsaPublicKeyComponents {
            n: self.pkey.n(),
            e: self.pkey.e(),
        };
        public_key
            .verify(alg, message, signature)
            .map_err(Into::into)
    }

    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnssec::{
        decode_key,
        test_utils::{hash_test, public_key_test},
        KeyFormat,
    };

    #[test]
    fn test_ec_p256_pkcs8() {
        let algorithm = Algorithm::ECDSAP256SHA256;
        let format = KeyFormat::Pkcs8;
        let pkcs8 = EcdsaSigningKey::generate_pkcs8(algorithm).unwrap();
        let key = decode_key(&pkcs8, None, algorithm, format).unwrap();
        public_key_test(&*key, algorithm);

        let neg_pkcs8 = EcdsaSigningKey::generate_pkcs8(algorithm).unwrap();
        let neg = decode_key(&neg_pkcs8, None, algorithm, format).unwrap();
        hash_test(&*key, &*neg, algorithm);
    }

    #[test]
    fn test_ec_p384_pkcs8() {
        let algorithm = Algorithm::ECDSAP384SHA384;
        let format = KeyFormat::Pkcs8;
        let pkcs8 = EcdsaSigningKey::generate_pkcs8(algorithm).unwrap();
        let key = decode_key(&pkcs8, None, algorithm, format).unwrap();
        public_key_test(&*key, algorithm);

        let neg_pkcs8 = EcdsaSigningKey::generate_pkcs8(algorithm).unwrap();
        let neg = decode_key(&neg_pkcs8, None, algorithm, format).unwrap();
        hash_test(&*key, &*neg, algorithm);
    }

    #[test]
    fn test_ed25519() {
        let algorithm = Algorithm::ED25519;
        let format = KeyFormat::Pkcs8;
        let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
        let key = decode_key(&pkcs8, None, algorithm, format).unwrap();
        public_key_test(&*key, algorithm);

        let neg_pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
        let neg = decode_key(&neg_pkcs8, None, algorithm, format).unwrap();
        hash_test(&*key, &*neg, algorithm);
    }
}
