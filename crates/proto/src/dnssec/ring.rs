use ring::{
    rand::{self, SystemRandom},
    signature::{
        EcdsaKeyPair, Ed25519KeyPair, KeyPair as RingKeyPair, RsaKeyPair,
        ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, RSA_PKCS1_SHA256, RSA_PKCS1_SHA512,
    },
};

use super::{Algorithm, PublicKeyBuf, SigningKey, TBS};
use crate::error::{DnsSecErrorKind, DnsSecResult};

/// An ECDSA signing key pair (backed by ring).
pub struct EcdsaSigningKey {
    inner: EcdsaKeyPair,
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
        })
    }

    /// Creates an ECDSA key pair with ring.
    pub fn from_ecdsa(inner: EcdsaKeyPair) -> Self {
        Self { inner }
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
        Ok(PublicKeyBuf::new(bytes))
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
        Ok(PublicKeyBuf::new(self.inner.public_key().as_ref().to_vec()))
    }
}

/// An RSA signing key pair (backed by ring).
pub struct RsaSigningKey {
    inner: RsaKeyPair,
    algorithm: Algorithm,
}

impl RsaSigningKey {
    /// Decode signing key pair from DER-encoded PKCS#8 bytes.
    pub fn from_pkcs8(bytes: &[u8], algorithm: Algorithm) -> DnsSecResult<Self> {
        match algorithm {
            #[allow(deprecated)]
            Algorithm::RSASHA1 | Algorithm::RSASHA1NSEC3SHA1 => {
                return Err("unsupported Algorithm (insecure): {algorithm:?}".into())
            }
            Algorithm::RSASHA256 | Algorithm::RSASHA512 => {}
            _ => return Err("unsupported Algorithm: {algorithm:?}".into()),
        }

        Ok(Self {
            inner: RsaKeyPair::from_pkcs8(bytes)?,
            algorithm,
        })
    }
}

impl SigningKey for RsaSigningKey {
    fn sign(&self, tbs: &TBS) -> DnsSecResult<Vec<u8>> {
        let encoding = match self.algorithm {
            Algorithm::RSASHA256 => &RSA_PKCS1_SHA256,
            Algorithm::RSASHA512 => &RSA_PKCS1_SHA512,
            _ => unreachable!(),
        };

        let rng = rand::SystemRandom::new();
        let mut signature = vec![0; self.inner.public().modulus_len()];
        self.inner
            .sign(encoding, &rng, tbs.as_ref(), &mut signature)?;
        Ok(signature)
    }

    fn to_public_key(&self) -> DnsSecResult<PublicKeyBuf> {
        Ok(PublicKeyBuf::new(self.inner.public_key().as_ref().to_vec()))
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

    #[test]
    fn test_rsa() {
        // ring currently does not support RSA key generation support.
        // Generated per the documentation from https://docs.rs/ring/latest/ring/rsa/struct.KeyPair.html#method.from_pkcs8.
        const KEY_1: &[u8] = include_bytes!("../../tests/test-data/rsa-2048-private-key-1.pk8");
        const KEY_2: &[u8] = include_bytes!("../../tests/test-data/rsa-2048-private-key-2.pk8");

        let algorithm = Algorithm::RSASHA256;
        let format = KeyFormat::Pkcs8;
        let key = decode_key(KEY_1, None, algorithm, format).unwrap();
        public_key_test(&*key, algorithm);

        let neg = decode_key(KEY_2, None, algorithm, format).unwrap();
        hash_test(&*key, &*neg, algorithm);
    }

    #[test]
    fn test_ec_encode_decode_pkcs8() {
        let algorithm = Algorithm::ECDSAP256SHA256;
        let pkcs8 = EcdsaSigningKey::generate_pkcs8(algorithm).unwrap();
        decode_key(&pkcs8, None, algorithm, KeyFormat::Pkcs8).unwrap();
    }

    #[test]
    fn test_ed25519_encode_decode_pkcs8() {
        let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
        decode_key(&pkcs8, None, Algorithm::ED25519, KeyFormat::Pkcs8).unwrap();
    }

    #[test]
    fn test_rsasha256_encode_decode_pkcs8() {
        // ring currently does not support RSA key generation support.
        // Generated per the documentation from https://docs.rs/ring/latest/ring/rsa/struct.KeyPair.html#method.from_pkcs8.
        const KEY: &[u8] = include_bytes!("../../tests/test-data/rsa-2048-private-key-1.pk8");
        decode_key(KEY, None, Algorithm::RSASHA256, KeyFormat::Pkcs8).unwrap();
    }
}
