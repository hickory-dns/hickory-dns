// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::borrow::Cow;
use std::iter;

use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::{HasPublic, PKey, Private, Public};
use openssl::rsa::Rsa as OpenSslRsa;
use openssl::sign::Verifier;
use openssl::symm::Cipher;

use super::ec_public_key::ECPublicKey;
use super::rsa_public_key::RSAPublicKey;
use super::{Algorithm, DigestType, KeyFormat, PublicKey, PublicKeyBuf, SigningKey, TBS};
use crate::error::{DnsSecErrorKind, DnsSecResult, ProtoResult};

/// An RSA signing key pair (backed by OpenSSL).
pub struct RsaSigningKey {
    inner: PKey<Private>,
    algorithm: Algorithm,
}

impl RsaSigningKey {
    /// Generates a 2048-bits RSA key pair.
    ///
    /// Errors unless the given algorithm is one of the following:
    ///
    /// - [`Algorithm::RSASHA256`]
    /// - [`Algorithm::RSASHA512`]
    pub fn generate(algorithm: Algorithm) -> DnsSecResult<Self> {
        match algorithm {
            #[allow(deprecated)]
            Algorithm::RSASHA1 | Algorithm::RSASHA1NSEC3SHA1 => {
                Err("unsupported Algorithm (insecure): {algorithm:?}".into())
            }
            Algorithm::RSASHA256 | Algorithm::RSASHA512 => {
                Self::from_rsa(OpenSslRsa::generate(2_048)?, algorithm)
            }
            _ => Err("invalid Algorithm for RSA key generation: {algorithm:?}".into()),
        }
    }

    /// Decode signing key pair from bytes according to the given `format`.
    ///
    /// Errors unless the given algorithm is one of the following:
    ///
    /// - [`Algorithm::RSASHA256`]
    /// - [`Algorithm::RSASHA512`]
    pub fn decode_key(
        bytes: &[u8],
        password: Option<&str>,
        algorithm: Algorithm,
        format: KeyFormat,
    ) -> DnsSecResult<Self> {
        match algorithm {
            #[allow(deprecated)]
            Algorithm::RSASHA1 | Algorithm::RSASHA1NSEC3SHA1 => {
                return Err(format!("unsupported Algorithm (insecure): {algorithm:?}").into())
            }
            Algorithm::RSASHA256 | Algorithm::RSASHA512 => {}
            _ => {
                return Err(format!("invalid Algorithm for RSA: {algorithm:?}").into());
            }
        }

        let key = match format {
            KeyFormat::Der => OpenSslRsa::private_key_from_der(bytes)
                .map_err(|e| format!("error reading RSA as DER: {e}"))?,
            KeyFormat::Pem => {
                //  empty string prevents openssl from triggering a read from stdin...
                let password = password.unwrap_or("");
                OpenSslRsa::private_key_from_pem_passphrase(bytes, password.as_bytes())
                    .map_err(|e| format!("could not decode RSA from PEM, bad password?: {e}"))?
            }
            _ => {
                return Err(format!(
                    "unsupported key format with RSA (DER or PEM only): {format:?}"
                )
                .into())
            }
        };

        Ok(Self::from_rsa(key, algorithm)
            .map_err(|e| format!("could not decode RSA key pair: {e}"))?)
    }

    /// Creates an RSA type key pair.
    ///
    /// Errors unless the given algorithm is one of the following:
    ///
    /// - [`Algorithm::RSASHA256`]
    /// - [`Algorithm::RSASHA512`]
    pub fn from_rsa(rsa: OpenSslRsa<Private>, algorithm: Algorithm) -> DnsSecResult<Self> {
        Self::from_rsa_pkey(PKey::from_rsa(rsa)?, algorithm)
    }

    /// Creates an RSA type key pair.
    ///
    /// Errors unless the given algorithm is one of the following:
    ///
    /// - [`Algorithm::RSASHA256`]
    /// - [`Algorithm::RSASHA512`]
    pub fn from_rsa_pkey(inner: PKey<Private>, algorithm: Algorithm) -> DnsSecResult<Self> {
        match algorithm {
            #[allow(deprecated)]
            Algorithm::RSASHA1 | Algorithm::RSASHA1NSEC3SHA1 => {
                Err(format!("unsupported signing algorithm (insecure): {algorithm:?}").into())
            }
            Algorithm::RSASHA256 | Algorithm::RSASHA512 => Ok(Self { inner, algorithm }),
            _ => {
                Err(DnsSecErrorKind::Message("unsupported signing algorithm: {algorithm:?}").into())
            }
        }
    }

    /// Encode the key pair to DER-encoded ASN.1 bytes.
    pub fn encode_der(&self) -> DnsSecResult<Vec<u8>> {
        self.inner
            .private_key_to_der()
            .map_err(|e| format!("error writing key as DER: {e}").into())
    }

    /// Encode the key pair to DER-encoded ASN.1 bytes, optionally encrypted with `password`.
    pub fn encode_pem(&self, password: Option<&str>) -> DnsSecResult<Vec<u8>> {
        if let Some(password) = password {
            self.inner
                .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), password.as_bytes())
        } else {
            self.inner.private_key_to_pem_pkcs8()
        }
        .map_err(|e| format!("error writing key as PEM: {e}").into())
    }
}

impl SigningKey for RsaSigningKey {
    fn sign(&self, tbs: &TBS) -> DnsSecResult<Vec<u8>> {
        let digest = DigestType::try_from(self.algorithm)?.to_openssl_digest();
        let mut signer = openssl::sign::Signer::new(digest, &self.inner)?;
        signer.update(tbs.as_ref())?;
        Ok(signer.sign_to_vec()?)
    }

    fn to_public_key(&self) -> DnsSecResult<PublicKeyBuf> {
        let rsa = self.inner.rsa()?;
        Ok(rsa_key_buf(&rsa, self.algorithm))
    }
}

/// Constructs a new [`PublicKeyBuf`] from an [`OpenSslRsa`] key.
pub fn rsa_key_buf<T: HasPublic>(key: &OpenSslRsa<T>, algorithm: Algorithm) -> PublicKeyBuf {
    let mut key_buf = Vec::new();

    // this is to get us access to the exponent and the modulus
    let e = key.e().to_vec();
    let n = key.n().to_vec();

    if e.len() > 255 {
        key_buf.push(0);
        key_buf.push((e.len() >> 8) as u8);
    }

    key_buf.push(e.len() as u8);
    key_buf.extend_from_slice(&e);
    key_buf.extend_from_slice(&n);
    PublicKeyBuf::new(key_buf, algorithm)
}

/// An ECDSA signing key pair (backed by OpenSSL).
pub struct EcSigningKey {
    inner: PKey<Private>,
    algorithm: Algorithm,
}

impl EcSigningKey {
    /// Generates a 2048-bits RSA key pair.
    pub fn generate(algorithm: Algorithm) -> DnsSecResult<Self> {
        match algorithm {
            Algorithm::ECDSAP256SHA256 => {
                let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
                let inner = EcKey::generate(&group)?;
                Self::from_ec_key(inner, algorithm)
            }
            Algorithm::ECDSAP384SHA384 => {
                let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
                let inner = EcKey::generate(&group)?;
                Self::from_ec_key(inner, algorithm)
            }
            _ => {
                Err(format!("unsupported Algorithm for ECDSA key generation: {algorithm:?}").into())
            }
        }
    }

    /// Decode signing key pair from bytes according to the given `format`.
    pub fn decode_key(
        bytes: &[u8],
        password: Option<&str>,
        algorithm: Algorithm,
        format: KeyFormat,
    ) -> DnsSecResult<Self> {
        match algorithm {
            Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => {}
            _ => {
                return Err(format!("invalid Algorithm for EcSigningKey: {algorithm:?}").into());
            }
        }

        let key = match format {
            KeyFormat::Der => EcKey::private_key_from_der(bytes)
                .map_err(|e| format!("error reading EC key as DER: {e}"))?,
            KeyFormat::Pem => {
                //  empty string prevents openssl from triggering a read from stdin...
                let password = password.unwrap_or("");
                EcKey::private_key_from_pem_passphrase(bytes, password.as_bytes())
                    .map_err(|e| format!("could not decode EC key from PEM, bad password?: {e}"))?
            }
            _ => {
                return Err(format!(
                    "unsupported key format with EC key (DER or PEM only): {format:?}"
                )
                .into())
            }
        };

        Ok(Self::from_ec_key(key, algorithm)
            .map_err(|e| format!("could not decode EC key: {e}"))?)
    }

    /// Creates an elliptic curve key pair.
    ///
    /// Errors unless the given algorithm is one of the following:
    ///
    /// - [`Algorithm::ECDSAP256SHA256`]
    /// - [`Algorithm::ECDSAP384SHA384`]
    pub fn from_ec_key(ec_key: EcKey<Private>, algorithm: Algorithm) -> DnsSecResult<Self> {
        Self::from_ec_pkey(PKey::from_ec_key(ec_key)?, algorithm)
    }

    /// Given a known pkey of an RSA key, return the wrapped key pair.
    ///
    /// Errors unless the given algorithm is one of the following:
    ///
    /// - [`Algorithm::ECDSAP256SHA256`]
    /// - [`Algorithm::ECDSAP384SHA384`]
    pub fn from_ec_pkey(inner: PKey<Private>, algorithm: Algorithm) -> DnsSecResult<Self> {
        match algorithm {
            Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => {
                Ok(Self { inner, algorithm })
            }
            _ => Err(DnsSecErrorKind::Message("unsupported signing algorithm").into()),
        }
    }

    /// Encode the key pair to DER-encoded ASN.1 bytes.
    pub fn encode_der(&self) -> DnsSecResult<Vec<u8>> {
        self.inner
            .private_key_to_der()
            .map_err(|e| format!("error writing key as DER: {e}").into())
    }

    /// Encode the key pair to DER-encoded ASN.1 bytes, optionally encrypted with `password`.
    pub fn encode_pem(&self, password: Option<&str>) -> DnsSecResult<Vec<u8>> {
        if let Some(password) = password {
            self.inner
                .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), password.as_bytes())
        } else {
            self.inner.private_key_to_pem_pkcs8()
        }
        .map_err(|e| format!("error writing key as PEM: {e}").into())
    }
}

impl SigningKey for EcSigningKey {
    fn sign(&self, tbs: &TBS) -> DnsSecResult<Vec<u8>> {
        let digest = DigestType::try_from(self.algorithm)?.to_openssl_digest();
        let mut signer = openssl::sign::Signer::new(digest, &self.inner)?;
        signer.update(tbs.as_ref())?;
        let bytes = signer.sign_to_vec()?;

        // Convert DER signature to raw signature (see RFC 6605 Section 4)
        if bytes.len() < 8 {
            return Err("unexpected signature format (length too short)".into());
        }
        let expect = |pos: usize, expected: u8| -> DnsSecResult<()> {
            if bytes[pos] != expected {
                return Err(format!("unexpected signature format ({pos}, {expected}))").into());
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
        let part_len = match self.algorithm {
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
    }

    fn to_public_key(&self) -> DnsSecResult<PublicKeyBuf> {
        ec_key_buf(&self.inner.ec_key()?)
    }
}

/// Constructs a new [`PublicKeyBuf`] from an openssl [`EcKey`].
pub fn ec_key_buf<T: HasPublic>(ec_key: &EcKey<T>) -> DnsSecResult<PublicKeyBuf> {
    let group = ec_key.group();
    let algorithm = match group.curve_name() {
        Some(Nid::X9_62_PRIME256V1) => Algorithm::ECDSAP256SHA256,
        Some(Nid::SECP384R1) => Algorithm::ECDSAP384SHA384,
        val => {
            return Err(format!(
                "unsupported curve {val:?} ({:?})",
                val.and_then(|nid| nid.long_name().ok())
            )
            .into())
        }
    };

    let point = ec_key.public_key();
    let mut key_buf = BigNumContext::new()
        .and_then(|mut ctx| point.to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx))?;

    // Remove OpenSSL header byte
    key_buf.remove(0);
    Ok(PublicKeyBuf::new(key_buf, algorithm))
}

fn verify_with_pkey(
    pkey: &PKey<Public>,
    algorithm: Algorithm,
    message: &[u8],
    signature: &[u8],
) -> ProtoResult<()> {
    let digest_type = DigestType::try_from(algorithm)?.to_openssl_digest();
    let mut verifier = Verifier::new(digest_type, pkey)?;
    verifier.update(message)?;

    if verifier.verify(signature)? {
        Ok(())
    } else {
        Err("could not verify".into())
    }
}

/// Elyptic Curve public key type
pub struct Ec<'k> {
    raw: Cow<'k, [u8]>,
    pkey: PKey<Public>,
    algorithm: Algorithm,
}

impl<'k> Ec<'k> {
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
    pub fn from_public_bytes(public_key: Cow<'k, [u8]>, algorithm: Algorithm) -> ProtoResult<Self> {
        let curve = match algorithm {
            Algorithm::ECDSAP256SHA256 => Nid::X9_62_PRIME256V1,
            Algorithm::ECDSAP384SHA384 => Nid::SECP384R1,
            _ => return Err("only ECDSAP256SHA256 and ECDSAP384SHA384 are supported by Ec".into()),
        };

        // Key needs to be converted to OpenSSL format
        let k = ECPublicKey::from_unprefixed(public_key.as_ref(), algorithm)?;
        let group = EcGroup::from_curve_name(curve)?;
        let mut ctx = BigNumContext::new()?;
        let point = EcPoint::from_bytes(&group, k.prefixed_bytes(), &mut ctx)?;
        let pkey = PKey::from_ec_key(EcKey::from_public_key(&group, &point)?)?;

        Ok(Self {
            raw: public_key,
            pkey,
            algorithm,
        })
    }
}

fn asn1_emit_integer(output: &mut Vec<u8>, int: &[u8]) {
    assert!(!int.is_empty());
    output.push(0x02); // INTEGER
    if int[0] > 0x7f {
        output.push((int.len() + 1) as u8);
        output.push(0x00); // MSB must be zero
        output.extend(int);
        return;
    }
    // Trim leading zeros
    let mut pos = 0;
    while pos < int.len() {
        if int[pos] == 0 {
            if pos == int.len() - 1 {
                break;
            }
            pos += 1;
            continue;
        }
        if int[pos] > 0x7f {
            // We need to leave one 0x00 to make MSB zero
            pos -= 1;
        }
        break;
    }
    let int_output = &int[pos..];
    output.push(int_output.len() as u8);
    output.extend(int_output);
}

/// Convert raw DNSSEC ECDSA signature to ASN.1 DER format
pub fn dnssec_ecdsa_signature_to_der(signature: &[u8]) -> ProtoResult<Vec<u8>> {
    if signature.is_empty() || signature.len() & 1 != 0 || signature.len() > 127 {
        return Err("invalid signature length".into());
    }
    let part_len = signature.len() / 2;
    // ASN.1 SEQUENCE: 0x30 [LENGTH]
    let mut signature_asn1 = vec![0x30, 0x00];
    asn1_emit_integer(&mut signature_asn1, &signature[..part_len]);
    asn1_emit_integer(&mut signature_asn1, &signature[part_len..]);
    signature_asn1[1] = (signature_asn1.len() - 2) as u8;
    Ok(signature_asn1)
}

impl PublicKey for Ec<'_> {
    fn public_bytes(&self) -> &[u8] {
        self.raw.as_ref()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> ProtoResult<()> {
        let signature_asn1 = dnssec_ecdsa_signature_to_der(signature)?;
        verify_with_pkey(&self.pkey, self.algorithm, message, &signature_asn1)
    }

    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

/// Rsa public key
pub struct Rsa<'k> {
    raw: Cow<'k, [u8]>,
    pkey: PKey<Public>,
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
    pub fn from_public_bytes(raw: Cow<'k, [u8]>, algorithm: Algorithm) -> ProtoResult<Self> {
        let parsed = RSAPublicKey::try_from(raw.as_ref())?;
        // FYI: BigNum slices treat all slices as BigEndian, i.e NetworkByteOrder
        let e = BigNum::from_slice(parsed.e())?;
        let n = BigNum::from_slice(parsed.n())?;

        let pkey = OpenSslRsa::from_public_components(n, e).and_then(PKey::from_rsa)?;
        Ok(Self {
            raw,
            pkey,
            algorithm,
        })
    }
}

impl PublicKey for Rsa<'_> {
    fn public_bytes(&self) -> &[u8] {
        self.raw.as_ref()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> ProtoResult<()> {
        verify_with_pkey(&self.pkey, self.algorithm, message, signature)
    }

    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnssec::test_utils::{hash_test, public_key_test};

    #[test]
    fn test_rsa() {
        let algorithm = Algorithm::RSASHA256;
        let key = RsaSigningKey::generate(algorithm).unwrap();
        public_key_test(&key, algorithm);

        let neg = RsaSigningKey::generate(algorithm).unwrap();
        hash_test(&key, &neg, algorithm);
    }

    #[test]
    fn test_ec_p256() {
        let algorithm = Algorithm::ECDSAP256SHA256;
        let key = EcSigningKey::generate(algorithm).unwrap();
        public_key_test(&key, algorithm);

        let neg = EcSigningKey::generate(algorithm).unwrap();
        hash_test(&key, &neg, algorithm);
    }

    #[test]
    fn test_ec_p384() {
        let algorithm = Algorithm::ECDSAP384SHA384;
        let key = EcSigningKey::generate(algorithm).unwrap();
        public_key_test(&key, algorithm);

        let neg = EcSigningKey::generate(algorithm).unwrap();
        hash_test(&key, &neg, algorithm);
    }

    #[test]
    fn test_asn1_emit_integer() {
        fn test_case(source: &[u8], expected_data: &[u8]) {
            let mut output = Vec::<u8>::new();
            asn1_emit_integer(&mut output, source);
            assert_eq!(output[0], 0x02);
            assert_eq!(output[1], expected_data.len() as u8);
            assert_eq!(&output[2..], expected_data);
        }
        test_case(&[0x00], &[0x00]);
        test_case(&[0x00, 0x00], &[0x00]);
        test_case(&[0x7f], &[0x7f]);
        test_case(&[0x80], &[0x00, 0x80]);
        test_case(&[0x00, 0x80], &[0x00, 0x80]);
        test_case(&[0x00, 0x00, 0x80], &[0x00, 0x80]);
        test_case(&[0x7f, 0x00, 0x80], &[0x7f, 0x00, 0x80]);
        test_case(&[0x00, 0x7f, 0x00, 0x80], &[0x7f, 0x00, 0x80]);
        test_case(&[0x80, 0x00, 0x80], &[0x00, 0x80, 0x00, 0x80]);
        test_case(&[0xff, 0x00, 0x80], &[0x00, 0xff, 0x00, 0x80]);
    }
}
