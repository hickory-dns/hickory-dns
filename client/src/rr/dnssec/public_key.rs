// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Public Key implementations for supported key types
#[cfg(not(any(feature = "openssl", feature = "ring")))]
use std::marker::PhantomData;

#[cfg(feature = "openssl")]
use openssl::rsa::Rsa as OpenSslRsa;
#[cfg(feature = "openssl")]
use openssl::sign::Verifier;
#[cfg(feature = "openssl")]
use openssl::pkey::PKey;
#[cfg(feature = "openssl")]
use openssl::bn::BigNum;
#[cfg(all(not(feature = "ring"), feature = "openssl"))]
use openssl::bn::BigNumContext;
#[cfg(all(not(feature = "ring"), feature = "openssl"))]
use openssl::ec::{EcGroup, EcKey, EcPoint};
#[cfg(all(not(feature = "ring"), feature = "openssl"))]
use openssl::nid;
#[cfg(feature = "ring")]
use ring::signature;
#[cfg(feature = "ring")]
use ring::signature::{ED25519_PUBLIC_KEY_LEN, EdDSAParameters, VerificationAlgorithm};
#[cfg(feature = "ring")]
use untrusted::Input;

use error::*;
#[cfg(feature = "openssl")]
use rr::dnssec::DigestType;
use rr::dnssec::Algorithm;

#[cfg(any(feature = "openssl", feature = "ring"))]
use rr::dnssec::ec_public_key::ECPublicKey;

/// PublicKeys implement the ability to ideally be zero copy abstractions over public keys for verifying signed content.
///
/// In DNS the KEY and DNSKEY types are generally the RData types which store public key material.
pub trait PublicKey {
    /// Returns the public bytes of the public key, in DNS format
    fn public_bytes(&self) -> &[u8];

    /// Verifies the hash matches the signature with the current `key`.
    ///
    /// # Arguments
    ///
    /// * `message` - the message to be validated, see `hash_rrset`
    /// * `signature` - the signature to use to verify the hash, extracted from an `RData::RRSIG`
    ///                 for example.
    ///
    /// # Return value
    ///
    /// True if and only if the signature is valid for the hash. This will always return
    /// false if the `key`.
    #[allow(unused)]
    fn verify(&self, algorithm: Algorithm, message: &[u8], signature: &[u8]) -> DnsSecResult<()>;

    /// The key tag is calculated as a hash to more quickly lookup a DNSKEY.
    ///
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035), DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987
    ///
    /// ```text
    /// RFC 2535                DNS Security Extensions               March 1999
    ///
    /// 4.1.6 Key Tag Field
    ///
    ///  The "key Tag" is a two octet quantity that is used to efficiently
    ///  select between multiple keys which may be applicable and thus check
    ///  that a public key about to be used for the computationally expensive
    ///  effort to check the signature is possibly valid.  For algorithm 1
    ///  (MD5/RSA) as defined in [RFC 2537], it is the next to the bottom two
    ///  octets of the public key modulus needed to decode the signature
    ///  field.  That is to say, the most significant 16 of the least
    ///  significant 24 bits of the modulus in network (big endian) order. For
    ///  all other algorithms, including private algorithms, it is calculated
    ///  as a simple checksum of the KEY RR as described in Appendix C.
    ///
    /// Appendix C: Key Tag Calculation
    ///
    ///  The key tag field in the SIG RR is just a means of more efficiently
    ///  selecting the correct KEY RR to use when there is more than one KEY
    ///  RR candidate available, for example, in verifying a signature.  It is
    ///  possible for more than one candidate key to have the same tag, in
    ///  which case each must be tried until one works or all fail.  The
    ///  following reference implementation of how to calculate the Key Tag,
    ///  for all algorithms other than algorithm 1, is in ANSI C.  It is coded
    ///  for clarity, not efficiency.  (See section 4.1.6 for how to determine
    ///  the Key Tag of an algorithm 1 key.)
    ///
    ///  /* assumes int is at least 16 bits
    ///     first byte of the key tag is the most significant byte of return
    ///     value
    ///     second byte of the key tag is the least significant byte of
    ///     return value
    ///     */
    ///
    ///  int keytag (
    ///
    ///          unsigned char key[],  /* the RDATA part of the KEY RR */
    ///          unsigned int keysize, /* the RDLENGTH */
    ///          )
    ///  {
    ///  long int    ac;    /* assumed to be 32 bits or larger */
    ///
    ///  for ( ac = 0, i = 0; i < keysize; ++i )
    ///      ac += (i&1) ? key[i] : key[i]<<8;
    ///  ac += (ac>>16) & 0xFFFF;
    ///  return ac & 0xFFFF;
    ///  }
    /// ```
    fn key_tag(&self) -> DnsSecResult<u16> {
        let mut ac: usize = 0;

        for (i, k) in self.public_bytes().iter().enumerate() {
            ac += if i & 0x0001 == 0x0001 {
                *k as usize
            } else {
                (*k as usize) << 8
            };
        }

        ac += (ac >> 16) & 0xFFFF;
        return Ok((ac & 0xFFFF) as u16);
    }
}

#[cfg(feature = "openssl")]
fn verify_with_pkey(pkey: &PKey,
                    algorithm: Algorithm,
                    message: &[u8],
                    signature: &[u8])
                    -> DnsSecResult<()> {
    let digest_type = try!(DigestType::from(algorithm).to_openssl_digest());
    let mut verifier = Verifier::new(digest_type, &pkey).unwrap();
    try!(verifier.update(message));
    verifier
        .finish(signature)
        .map_err(|e| e.into())
        .and_then(|b| if b {
                      Ok(())
                  } else {
                      Err(DnsSecErrorKind::Message("could not verify").into())
                  })
}

/// Elyptic Curve public key type
#[cfg(all(not(feature = "ring"), feature = "openssl"))]
pub struct Ec<'k> {
    raw: &'k [u8],
    pkey: PKey,
}

#[cfg(all(not(feature = "ring"), feature = "openssl"))]
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
    pub fn from_public_bytes(public_key: &'k [u8], algorithm: Algorithm) -> DnsSecResult<Self> {
        let curve = match algorithm {
            Algorithm::ECDSAP256SHA256 => nid::X9_62_PRIME256V1,
            Algorithm::ECDSAP384SHA384 => nid::SECP384R1,
            _ => return Err("only ECDSAP256SHA256 and ECDSAP384SHA384 are supported by Ec".into()),
        };
        // Key needs to be converted to OpenSSL format
        let k = ECPublicKey::from_unprefixed(public_key, algorithm)?;
        EcGroup::from_curve_name(curve)
                .and_then(|group| BigNumContext::new().map(|ctx| (group, ctx)))
                // FYI: BigNum slices treat all slices as BigEndian, i.e NetworkByteOrder
                .and_then(|(group, mut ctx)| EcPoint::from_bytes(&group, k.prefixed_bytes(), &mut ctx).map(|point| (group, point) ))
                .and_then(|(group, point)| EcKey::from_public_key(&group, &point))
                .and_then(|ec_key| PKey::from_ec_key(ec_key) )
                .map_err(|e| e.into())
                .map(|pkey| Ec{raw: public_key, pkey: pkey})

    }
}

#[cfg(all(not(feature = "ring"), feature = "openssl"))]
fn asn1_emit_integer(output: &mut Vec<u8>, int: &[u8]) {
    assert!(int.len() > 0);
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
#[cfg(all(not(feature = "ring"), feature = "openssl"))]
pub fn dnssec_ecdsa_signature_to_der(signature: &[u8]) -> DnsSecResult<Vec<u8>> {
    if signature.len() == 0 || signature.len() & 1 != 0 || signature.len() > 127 {
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
#[cfg(all(not(feature = "ring"), feature = "openssl"))]
impl<'k> PublicKey for Ec<'k> {
    fn public_bytes(&self) -> &[u8] {
        self.raw
    }

    fn verify(&self, algorithm: Algorithm, message: &[u8], signature: &[u8]) -> DnsSecResult<()> {
        let signature_asn1 = dnssec_ecdsa_signature_to_der(signature)?;
        verify_with_pkey(&self.pkey, algorithm, message, &signature_asn1)
    }
}

/// Elyptic Curve public key type
#[cfg(feature = "ring")]
type Ec = ECPublicKey;

#[cfg(feature = "ring")]
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
    pub fn from_public_bytes(public_key: &[u8], algorithm: Algorithm) -> DnsSecResult<Self> {
        ECPublicKey::from_unprefixed(public_key, algorithm)
    }
}

#[cfg(feature = "ring")]
impl PublicKey for Ec {
    fn public_bytes(&self) -> &[u8] {
        self.unprefixed_bytes()
    }

    fn verify(&self, algorithm: Algorithm, message: &[u8], signature: &[u8]) -> DnsSecResult<()> {
        // TODO: assert_eq!(algorithm, self.algorithm); once *ring* allows this.
        let alg = match algorithm {
            Algorithm::ECDSAP256SHA256 => &signature::ECDSA_P256_SHA256_FIXED,
            Algorithm::ECDSAP384SHA384 => &signature::ECDSA_P384_SHA384_FIXED,
            _ => return Err("only ECDSAP256SHA256 and ECDSAP384SHA384 are supported by Ec".into()),
        };
        signature::verify(alg, Input::from(self.prefixed_bytes()), Input::from(message),
                          Input::from(signature))
            .map_err(|e| e.into())
    }
}

/// Ed25519 Public key
#[cfg(feature = "ring")]
pub struct Ed25519<'k> {
    raw: &'k [u8],
}

#[cfg(feature = "ring")]
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
    pub fn from_public_bytes(public_key: &'k [u8]) -> DnsSecResult<Self> {
        if public_key.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(DnsSecErrorKind::Msg(format!("expected {} byte public_key: {}",
                                                    ED25519_PUBLIC_KEY_LEN,
                                                    public_key.len()))
                               .into());
        }

        Ok(Ed25519 { raw: public_key })
    }
}

#[cfg(feature = "ring")]
impl<'k> PublicKey for Ed25519<'k> {
    // TODO: just store reference to public key bytes in ctor...
    fn public_bytes(&self) -> &[u8] {
        self.raw
    }

    fn verify(&self, _: Algorithm, message: &[u8], signature: &[u8]) -> DnsSecResult<()> {
        let public_key = Input::from(self.raw);
        let message = Input::from(message);
        let signature = Input::from(signature);
        EdDSAParameters {}
            .verify(public_key, message, signature)
            .map_err(|e| e.into())
    }
}

/// Rsa public key
#[cfg(feature = "openssl")]
pub struct Rsa<'k> {
    raw: &'k [u8],
    pkey: PKey,
}

#[cfg(feature = "openssl")]
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
    pub fn from_public_bytes(public_key: &'k [u8]) -> DnsSecResult<Self> {
        if public_key.len() < 3 || public_key.len() > (4096 + 3) {
            return Err(DnsSecErrorKind::Message("bad public key").into());
        }
        let mut num_exp_len_octs = 1;
        let mut len: u16 = public_key[0] as u16;
        if len == 0 {
            num_exp_len_octs = 3;
            len = ((public_key[1] as u16) << 8) | (public_key[2] as u16)
        }
        let len = len; // demut

        // FYI: BigNum slices treat all slices as BigEndian, i.e NetworkByteOrder
        let e = try!(BigNum::from_slice(&public_key[(num_exp_len_octs as usize)..
                                         (len as usize + num_exp_len_octs)]));
        let n = try!(BigNum::from_slice(&public_key[(len as usize + num_exp_len_octs)..]));

        OpenSslRsa::from_public_components(n, e)
            .and_then(|rsa| PKey::from_rsa(rsa))
            .map_err(|e| e.into())
            .map(|pkey| {
                     Rsa {
                         raw: public_key,
                         pkey: pkey,
                     }
                 })
    }
}

#[cfg(feature = "openssl")]
impl<'k> PublicKey for Rsa<'k> {
    fn public_bytes(&self) -> &[u8] {
        self.raw
    }

    fn verify(&self, algorithm: Algorithm, message: &[u8], signature: &[u8]) -> DnsSecResult<()> {
        verify_with_pkey(&self.pkey, algorithm, message, signature)
    }
}

/// Variants of all know public keys
pub enum PublicKeyEnum<'k> {
    /// RSA keypair, supported by OpenSSL
    #[cfg(feature = "openssl")]
    Rsa(Rsa<'k>),
    /// Elliptic curve keypair
    #[cfg(all(not(feature = "ring"), feature = "openssl"))]
    Ec(Ec<'k>),
    /// Elliptic curve keypair
    #[cfg(feature = "ring")]
    Ec(Ec),
    /// Ed25519 public key for the Algorithm::ED25519
    #[cfg(feature = "ring")]
    Ed25519(Ed25519<'k>),
    /// PhatomData for compiler when ring and or openssl not defined, do not use...
    #[cfg(not(any(feature = "ring", feature = "openssl")))]
    Phantom(&'k PhantomData<()>),
}

impl<'k> PublicKeyEnum<'k> {
    /// Converts the bytes into a PulbicKey of the specified algorithm
    #[allow(unused_variables)]
    pub fn from_public_bytes(public_key: &'k [u8], algorithm: Algorithm) -> DnsSecResult<Self> {
        match algorithm {
            #[cfg(any(feature = "openssl", feature = "ring"))]
            Algorithm::ECDSAP256SHA256 |
            Algorithm::ECDSAP384SHA384 =>
                Ok(PublicKeyEnum::Ec(Ec::from_public_bytes(public_key, algorithm)?)),
            #[cfg(feature = "ring")]
            Algorithm::ED25519 => {
                Ok(PublicKeyEnum::Ed25519(Ed25519::from_public_bytes(public_key)?))
            }
            #[cfg(feature = "openssl")]
            Algorithm::RSASHA1 |
            Algorithm::RSASHA1NSEC3SHA1 |
            Algorithm::RSASHA256 |
            Algorithm::RSASHA512 => Ok(PublicKeyEnum::Rsa(Rsa::from_public_bytes(public_key)?)),
            #[cfg(not(all(feature = "ring", feature = "openssl")))]
            _ => Err("no public keys registered, enable ring or openssl features".into()),
        }
    }
}

impl<'k> PublicKey for PublicKeyEnum<'k> {
    fn public_bytes(&self) -> &[u8] {
        match *self {
            #[cfg(any(feature = "openssl", feature="ring"))]
            PublicKeyEnum::Ec(ref ec) => ec.public_bytes(),
            #[cfg(feature = "ring")]
            PublicKeyEnum::Ed25519(ref ed) => ed.public_bytes(),
            #[cfg(feature = "openssl")]
            PublicKeyEnum::Rsa(ref rsa) => rsa.public_bytes(),
            #[cfg(not(any(feature = "ring", feature = "openssl")))]
            _ => panic!("no public keys registered, enable ring or openssl features"),
        }
    }

    #[allow(unused_variables)]
    fn verify(&self, algorithm: Algorithm, message: &[u8], signature: &[u8]) -> DnsSecResult<()> {
        match *self {
            #[cfg(any(feature = "openssl", feature="ring"))]
            PublicKeyEnum::Ec(ref ec) => ec.verify(algorithm, message, signature),
            #[cfg(feature = "ring")]
            PublicKeyEnum::Ed25519(ref ed) => ed.verify(algorithm, message, signature),
            #[cfg(feature = "openssl")]
            PublicKeyEnum::Rsa(ref rsa) => rsa.verify(algorithm, message, signature),
            #[cfg(not(any(feature = "ring", feature = "openssl")))]
            _ => panic!("no public keys registered, enable ring or openssl features"),
        }
    }
}

#[cfg(all(not(feature = "ring"), feature = "openssl"))]
#[cfg(test)]
mod tests {
    #[cfg(feature = "openssl")]
    #[test]
    fn test_asn1_emit_integer() {
        fn test_case(source: &[u8], expected_data: &[u8]) {
            use rr::dnssec::public_key::asn1_emit_integer;

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
