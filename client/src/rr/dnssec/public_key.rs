// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::marker::PhantomData;

#[cfg(feature = "ring")]
use untrusted::Input;

#[cfg(feature = "ring")]
use ring::signature::{ED25519_PUBLIC_KEY_LEN, EdDSAParameters, VerificationAlgorithm};

use error::*;
use rr::dnssec::algorithm::Algorithm;

/// PublicKeys implement the ability to ideally be zero copy abstractions over public keys for verifying signed content.
///
/// In DNS the KEY and DNSKEY types are generally the RData types which store public key material.
pub trait PublicKey {
    /// Converts this keypair to the DNS binary form of the public_key.
    ///
    /// If there is a private key associated with this keypair, it will not be included in this
    ///  format. Only the public key material will be included.
    fn to_public_bytes(&self) -> DnsSecResult<Vec<u8>>;

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

        for (i, k) in try!(self.to_public_bytes()).iter().enumerate() {
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

#[cfg(feature = "ring")]
pub struct Ed25519<'k> {
    bytes: &'k [u8],
}

#[cfg(feature = "ring")]
impl<'k> Ed25519<'k> {
    /// Internet-Draft              EdDSA for DNSSEC               December 2016
    ///
    ///  An Ed25519 public key consists of a 32-octet value, which is encoded
    ///  into the Public Key field of a DNSKEY resource record as a simple bit
    ///  string.  The generation of a public key is defined in Section 5.1.5
    ///  in [RFC 8032]. Breaking tradition, the keys are encoded in little-
    ///  endian byte order.
    fn from_public_bytes(public_key: &'k [u8], algorithm: Algorithm) -> DnsSecResult<Self> {
        if public_key.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(DnsSecErrorKind::Msg(format!("expected {} byte public_key: {}",
                                                    ED25519_PUBLIC_KEY_LEN,
                                                    public_key.len()))
                               .into());
        }

        Ok(Ed25519 { bytes: public_key })
    }
}

#[cfg(feature = "ring")]
impl<'k> PublicKey for Ed25519<'k> {
    // TODO: just store reference to public key bytes in ctor...
    fn to_public_bytes(&self) -> DnsSecResult<Vec<u8>> {
        Ok(self.bytes.to_vec())
    }

    fn verify(&self, algorithm: Algorithm, message: &[u8], signature: &[u8]) -> DnsSecResult<()> {
        let public_key = Input::from(self.bytes);
        let message = Input::from(message);
        let signature = Input::from(signature);
        EdDSAParameters {}
            .verify(public_key, message, signature)
            .map_err(|e| e.into())
    }
}

/// Variants of all know public keys
pub enum PublicKeyEnum<'k> {
    /// RSA keypair, supported by OpenSSL
    #[cfg(feature = "openssl")]
    RSA(),
    /// Ellyptic curve keypair, supported by OpenSSL
    #[cfg(feature = "openssl")]
    EC(),
    /// Ed25519 public key for the Algorithm::ED25519
    #[cfg(feature = "ring")]
    Ed25519(Ed25519<'k>),
    /// PhatomData for compiler when ring and or openssl not defined, do not use...
    #[cfg(not(any(feature = "ring", feature = "openssl")))]   
    Phantom(&'k PhantomData<()>)
}

impl<'k> PublicKeyEnum<'k> {
    /// Converts the bytes into a PulbicKey of the specified algorithm
    pub fn from_public_bytes(public_key: &'k [u8], algorithm: Algorithm) -> DnsSecResult<Self> {
        match algorithm {
            #[cfg(feature = "ring")]
            Algorithm::ED25519 => Ok(PublicKeyEnum::Ed25519(Ed25519::from_public_bytes(public_key, algorithm)?)),
            _ => Err("no public keys registered, enable ring or openssl features".into()),
        }
    }
}

impl<'k> PublicKey for PublicKeyEnum<'k> {
    fn to_public_bytes(&self) -> DnsSecResult<Vec<u8>> {
        match *self {
            #[cfg(feature = "ring")]
            PublicKeyEnum::Ed25519(ref ed) => ed.to_public_bytes(),
            _ => Err("no public keys registered, enable ring or openssl features".into()),
        }
    }

    fn verify(&self, algorithm: Algorithm, message: &[u8], signature: &[u8]) -> DnsSecResult<()> {
        match *self {
            #[cfg(feature = "ring")]
            PublicKeyEnum::Ed25519(ref ed) => ed.verify(algorithm, message, signature),
            _ => panic!("no public keys registered, enable ring or openssl features"),            
        }
    }
}