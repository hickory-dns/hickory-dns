// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! pointer record from parent zone to child zone for dnskey proof

use alloc::borrow::ToOwned;
use alloc::vec::Vec;
use core::fmt::{self, Display, Formatter};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::DNSSECRData;
use crate::{
    dnssec::{Algorithm, DigestType, DnsSecError, PublicKey, rdata::DNSKEY},
    error::{ProtoError, ProtoResult},
    rr::{Name, RData, RecordData, RecordDataDecodable, RecordType},
    serialize::binary::{
        BinDecodable, BinDecoder, BinEncodable, BinEncoder, Restrict, RestrictedMath,
    },
};

/// [RFC 4034, DNSSEC Resource Records, March 2005](https://tools.ietf.org/html/rfc4034#section-5)
///
/// ```text
/// 5.1.  DS RDATA Wire Format
///
///    The RDATA for a DS RR consists of a 2 octet Key Tag field, a 1 octet
///    Algorithm field, a 1 octet Digest Type field, and a Digest field.
///
///                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |           Key Tag             |  Algorithm    |  Digest Type  |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    /                                                               /
///    /                            Digest                             /
///    /                                                               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// 5.2.  Processing of DS RRs When Validating Responses
///
///    The DS RR links the authentication chain across zone boundaries, so
///    the DS RR requires extra care in processing.  The DNSKEY RR referred
///    to in the DS RR MUST be a DNSSEC zone key.  The DNSKEY RR Flags MUST
///    have Flags bit 7 set.  If the DNSKEY flags do not indicate a DNSSEC
///    zone key, the DS RR (and the DNSKEY RR it references) MUST NOT be
///    used in the validation process.
///
/// 5.3.  The DS RR Presentation Format
///
///    The presentation format of the RDATA portion is as follows:
///
///    The Key Tag field MUST be represented as an unsigned decimal integer.
///
///    The Algorithm field MUST be represented either as an unsigned decimal
///    integer or as an algorithm mnemonic specified in Appendix A.1.
///
///    The Digest Type field MUST be represented as an unsigned decimal
///    integer.
///
///    The Digest MUST be represented as a sequence of case-insensitive
///    hexadecimal digits.  Whitespace is allowed within the hexadecimal
///    text.
/// ```
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct DS {
    key_tag: u16,
    algorithm: Algorithm,
    digest_type: DigestType,
    digest: Vec<u8>,
}

impl DS {
    /// Creates a [`DS`] record for the given `public_key` and `name`.
    ///
    /// # Arguments
    ///
    /// * `public_key` - the public key to create the DS record for
    /// * `name` - name of the DNSKEY record covered by the new DS record
    /// * `algorithm` - the algorithm of the DNSKEY
    /// * `digest_type` - the digest_type used to
    pub fn from_key(
        public_key: &dyn PublicKey,
        name: &Name,
        digest_type: DigestType,
    ) -> Result<Self, DnsSecError> {
        let tag = key_tag(public_key.public_bytes());
        let dnskey = DNSKEY::from_key(public_key);
        Ok(Self::new(
            tag,
            public_key.algorithm(),
            digest_type,
            dnskey.to_digest(name, digest_type)?.as_ref().to_owned(),
        ))
    }

    /// Constructs a new DS RData
    ///
    /// # Arguments
    ///
    /// * `key_tag` - the key_tag associated to the DNSKEY
    /// * `algorithm` - algorithm as specified in the DNSKEY
    /// * `digest_type` - hash algorithm used to validate the DNSKEY
    /// * `digest` - hash of the DNSKEY
    ///
    /// # Returns
    ///
    /// the DS RDATA for use in a Resource Record
    pub fn new(
        key_tag: u16,
        algorithm: Algorithm,
        digest_type: DigestType,
        digest: Vec<u8>,
    ) -> Self {
        Self {
            key_tag,
            algorithm,
            digest_type,
            digest,
        }
    }

    /// [RFC 4034, DNSSEC Resource Records, March 2005](https://tools.ietf.org/html/rfc4034#section-5.1.1)
    ///
    /// ```text
    /// 5.1.1.  The Key Tag Field
    ///
    ///    The Key Tag field lists the key tag of the DNSKEY RR referred to by
    ///    the DS record, in network byte order.
    ///
    ///    The Key Tag used by the DS RR is identical to the Key Tag used by
    ///    RRSIG RRs.  Appendix B describes how to compute a Key Tag.
    /// ```
    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// [RFC 4034, DNSSEC Resource Records, March 2005](https://tools.ietf.org/html/rfc4034#section-5.1.1)
    ///
    /// ```text
    /// 5.1.2.  The Algorithm Field
    ///
    ///    The Algorithm field lists the algorithm number of the DNSKEY RR
    ///    referred to by the DS record.
    ///
    ///    The algorithm number used by the DS RR is identical to the algorithm
    ///    number used by RRSIG and DNSKEY RRs.  Appendix A.1 lists the
    ///    algorithm number types.
    /// ```
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// [RFC 4034, DNSSEC Resource Records, March 2005](https://tools.ietf.org/html/rfc4034#section-5.1.1)
    ///
    /// ```text
    /// 5.1.3.  The Digest Type Field
    ///
    ///    The DS RR refers to a DNSKEY RR by including a digest of that DNSKEY
    ///    RR.  The Digest Type field identifies the algorithm used to construct
    ///    the digest.  Appendix A.2 lists the possible digest algorithm types.
    /// ```
    pub fn digest_type(&self) -> DigestType {
        self.digest_type
    }

    /// [RFC 4034, DNSSEC Resource Records, March 2005](https://tools.ietf.org/html/rfc4034#section-5.1.1)
    ///
    /// ```text
    /// 5.1.4.  The Digest Field
    ///
    ///    The DS record refers to a DNSKEY RR by including a digest of that
    ///    DNSKEY RR.
    ///
    ///    The digest is calculated by concatenating the canonical form of the
    ///    fully qualified owner name of the DNSKEY RR with the DNSKEY RDATA,
    ///    and then applying the digest algorithm.
    ///
    ///      digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
    ///
    ///       "|" denotes concatenation
    ///
    ///      DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.
    ///
    ///    The size of the digest may vary depending on the digest algorithm and
    ///    DNSKEY RR size.  As of the time of this writing, the only defined
    ///    digest algorithm is SHA-1, which produces a 20 octet digest.
    /// ```
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    /// Validates that a given DNSKEY is covered by the DS record.
    ///
    /// # Return
    ///
    /// true if and only if the DNSKEY is covered by the DS record.
    pub fn covers(&self, name: &Name, key: &DNSKEY) -> ProtoResult<bool> {
        key.to_digest(name, self.digest_type())
            .map(|hash| key.zone_key() && hash.as_ref() == self.digest())
    }
}

impl BinEncodable for DS {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.emit_u16(self.key_tag())?;
        self.algorithm().emit(encoder)?;
        encoder.emit(self.digest_type().into())?;
        encoder.emit_vec(self.digest())?;

        Ok(())
    }
}

impl<'r> RecordDataDecodable<'r> for DS {
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> ProtoResult<Self> {
        let start_idx = decoder.index();

        let key_tag: u16 = decoder.read_u16()?.unverified(/*key_tag is valid as any u16*/);
        let algorithm: Algorithm = Algorithm::read(decoder)?;
        let digest_type =
            DigestType::from(decoder.read_u8()?.unverified(/*DigestType is verified as safe*/));

        let bytes_read = decoder.index() - start_idx;
        let left: usize = length
        .map(|u| u as usize)
        .checked_sub(bytes_read)
        .map_err(|_| ProtoError::from("invalid rdata length in DS"))?
        .unverified(/*used only as length safely*/);
        let digest =
            decoder.read_vec(left)?.unverified(/*the byte array will fail in usage if invalid*/);

        Ok(Self::new(key_tag, algorithm, digest_type, digest))
    }
}

impl RecordData for DS {
    fn try_from_rdata(data: RData) -> Result<Self, RData> {
        match data {
            RData::DNSSEC(DNSSECRData::DS(csync)) => Ok(csync),
            _ => Err(data),
        }
    }

    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::DNSSEC(DNSSECRData::DS(csync)) => Some(csync),
            _ => None,
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::DS
    }

    fn into_rdata(self) -> RData {
        RData::DNSSEC(DNSSECRData::DS(self))
    }
}

/// [RFC 4034, DNSSEC Resource Records, March 2005](https://tools.ietf.org/html/rfc4034#section-5.3)
///
/// ```text
/// 5.3.  The DS RR Presentation Format
///
///    The presentation format of the RDATA portion is as follows:
///
///    The Key Tag field MUST be represented as an unsigned decimal integer.
///
///    The Algorithm field MUST be represented either as an unsigned decimal
///    integer or as an algorithm mnemonic specified in Appendix A.1.
///
///    The Digest Type field MUST be represented as an unsigned decimal
///    integer.
///
///    The Digest MUST be represented as a sequence of case-insensitive
///    hexadecimal digits.  Whitespace is allowed within the hexadecimal
///    text.
///
/// 5.4.  DS RR Example
///
///    The following example shows a DNSKEY RR and its corresponding DS RR.
///
///    dskey.example.com. 86400 IN DNSKEY 256 3 5 ( AQOeiiR0GOMYkDshWoSKz9Xz
///                                              fwJr1AYtsmx3TGkJaNXVbfi/
///                                              2pHm822aJ5iI9BMzNXxeYCmZ
///                                              DRD99WYwYqUSdjMmmAphXdvx
///                                              egXd/M5+X7OrzKBaMbCVdFLU
///                                              Uh6DhweJBjEVv5f2wwjM9Xzc
///                                              nOf+EPbtG9DMBmADjFDc2w/r
///                                              ljwvFw==
///                                              ) ;  key id = 60485
///
///    dskey.example.com. 86400 IN DS 60485 5 1 ( 2BB183AF5F22588179A53B0A
///                                               98631FAD1A292118 )
///
///    The first four text fields specify the name, TTL, Class, and RR type
///    (DS).  Value 60485 is the key tag for the corresponding
///    "dskey.example.com." DNSKEY RR, and value 5 denotes the algorithm
///    used by this "dskey.example.com." DNSKEY RR.  The value 1 is the
///    algorithm used to construct the digest, and the rest of the RDATA
///    text is the digest in hexadecimal.
/// ```
impl Display for DS {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{tag} {alg} {ty} {digest}",
            tag = self.key_tag,
            alg = u8::from(self.algorithm),
            ty = u8::from(self.digest_type),
            digest = data_encoding::HEXUPPER_PERMISSIVE.encode(&self.digest)
        )
    }
}

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
fn key_tag(public_key: &[u8]) -> u16 {
    let mut ac = 0;

    for (i, k) in public_key.iter().enumerate() {
        ac += if i & 0x0001 == 0x0001 {
            *k as usize
        } else {
            (*k as usize) << 8
        };
    }

    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16 // this is unnecessary, no?
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use std::println;

    use super::*;
    use crate::dnssec::{PublicKeyBuf, SigningKey, crypto::EcdsaSigningKey, rdata::DNSKEY};

    #[test]
    fn test() {
        let rdata = DS::new(
            0xF00F,
            Algorithm::RSASHA256,
            DigestType::SHA256,
            vec![5, 6, 7, 8],
        );

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(rdata.emit(&mut encoder).is_ok());
        let bytes = encoder.into_bytes();

        println!("bytes: {bytes:?}");

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let restrict = Restrict::new(bytes.len() as u16);
        let read_rdata = DS::read_data(&mut decoder, restrict).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }

    #[test]
    fn test_covers() {
        let algorithm = Algorithm::ECDSAP256SHA256;
        let pkcs8 = EcdsaSigningKey::generate_pkcs8(algorithm).unwrap();
        let signing_key = EcdsaSigningKey::from_pkcs8(&pkcs8, algorithm).unwrap();

        let dnskey_rdata = DNSKEY::new(
            true,
            true,
            false,
            PublicKeyBuf::new(
                signing_key
                    .to_public_key()
                    .unwrap()
                    .public_bytes()
                    .to_owned(),
                algorithm,
            ),
        );

        let name = Name::parse("www.example.com.", None).unwrap();
        let ds_rdata = DS::new(
            0,
            algorithm,
            DigestType::SHA256,
            dnskey_rdata
                .to_digest(&name, DigestType::SHA256)
                .unwrap()
                .as_ref()
                .to_owned(),
        );

        assert!(ds_rdata.covers(&name, &dnskey_rdata).unwrap());
    }

    #[test]
    fn test_covers_fails_with_non_zone_key() {
        let algorithm = Algorithm::ECDSAP256SHA256;
        let pkcs8 = EcdsaSigningKey::generate_pkcs8(algorithm).unwrap();
        let signing_key = EcdsaSigningKey::from_pkcs8(&pkcs8, algorithm).unwrap();

        let dnskey_rdata = DNSKEY::new(
            false,
            true,
            false,
            PublicKeyBuf::new(
                signing_key
                    .to_public_key()
                    .unwrap()
                    .public_bytes()
                    .to_owned(),
                algorithm,
            ),
        );

        let name = Name::parse("www.example.com.", None).unwrap();
        let ds_rdata = DS::new(
            0,
            algorithm,
            DigestType::SHA256,
            dnskey_rdata
                .to_digest(&name, DigestType::SHA256)
                .unwrap()
                .as_ref()
                .to_owned(),
        );

        assert!(!ds_rdata.covers(&name, &dnskey_rdata).unwrap());
    }

    #[test]
    fn test_covers_uppercase() {
        let algorithm = Algorithm::ECDSAP256SHA256;
        let pkcs8 = EcdsaSigningKey::generate_pkcs8(algorithm).unwrap();
        let signing_key = EcdsaSigningKey::from_pkcs8(&pkcs8, algorithm).unwrap();

        let dnskey_rdata = DNSKEY::new(
            true,
            true,
            false,
            PublicKeyBuf::new(
                signing_key
                    .to_public_key()
                    .unwrap()
                    .public_bytes()
                    .to_owned(),
                algorithm,
            ),
        );

        let name = Name::parse("www.example.com.", None).unwrap();
        let ds_rdata = DS::new(
            0,
            algorithm,
            DigestType::SHA256,
            dnskey_rdata
                .to_digest(&name, DigestType::SHA256)
                .unwrap()
                .as_ref()
                .to_owned(),
        );

        let uppercase_name = Name::from_ascii("WWW.EXAMPLE.COM.").unwrap();
        assert!(ds_rdata.covers(&uppercase_name, &dnskey_rdata).unwrap());
    }
}
