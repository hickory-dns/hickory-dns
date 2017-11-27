/*
 * Copyright (C) 2016 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! pointer record from parent zone to child zone for dnskey proof

use serialize::binary::*;
use error::*;
use rr::dnssec::{Algorithm, DigestType};

use rr::dnssec::rdata::DNSKEY;
use rr::Name;

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
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct DS {
    key_tag: u16,
    algorithm: Algorithm,
    digest_type: DigestType,
    digest: Vec<u8>,
}

impl DS {
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
    pub fn new(key_tag: u16, algorithm: Algorithm, digest_type: DigestType, digest: Vec<u8>) -> DS {
        DS {
            key_tag: key_tag,
            algorithm: algorithm,
            digest_type: digest_type,
            digest: digest,
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
    pub fn algorithm(&self) -> &Algorithm {
        &self.algorithm
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
    #[cfg(any(feature = "openssl", feature = "ring"))]
    pub fn covers(&self, name: &Name, key: &DNSKEY) -> ProtoResult<bool> {
        key.to_digest(name, self.digest_type())
            .map(|hash| hash.as_ref() == self.digest())
    }

    /// This will always return an error unless the Ring or OpenSSL features are enabled
    #[cfg(not(any(feature = "openssl", feature = "ring")))]
    pub fn covers(&self, _: &Name, _: &DNSKEY) -> ProtoResult<bool> {
        Err(ProtoErrorKind::Message("Ring or OpenSSL must be enabled for this feature").into())
    }
}

/// Read the RData from the given Decoder
pub fn read(decoder: &mut BinDecoder, rdata_length: u16) -> ProtoResult<DS> {
    let start_idx = decoder.index();

    let key_tag: u16 = decoder.read_u16()?;
    let algorithm: Algorithm = Algorithm::read(decoder)?;
    let digest_type: DigestType = DigestType::from_u8(decoder.read_u8()?)?;

    let left: usize = rdata_length as usize - (decoder.index() - start_idx);
    let digest = decoder.read_vec(left)?;

    Ok(DS::new(key_tag, algorithm, digest_type, digest))
}

/// Write the RData from the given Decoder
pub fn emit(encoder: &mut BinEncoder, rdata: &DS) -> ProtoResult<()> {
    encoder.emit_u16(rdata.key_tag())?;
    rdata.algorithm().emit(encoder)?; // always 3 for now
    encoder.emit(rdata.digest_type().into())?;
    encoder.emit_vec(rdata.digest())?;

    Ok(())
}

#[test]
pub fn test() {
    let rdata = DS::new(
        0xF00F,
        Algorithm::RSASHA256,
        DigestType::SHA256,
        vec![5, 6, 7, 8],
    );

    let mut bytes = Vec::new();
    let mut encoder: BinEncoder = BinEncoder::new(&mut bytes);
    assert!(emit(&mut encoder, &rdata).is_ok());
    let bytes = encoder.into_bytes();

    println!("bytes: {:?}", bytes);

    let mut decoder: BinDecoder = BinDecoder::new(bytes);
    let read_rdata = read(&mut decoder, bytes.len() as u16);
    assert!(
        read_rdata.is_ok(),
        format!("error decoding: {:?}", read_rdata.unwrap_err())
    );
    assert_eq!(rdata, read_rdata.unwrap());
}

#[test]
#[cfg(any(feature = "openssl", feature = "ring"))]
pub fn test_covers() {
    use rr::dnssec::rdata::DNSKEY;

    let name = Name::parse("www.example.com.", None).unwrap();

    let dnskey_rdata = DNSKEY::new(true, true, false, Algorithm::RSASHA256, vec![1, 2, 3, 4]);
    let ds_rdata = DS::new(
        0,
        Algorithm::RSASHA256,
        DigestType::SHA256,
        dnskey_rdata
            .to_digest(&name, DigestType::SHA256)
            .unwrap()
            .as_ref()
            .to_owned(),
    );

    assert!(ds_rdata.covers(&name, &dnskey_rdata).unwrap());
}
