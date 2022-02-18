/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
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

//! parameters used for the nsec3 hash method

use std::fmt;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::rr::dnssec::Nsec3HashAlgorithm;
use crate::serialize::binary::*;

/// [RFC 5155](https://tools.ietf.org/html/rfc5155#section-4), NSEC3, March 2008
///
/// ```text
/// 4.  The NSEC3PARAM Resource Record
///
///    The NSEC3PARAM RR contains the NSEC3 parameters (hash algorithm,
///    flags, iterations, and salt) needed by authoritative servers to
///    calculate hashed owner names.  The presence of an NSEC3PARAM RR at a
///    zone apex indicates that the specified parameters may be used by
///    authoritative servers to choose an appropriate set of NSEC3 RRs for
///    negative responses.  The NSEC3PARAM RR is not used by validators or
///    resolvers.
///
///    If an NSEC3PARAM RR is present at the apex of a zone with a Flags
///    field value of zero, then there MUST be an NSEC3 RR using the same
///    hash algorithm, iterations, and salt parameters present at every
///    hashed owner name in the zone.  That is, the zone MUST contain a
///    complete set of NSEC3 RRs with the same hash algorithm, iterations,
///    and salt parameters.
///
///    The owner name for the NSEC3PARAM RR is the name of the zone apex.
///
///    The type value for the NSEC3PARAM RR is 51.
///
///    The NSEC3PARAM RR RDATA format is class independent and is described
///    below.
///
///    The class MUST be the same as the NSEC3 RRs to which this RR refers.
///
/// 4.2.  NSEC3PARAM RDATA Wire Format
///
///  The RDATA of the NSEC3PARAM RR is as shown below:
///
///                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |   Hash Alg.   |     Flags     |          Iterations           |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |  Salt Length  |                     Salt                      /
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
///  Hash Algorithm is a single octet.
///
///  Flags field is a single octet.
///
///  Iterations is represented as a 16-bit unsigned integer, with the most
///  significant bit first.
///
///  Salt Length is represented as an unsigned octet.  Salt Length
///  represents the length of the following Salt field in octets.  If the
///  value is zero, the Salt field is omitted.
///
///  Salt, if present, is encoded as a sequence of binary octets.  The
///  length of this field is determined by the preceding Salt Length
///  field.
/// ```
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct NSEC3PARAM {
    hash_algorithm: Nsec3HashAlgorithm,
    opt_out: bool,
    iterations: u16,
    salt: Vec<u8>,
}

impl NSEC3PARAM {
    /// Constructs a new NSEC3PARAM RData for use in a Resource Record
    pub fn new(
        hash_algorithm: Nsec3HashAlgorithm,
        opt_out: bool,
        iterations: u16,
        salt: Vec<u8>,
    ) -> Self {
        Self {
            hash_algorithm,
            opt_out,
            iterations,
            salt,
        }
    }

    /// [RFC 5155](https://tools.ietf.org/html/rfc5155#section-4.1.1), NSEC3, March 2008
    ///
    /// ```text
    /// 4.1.1.  Hash Algorithm
    ///
    ///    The Hash Algorithm field identifies the cryptographic hash algorithm
    ///    used to construct the hash-value.
    ///
    ///    The acceptable values are the same as the corresponding field in the
    ///    NSEC3 RR.
    /// ```
    pub fn hash_algorithm(&self) -> Nsec3HashAlgorithm {
        self.hash_algorithm
    }

    /// [RFC 5155](https://tools.ietf.org/html/rfc5155#section-4.1.2), NSEC3, March 2008
    ///
    /// ```text
    /// 4.1.2.  Flag Fields
    ///
    ///    The Opt-Out flag is not used and is set to zero.
    ///
    ///    All other flags are reserved for future use, and must be zero.
    ///
    ///    NSEC3PARAM RRs with a Flags field value other than zero MUST be
    ///    ignored.
    /// ```
    pub fn opt_out(&self) -> bool {
        self.opt_out
    }

    /// [RFC 5155](https://tools.ietf.org/html/rfc5155#section-4.1.3), NSEC3, March 2008
    ///
    /// ```text
    /// 4.1.3.  Iterations
    ///
    ///    The Iterations field defines the number of additional times the hash
    ///    is performed.
    ///
    ///    Its acceptable values are the same as the corresponding field in the
    ///    NSEC3 RR.
    /// ```
    pub fn iterations(&self) -> u16 {
        self.iterations
    }

    /// [RFC 5155](https://tools.ietf.org/html/rfc5155#section-4.1.5), NSEC3, March 2008
    ///
    /// ```text
    /// 4.1.5.  Salt
    ///
    ///    The Salt field is appended to the original owner name before hashing.
    /// ```
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// flags for encoding
    pub fn flags(&self) -> u8 {
        let mut flags: u8 = 0;
        if self.opt_out {
            flags |= 0b0000_0001
        };
        flags
    }
}

/// Read the RData from the given Decoder
pub fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<NSEC3PARAM> {
    let hash_algorithm =
        Nsec3HashAlgorithm::from_u8(decoder.read_u8()?.unverified(/*Algorithm verified as safe*/))?;
    let flags: u8 = decoder
        .read_u8()?
        .verify_unwrap(|flags| flags & 0b1111_1110 == 0)
        .map_err(|flags| ProtoError::from(ProtoErrorKind::UnrecognizedNsec3Flags(flags)))?;

    let opt_out: bool = flags & 0b0000_0001 == 0b0000_0001;
    let iterations: u16 = decoder.read_u16()?.unverified(/*valid as any u16*/);
    let salt_len: usize = decoder
        .read_u8()?
        .map(|u| u as usize)
        .verify_unwrap(|salt_len| *salt_len <= decoder.len())
        .map_err(|_| ProtoError::from("salt_len exceeds buffer length"))?;
    let salt: Vec<u8> = decoder.read_vec(salt_len)?.unverified(/*valid as any array of u8*/);

    Ok(NSEC3PARAM::new(hash_algorithm, opt_out, iterations, salt))
}

/// Write the RData from the given Decoder
pub fn emit(encoder: &mut BinEncoder<'_>, rdata: &NSEC3PARAM) -> ProtoResult<()> {
    encoder.emit(rdata.hash_algorithm().into())?;
    encoder.emit(rdata.flags())?;
    encoder.emit_u16(rdata.iterations())?;
    encoder.emit(rdata.salt().len() as u8)?;
    encoder.emit_vec(rdata.salt())?;

    Ok(())
}

/// [RFC 5155](https://tools.ietf.org/html/rfc5155#section-4), NSEC3, March 2008
///
/// ```text
/// 4.3.  Presentation Format
///
///    The presentation format of the RDATA portion is as follows:
///
///    o  The Hash Algorithm field is represented as an unsigned decimal
///       integer.  The value has a maximum of 255.
///
///    o  The Flags field is represented as an unsigned decimal integer.
///       The value has a maximum value of 255.
///
///    o  The Iterations field is represented as an unsigned decimal
///       integer.  The value is between 0 and 65535, inclusive.
///
///    o  The Salt Length field is not represented.
///
///    o  The Salt field is represented as a sequence of case-insensitive
///       hexadecimal digits.  Whitespace is not allowed within the
///       sequence.  This field is represented as "-" (without the quotes)
///       when the Salt Length field is zero.
/// ```
impl fmt::Display for NSEC3PARAM {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let salt = if self.salt.is_empty() {
            "-".to_string()
        } else {
            data_encoding::HEXUPPER_PERMISSIVE.encode(&self.salt)
        };

        write!(
            f,
            "{alg} {flags} {iterations} {salt}",
            alg = u8::from(self.hash_algorithm),
            flags = self.flags(),
            iterations = self.iterations,
            salt = salt
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;

    #[test]
    fn test() {
        let rdata = NSEC3PARAM::new(Nsec3HashAlgorithm::SHA1, true, 2, vec![1, 2, 3, 4, 5]);

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(emit(&mut encoder, &rdata).is_ok());
        let bytes = encoder.into_bytes();

        println!("bytes: {:?}", bytes);

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let read_rdata = read(&mut decoder).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }
}
