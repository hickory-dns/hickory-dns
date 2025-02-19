// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! CDS type and related implementations

use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    ProtoError,
    dnssec::{Algorithm, DigestType},
    error::ProtoResult,
    rr::{RData, RecordData, RecordDataDecodable, RecordType},
    serialize::binary::{BinDecoder, BinEncodable, BinEncoder, Restrict, RestrictedMath},
};

use super::DNSSECRData;

/// Child DS. See RFC 8078.
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct CDS {
    key_tag: u16,
    /// The algorithm of the desired DS record if requesting an update, or `None` if requesting
    /// deletion.
    algorithm: Option<Algorithm>,
    digest_type: DigestType,
    digest: Vec<u8>,
}

impl CDS {
    /// Constructs a new CDS RData
    ///
    /// # Arguments
    ///
    /// * `key_tag` - the key tag associated to the DNSKEY
    /// * `algorithm` - algorithm as specified in the DNSKEY, or None to request DS RRset deletion
    /// * `digest_type` - hash algorithm used to validate the DNSKEY
    /// * `digest` - hash of the DNSKEY
    ///
    /// # Returns
    ///
    /// the CDS RDATA for use in a Resource Record
    pub fn new(
        key_tag: u16,
        algorithm: Option<Algorithm>,
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

    /// Returns the Key Tag field
    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// Returns the Algorithm field. This is `None` if deletion is requested, or the key's algorithm
    /// if an update is requested.
    pub fn algorithm(&self) -> Option<Algorithm> {
        self.algorithm
    }

    /// Returns whether this record is requesting deletion of the DS RRset.
    pub fn is_delete(&self) -> bool {
        self.algorithm.is_none()
    }

    /// Returns the Digest Type field.
    pub fn digest_type(&self) -> DigestType {
        self.digest_type
    }

    /// Returns the Digest field.
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }
}

impl From<CDS> for RData {
    fn from(value: CDS) -> Self {
        Self::DNSSEC(DNSSECRData::CDS(value))
    }
}

impl BinEncodable for CDS {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.emit_u16(self.key_tag())?;
        match self.algorithm() {
            Some(algorithm) => algorithm.emit(encoder)?,
            None => encoder.emit_u8(0)?,
        }
        encoder.emit(self.digest_type().into())?;
        encoder.emit_vec(self.digest())?;

        Ok(())
    }
}

impl<'r> RecordDataDecodable<'r> for CDS {
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> ProtoResult<Self> {
        let start_idx = decoder.index();

        let key_tag = decoder.read_u16()?.unverified(/* any u16 is a valid key_tag */);

        let algorithm_value = decoder.read_u8()?.unverified(/* no further validation required */);
        let algorithm = match algorithm_value {
            0 => None,
            _ => Some(Algorithm::from_u8(algorithm_value)),
        };

        let digest_type =
            DigestType::from(decoder.read_u8()?.unverified(/* DigestType is verified as safe */));

        let bytes_read = decoder.index() - start_idx;
        let left = length
            .map(|u| u as usize)
            .checked_sub(bytes_read)
            .map_err(|_| ProtoError::from("invalid rdata length in CDS"))?
            .unverified(/* used only as length safely */);
        let digest =
            decoder.read_vec(left)?.unverified(/* this is only compared with other digests */);

        Ok(Self::new(key_tag, algorithm, digest_type, digest))
    }
}

impl RecordData for CDS {
    fn try_from_rdata(data: RData) -> Result<Self, RData> {
        match data {
            RData::DNSSEC(DNSSECRData::CDS(cds)) => Ok(cds),
            _ => Err(data),
        }
    }

    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::DNSSEC(DNSSECRData::CDS(cds)) => Some(cds),
            _ => None,
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::CDS
    }

    fn into_rdata(self) -> RData {
        RData::DNSSEC(DNSSECRData::CDS(self))
    }
}

impl fmt::Display for CDS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{tag} {alg} {ty} {digest}",
            tag = self.key_tag,
            alg = self.algorithm.map(u8::from).unwrap_or(0),
            ty = u8::from(self.digest_type),
            digest = data_encoding::HEXUPPER_PERMISSIVE.encode(&self.digest)
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use alloc::vec::Vec;
    use std::println;

    use crate::{
        dnssec::{Algorithm, DigestType},
        rr::RecordDataDecodable,
        serialize::binary::{BinDecoder, BinEncodable, BinEncoder, Restrict},
    };

    use super::CDS;

    #[test]
    fn test() {
        let rdata = CDS::new(
            0xF00F,
            Some(Algorithm::RSASHA256),
            DigestType::SHA256,
            vec![5, 6, 7, 8],
        );

        let mut bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut bytes);
        rdata.emit(&mut encoder).expect("error encoding");
        let bytes = encoder.into_bytes();

        println!("bytes: {bytes:?}");

        let mut decoder = BinDecoder::new(bytes);
        let read_rdata = CDS::read_data(&mut decoder, Restrict::new(bytes.len() as u16))
            .expect("error decoding");
        assert_eq!(rdata, read_rdata);
    }

    #[test]
    fn test_delete() {
        let rdata = CDS::new(0, None, DigestType::Unknown(0), vec![0]);

        let mut bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut bytes);
        rdata.emit(&mut encoder).expect("error encoding");
        let bytes = encoder.into_bytes();

        println!("bytes: {bytes:?}");

        let mut decoder = BinDecoder::new(bytes);
        let read_rdata = CDS::read_data(&mut decoder, Restrict::new(bytes.len() as u16))
            .expect("error decoding");
        assert_eq!(rdata, read_rdata);
    }
}
