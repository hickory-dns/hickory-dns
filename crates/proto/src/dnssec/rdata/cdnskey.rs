// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! CDNSKEY type and related implementations

use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    ProtoError, ProtoErrorKind,
    dnssec::{Algorithm, PublicKeyBuf},
    error::ProtoResult,
    rr::{RData, RecordData, RecordDataDecodable, RecordType},
    serialize::binary::{BinDecoder, BinEncodable, BinEncoder, Restrict, RestrictedMath},
};

use super::DNSSECRData;

/// Child DNSKEY. See RFC 8078.
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct CDNSKEY {
    flags: u16,
    algorithm: Option<Algorithm>,
    public_key: Vec<u8>,
}

impl CDNSKEY {
    /// Construct a new CDNSKEY RData
    ///
    /// # Arguments
    ///
    /// * `zone_key` - this key is used to sign Zone resource records
    /// * `secure_entry_point` - this key is used to sign DNSKeys that sign the Zone records
    /// * `revoke` - this key has been revoked
    /// * `algorithm` - the key's algorithm, or `None` to request deletion
    /// * `public_key` - the public key encoded as a byte array
    ///
    /// # Return
    ///
    /// A new CDNSKEY RData for use in a Resource Record
    pub fn new(
        zone_key: bool,
        secure_entry_point: bool,
        revoke: bool,
        algorithm: Option<Algorithm>,
        public_key: Vec<u8>,
    ) -> Self {
        let mut flags: u16 = 0;
        if zone_key {
            flags |= 0b0000_0001_0000_0000;
        }
        if secure_entry_point {
            flags |= 0b0000_0000_0000_0001;
        }
        if revoke {
            flags |= 0b0000_0000_1000_0000;
        }
        Self::with_flags(flags, algorithm, public_key)
    }

    /// Construct a new CDNSKEY RData
    ///
    /// # Arguments
    ///
    /// * `flags` - flags associated with this key
    /// * `algorithm` - the key's algorithm, or `None` to request deletion
    /// * `public_key` - the public key encoded as a byte array
    ///
    /// # Return
    ///
    /// A new CDNSKEY RData for use in a Resource Record
    pub fn with_flags(flags: u16, algorithm: Option<Algorithm>, public_key: Vec<u8>) -> Self {
        Self {
            flags,
            algorithm,
            public_key,
        }
    }

    /// Returns the value of the Zone Key flag
    pub fn zone_key(&self) -> bool {
        self.flags & 0b0000_0001_0000_0000 != 0
    }

    /// Returns the value of the Secure Entry Point flag
    pub fn secure_entry_point(&self) -> bool {
        self.flags & 0b0000_0000_0000_0001 != 0
    }

    /// Returns the value of the Revoke flag.
    pub fn revoke(&self) -> bool {
        self.flags & 0b0000_0000_1000_0000 != 0
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

    /// Returns the public key, or `None` if deletion is requested.
    pub fn public_key(&self) -> Option<PublicKeyBuf> {
        Some(PublicKeyBuf::new(self.public_key.clone(), self.algorithm?))
    }

    /// Returns the Flags field
    pub fn flags(&self) -> u16 {
        self.flags
    }
}

impl From<CDNSKEY> for RData {
    fn from(value: CDNSKEY) -> Self {
        Self::DNSSEC(DNSSECRData::CDNSKEY(value))
    }
}

impl BinEncodable for CDNSKEY {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.emit_u16(self.flags())?;
        encoder.emit(3)?;
        match self.algorithm() {
            Some(algorithm) => algorithm.emit(encoder)?,
            None => encoder.emit_u8(0)?,
        }
        encoder.emit_vec(&self.public_key)?;

        Ok(())
    }
}

impl<'r> RecordDataDecodable<'r> for CDNSKEY {
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> ProtoResult<Self> {
        let flags = decoder.read_u16()?.unverified(/* used as a bitfield, this is safe */);

        // protocol is defined to only be '3' right now
        let _protocol = decoder
            .read_u8()?
            .verify_unwrap(|protocol| *protocol == 3)
            .map_err(|protocol| ProtoError::from(ProtoErrorKind::DnsKeyProtocolNot3(protocol)))?;

        let algorithm_value = decoder.read_u8()?.unverified(/* no further validation required */);
        let algorithm = match algorithm_value {
            0 => None,
            _ => Some(Algorithm::from_u8(algorithm_value)),
        };

        // The public key is the remaining bytes, excluding the first four bytes for the above
        // fields. This subtraction is safe, as the first three fields must have been in the RDATA,
        // otherwise there would have been an earlier return.
        let key_len = length
            .map(|u| u as usize)
            .checked_sub(4)
            .map_err(|_| ProtoError::from("invalid rdata length in DNSKEY"))?
            .unverified(/* used only as length safely */);
        let public_key = decoder
            .read_vec(key_len)?
            .unverified(/* signature verification will fail if the public key is invalid */);

        Ok(Self::with_flags(flags, algorithm, public_key))
    }
}

impl RecordData for CDNSKEY {
    fn try_from_rdata(data: RData) -> Result<Self, RData> {
        match data {
            RData::DNSSEC(DNSSECRData::CDNSKEY(cdnskey)) => Ok(cdnskey),
            _ => Err(data),
        }
    }

    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::DNSSEC(DNSSECRData::CDNSKEY(cdnskey)) => Some(cdnskey),
            _ => None,
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::CDNSKEY
    }

    fn into_rdata(self) -> RData {
        RData::DNSSEC(DNSSECRData::CDNSKEY(self))
    }
}

impl fmt::Display for CDNSKEY {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{flags} 3 {alg} {key}",
            flags = self.flags,
            alg = self.algorithm.map(u8::from).unwrap_or(0),
            key = data_encoding::BASE64.encode(&self.public_key)
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use alloc::vec::Vec;
    use std::println;

    use crate::{
        dnssec::Algorithm,
        rr::RecordDataDecodable,
        serialize::binary::{BinDecoder, BinEncodable, BinEncoder, Restrict},
    };

    use super::CDNSKEY;

    #[test]
    fn test() {
        let rdata = CDNSKEY::new(
            true,
            true,
            false,
            Some(Algorithm::ECDSAP256SHA256),
            vec![1u8, 2u8, 3u8, 4u8],
        );

        let mut bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut bytes);
        rdata.emit(&mut encoder).expect("error encoding");
        let bytes = encoder.into_bytes();

        println!("bytes: {bytes:?}");

        let mut decoder = BinDecoder::new(bytes);
        let read_rdata = CDNSKEY::read_data(&mut decoder, Restrict::new(bytes.len() as u16))
            .expect("error decoding");

        assert_eq!(rdata, read_rdata);
    }

    #[test]
    fn test_delete() {
        let rdata = CDNSKEY::with_flags(0, None, vec![0u8]);

        let mut bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut bytes);
        rdata.emit(&mut encoder).expect("error encoding");
        let bytes = encoder.into_bytes();

        println!("bytes: {bytes:?}");

        let mut decoder = BinDecoder::new(bytes);
        let read_rdata = CDNSKEY::read_data(&mut decoder, Restrict::new(bytes.len() as u16))
            .expect("error decoding");

        assert_eq!(rdata, read_rdata);
    }
}
