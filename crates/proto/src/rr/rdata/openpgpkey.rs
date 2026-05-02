// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! OPENPGPKEY records for OpenPGP public keys
use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    error::ProtoResult,
    rr::{RData, RecordData, RecordDataDecodable, RecordType},
    serialize::{
        binary::{BinDecoder, BinEncodable, BinEncoder, DecodeError, Restrict},
        txt::ParseError,
    },
};

/// [RFC 7929](https://tools.ietf.org/html/rfc7929#section-2.1)
///
/// ```text
/// The RDATA portion of an OPENPGPKEY resource record contains a single
/// value consisting of a Transferable Public Key formatted as specified
/// in [RFC4880].
/// ```
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[non_exhaustive]
pub struct OPENPGPKEY {
    /// The public key.
    ///
    /// This should be an OpenPGP Transferable Public Key, but this is not guaranteed.
    pub public_key: Vec<u8>,
}

impl OPENPGPKEY {
    /// Creates a new OPENPGPKEY record data.
    ///
    /// # Arguments
    ///
    /// * `public_key` - an OpenPGP Transferable Public Key. This will NOT
    ///   be checked.
    pub fn new(public_key: Vec<u8>) -> Self {
        Self { public_key }
    }

    /// Parse the RData from a set of tokens.
    ///
    /// [RFC 7929](https://tools.ietf.org/html/rfc7929#section-2.3)
    ///
    /// ```text
    /// 2.3.  The OPENPGPKEY RDATA Presentation Format
    ///
    ///    The RDATA Presentation Format, as visible in Zone Files [RFC1035],
    ///    consists of a single OpenPGP Transferable Public Key as defined in
    ///    Section 11.1 of [RFC4880] encoded in base64 as defined in Section 4
    ///    of [RFC4648].
    /// ```
    pub(crate) fn from_tokens<'i, I: Iterator<Item = &'i str>>(
        mut tokens: I,
    ) -> Result<Self, ParseError> {
        let encoded_public_key = tokens.next().ok_or(ParseError::Message(
            "OPENPGPKEY public key field is missing",
        ))?;
        let public_key = data_encoding::BASE64.decode(encoded_public_key.as_bytes())?;
        Some(Self::new(public_key))
            .filter(|_| tokens.next().is_none())
            .ok_or(ParseError::Message("too many fields for OPENPGPKEY"))
    }
}

impl BinEncodable for OPENPGPKEY {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.write_slice(&self.public_key)
    }
}

impl<'r> RecordDataDecodable<'r> for OPENPGPKEY {
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> Result<Self, DecodeError> {
        let rdata_length = length.map(usize::from).unverified();
        let public_key =
            decoder.read_vec(rdata_length)?.unverified(/*we do not enforce a specific format*/);
        Ok(Self::new(public_key))
    }
}

impl RecordData for OPENPGPKEY {
    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::OPENPGPKEY(csync) => Some(csync),
            _ => None,
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::OPENPGPKEY
    }

    fn into_rdata(self) -> RData {
        RData::OPENPGPKEY(self)
    }
}

/// Parse the RData from a set of tokens.
///
/// [RFC 7929](https://tools.ietf.org/html/rfc7929#section-2.3)
///
/// ```text
/// 2.3.  The OPENPGPKEY RDATA Presentation Format
///
///    The RDATA Presentation Format, as visible in Zone Files [RFC1035],
///    consists of a single OpenPGP Transferable Public Key as defined in
///    Section 11.1 of [RFC4880] encoded in base64 as defined in Section 4
///    of [RFC4648].
/// ```
impl fmt::Display for OPENPGPKEY {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&data_encoding::BASE64.encode(&self.public_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parsing() {
        assert!(OPENPGPKEY::from_tokens(core::iter::empty()).is_err());
        assert!(OPENPGPKEY::from_tokens(vec!["äöüäööüä"].into_iter()).is_err());
        assert!(OPENPGPKEY::from_tokens(vec!["ZmFpbGVk", "äöüäöüö"].into_iter()).is_err());

        assert!(
            OPENPGPKEY::from_tokens(vec!["dHJ1c3RfZG5zIGlzIGF3ZXNvbWU="].into_iter())
                .map(|rd| rd == OPENPGPKEY::new(b"trust_dns is awesome".to_vec()))
                .unwrap_or(false)
        );
        assert!(
            OPENPGPKEY::from_tokens(vec!["c2VsZi1wcmFpc2Ugc3Rpbmtz"].into_iter())
                .map(|rd| rd == OPENPGPKEY::new(b"self-praise stinks".to_vec()))
                .unwrap_or(false)
        );
    }
}
