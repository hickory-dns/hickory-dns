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
    serialize::binary::{BinDecoder, BinEncodable, BinEncoder, Restrict},
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
pub struct OPENPGPKEY {
    public_key: Vec<u8>,
}

impl OPENPGPKEY {
    /// Creates a new OPENPGPKEY record data.
    ///
    /// # Arguments
    ///
    /// * `public_key` - an OpenPGP Transferable Public Key. This will NOT
    ///    be checked.
    pub fn new(public_key: Vec<u8>) -> Self {
        Self { public_key }
    }

    /// The public key. This should be an OpenPGP Transferable Public Key,
    /// but this is not guaranteed.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

impl BinEncodable for OPENPGPKEY {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.emit_vec(self.public_key())
    }
}

impl<'r> RecordDataDecodable<'r> for OPENPGPKEY {
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> ProtoResult<Self> {
        let rdata_length = length.map(usize::from).unverified();
        let public_key =
            decoder.read_vec(rdata_length)?.unverified(/*we do not enforce a specific format*/);
        Ok(Self::new(public_key))
    }
}

impl RecordData for OPENPGPKEY {
    fn try_from_rdata(data: RData) -> Result<Self, RData> {
        match data {
            RData::OPENPGPKEY(csync) => Ok(csync),
            _ => Err(data),
        }
    }

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

// TODO test
