// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! CDNSKEY type and related implementations

use std::{fmt, ops::Deref};

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use crate::{
    error::ProtoResult,
    rr::{RData, RecordData, RecordDataDecodable, RecordType},
    serialize::binary::{BinDecoder, BinEncodable, BinEncoder, Restrict},
};

use super::{DNSSECRData, DNSKEY};

/// RRSIG is really a derivation of the original SIG record data. See SIG for more documentation
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct CDNSKEY(DNSKEY);

impl Deref for CDNSKEY {
    type Target = DNSKEY;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl BinEncodable for CDNSKEY {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        self.0.emit(encoder)
    }
}

impl<'r> RecordDataDecodable<'r> for CDNSKEY {
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> ProtoResult<Self> {
        DNSKEY::read_data(decoder, length).map(Self)
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
        write!(f, "{}", self.0)
    }
}
