// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! HTTPS type and related implementations

use core::{fmt, ops::Deref};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    error::ProtoResult,
    rr::{RData, RecordData, RecordDataDecodable, RecordType},
    serialize::binary::{BinDecoder, BinEncodable, BinEncoder, Restrict},
};

use super::SVCB;

/// HTTPS is really a derivation of the original SVCB record data. See SVCB for more documentation
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct HTTPS(pub SVCB);

impl Deref for HTTPS {
    type Target = SVCB;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl BinEncodable for HTTPS {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        self.0.emit(encoder)
    }
}

impl<'r> RecordDataDecodable<'r> for HTTPS {
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> ProtoResult<Self> {
        SVCB::read_data(decoder, length).map(Self)
    }
}

impl RecordData for HTTPS {
    fn try_from_rdata(data: RData) -> Result<Self, RData> {
        match data {
            RData::HTTPS(https) => Ok(https),
            _ => Err(data),
        }
    }

    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::HTTPS(https) => Some(https),
            _ => None,
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::HTTPS
    }

    fn into_rdata(self) -> RData {
        RData::HTTPS(self)
    }
}

impl fmt::Display for HTTPS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
    }
}
