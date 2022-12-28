// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! RRSIG type and related implementations

use std::{fmt, ops::Deref};

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use crate::{
    error::ProtoResult,
    rr::{RData, RecordData, RecordDataDecodable, RecordType},
    serialize::binary::{BinDecoder, BinEncodable, BinEncoder, Restrict},
};

use super::{DNSSECRData, SIG};

/// RRSIG is really a derivation of the original SIG record data. See SIG for more documentation
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct RRSIG(SIG);

impl Deref for RRSIG {
    type Target = SIG;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl BinEncodable for RRSIG {
    /// [RFC 4034](https://tools.ietf.org/html/rfc4034#section-6), DNSSEC Resource Records, March 2005
    ///
    /// This is accurate for all currently known name records.
    ///
    /// ```text
    /// 6.2.  Canonical RR Form
    ///
    ///    For the purposes of DNS security, the canonical form of an RR is the
    ///    wire format of the RR where:
    ///
    ///    ...
    ///
    ///    3.  if the type of the RR is NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR,
    ///        HINFO, MINFO, MX, HINFO, RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX,
    ///        SRV, DNAME, A6, RRSIG, or (rfc6840 removes NSEC), all uppercase
    ///        US-ASCII letters in the DNS names contained within the RDATA are replaced
    ///        by the corresponding lowercase US-ASCII letters;
    /// ```
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        self.0.emit(encoder)
    }
}

impl<'r> RecordDataDecodable<'r> for RRSIG {
    fn read_data(
        decoder: &mut BinDecoder<'r>,
        record_type: RecordType,
        length: Restrict<u16>,
    ) -> ProtoResult<Self> {
        SIG::read_data(decoder, record_type, length).map(Self)
    }
}

impl RecordData for RRSIG {
    fn try_from_rdata(data: RData) -> Result<Self, RData> {
        match data {
            RData::DNSSEC(DNSSECRData::RRSIG(csync)) => Ok(csync),
            _ => Err(data),
        }
    }

    fn try_borrow(data: &RData) -> Result<&Self, &RData> {
        match data {
            RData::DNSSEC(DNSSECRData::RRSIG(csync)) => Ok(csync),
            _ => Err(data),
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::RRSIG
    }

    fn into_rdata(self) -> RData {
        RData::DNSSEC(DNSSECRData::RRSIG(self))
    }
}

impl fmt::Display for RRSIG {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
    }
}
