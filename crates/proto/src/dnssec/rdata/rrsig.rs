// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! RRSIG type and related implementations

use alloc::vec::Vec;
use core::{fmt, ops::Deref};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    dnssec::Algorithm,
    error::ProtoResult,
    rr::{Name, RData, Record, RecordData, RecordDataDecodable, RecordType},
    serialize::binary::{BinDecoder, BinEncodable, BinEncoder, Restrict},
};

use super::{DNSSECRData, SIG};

/// RRSIG is really a derivation of the original SIG record data. See SIG for more documentation
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct RRSIG(SIG);

impl RRSIG {
    /// Creates a new SIG record data, used for both RRSIG and SIG(0) records.
    ///
    /// # Arguments
    ///
    /// * `type_covered` - The `RecordType` which this signature covers, should be NULL for SIG(0).
    /// * `algorithm` - The `Algorithm` used to generate the `signature`.
    /// * `num_labels` - The number of labels in the name, should be less 1 for *.name labels,
    ///                  see `Name::num_labels()`.
    /// * `original_ttl` - The TTL for the RRSet stored in the zone, should be 0 for SIG(0).
    /// * `sig_expiration` - Timestamp at which this signature is no longer valid, very important to
    ///                      keep this low, < +5 minutes to limit replay attacks.
    /// * `sig_inception` - Timestamp when this signature was generated.
    /// * `key_tag` - See the key_tag generation in `rr::dnssec::Signer::key_tag()`.
    /// * `signer_name` - Domain name of the server which was used to generate the signature.
    /// * `sig` - signature stored in this record.
    ///
    /// # Return value
    ///
    /// The new SIG record data.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        type_covered: RecordType,
        algorithm: Algorithm,
        num_labels: u8,
        original_ttl: u32,
        sig_expiration: u32,
        sig_inception: u32,
        key_tag: u16,
        signer_name: Name,
        sig: Vec<u8>,
    ) -> Self {
        Self(SIG::new(
            type_covered,
            algorithm,
            num_labels,
            original_ttl,
            sig_expiration,
            sig_inception,
            key_tag,
            signer_name,
            sig,
        ))
    }

    /// Returns the authenticated TTL of this RRSIG with a Record.
    ///
    /// ```text
    /// RFC 4035             DNSSEC Protocol Modifications            March 2005
    ///
    /// If the resolver accepts the RRset as authentic, the validator MUST
    /// set the TTL of the RRSIG RR and each RR in the authenticated RRset to
    /// a value no greater than the minimum of:
    ///
    ///   o  the RRset's TTL as received in the response;
    ///
    ///   o  the RRSIG RR's TTL as received in the response;
    ///
    ///   o  the value in the RRSIG RR's Original TTL field; and
    ///
    ///   o  the difference of the RRSIG RR's Signature Expiration time and the
    ///      current time.
    /// ```
    ///
    /// See [RFC 4035, section 5.3.3](https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.3).
    ///
    pub fn authenticated_ttl(&self, record: &Record, current_time: u32) -> u32 {
        record
            .ttl()
            .min(self.original_ttl())
            .min(self.sig_expiration().0.saturating_sub(current_time))
    }
}

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
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> ProtoResult<Self> {
        SIG::read_data(decoder, length).map(Self)
    }
}

impl RecordData for RRSIG {
    fn try_from_rdata(data: RData) -> Result<Self, RData> {
        match data {
            RData::DNSSEC(DNSSECRData::RRSIG(csync)) => Ok(csync),
            _ => Err(data),
        }
    }

    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::DNSSEC(DNSSECRData::RRSIG(csync)) => Some(csync),
            _ => None,
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
