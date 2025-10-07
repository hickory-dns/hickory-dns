//! SMIMEA records for storing S/MIME certificate validation information

use alloc::vec::Vec;
use core::{fmt, ops::Deref};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::tlsa::{CertUsage, Matching, Selector, TLSA};
use crate::{
    error::ProtoResult,
    rr::{RData, RecordData, RecordDataDecodable, RecordType},
    serialize::binary::{BinDecoder, BinEncodable, BinEncoder, Restrict},
};

/// [RFC 8162](https://datatracker.ietf.org/doc/html/rfc8162#section-2)
///
/// > The SMIMEA wire format and presentation format are the same as for
/// > the [TLSA] record
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SMIMEA(TLSA);

impl SMIMEA {
    /// Construct a new SMIMEA
    ///
    /// [RFC 8162](https://datatracker.ietf.org/doc/html/rfc8162#section-2)
    ///
    /// ```text
    /// 2.  The SMIMEA Resource Record
    ///
    ///    The SMIMEA DNS resource record (RR) is used to associate an end
    ///    entity certificate or public key with the associated email address,
    ///    thus forming a "SMIMEA certificate association".  The semantics of
    ///    how the SMIMEA resource record is interpreted are given later in this
    ///    document.  Note that the information returned in the SMIMEA record
    ///    might be for the end entity certificate, or it might be for the trust
    ///    anchor or an intermediate certificate.  This mechanism is similar to
    ///    the one given in [RFC7929] for OpenPGP.
    ///
    ///    The type value for the SMIMEA RRtype is defined in Section 8.  The
    ///    SMIMEA resource record is class independent.
    /// ```
    pub fn new(
        cert_usage: CertUsage,
        selector: Selector,
        matching: Matching,
        cert_data: Vec<u8>,
    ) -> Self {
        Self(TLSA::new(cert_usage, selector, matching, cert_data))
    }
}

/// This implementation allows calling the associated functions of [TLSA] on [SMIMEA].
/// Since they contain exactly the same data, duplicating them would be pointless.
impl Deref for SMIMEA {
    type Target = TLSA;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl BinEncodable for SMIMEA {
    #[inline]
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        BinEncodable::emit(&self.0, encoder)
    }
}

impl RecordDataDecodable<'_> for SMIMEA {
    #[inline]
    fn read_data(decoder: &mut BinDecoder<'_>, length: Restrict<u16>) -> ProtoResult<Self> {
        TLSA::read_data(decoder, length).map(Self)
    }
}

impl RecordData for SMIMEA {
    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::SMIMEA(data) => Some(data),
            _ => None,
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::SMIMEA
    }

    fn into_rdata(self) -> RData {
        RData::SMIMEA(self)
    }
}

impl fmt::Display for SMIMEA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fmt::Display::fmt(&self.0, f)
    }
}
