// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! RRSIG type and related implementations

use core::{fmt, ops::Deref};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{DNSSECRData, SIG, sig::SigInput};
use crate::{
    ProtoError,
    dnssec::{SigSigner, TBS},
    error::ProtoResult,
    rr::{DNSClass, RData, Record, RecordData, RecordDataDecodable, RecordSet, RecordType},
    serialize::binary::{BinDecoder, BinEncodable, BinEncoder, Restrict},
};

/// RRSIG is really a derivation of the original SIG record data. See SIG for more documentation
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct RRSIG(pub(super) SIG);

impl RRSIG {
    /// Creates a new RRSIG record data from the given record set and signer.
    pub fn from_rrset(
        rr_set: &RecordSet,
        zone_class: DNSClass,
        inception: OffsetDateTime,
        signer: &SigSigner,
    ) -> Result<Self, ProtoError> {
        let expiration = inception + signer.sig_duration();
        let input = SigInput::from_rrset(rr_set, expiration, inception, signer)?;
        let tbs = TBS::from_input(
            rr_set.name(),
            zone_class,
            &input,
            rr_set.records_without_rrsigs(),
        )?;

        let sig = signer.sign(&tbs)?;
        Ok(Self(SIG { input, sig }))
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
            .min(self.input.original_ttl)
            .min(self.input.sig_expiration.0.saturating_sub(current_time))
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

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;

    use super::*;
    use crate::{
        dnssec::{
            Algorithm,
            rdata::{DNSSECRData, RRSIG, sig::SigInput},
        },
        rr::{Name, SerialNumber},
    };

    #[test]
    fn test_get_filter() {
        let name = Name::root();
        const ALGORITHMS: [Algorithm; 4] = [
            Algorithm::RSASHA256,
            Algorithm::ECDSAP256SHA256,
            Algorithm::ECDSAP384SHA384,
            Algorithm::ED25519,
        ];

        let mut a = Record::from_rdata(
            name.clone(),
            3600,
            RData::A(Ipv4Addr::new(93, 184, 216, 24).into()),
        );
        a.set_dns_class(DNSClass::IN);
        let mut rrset = RecordSet::from(a);

        for algorithm in ALGORITHMS {
            let input = SigInput {
                type_covered: RecordType::A,
                algorithm,
                num_labels: 0,
                original_ttl: 0,
                sig_expiration: SerialNumber(0),
                sig_inception: SerialNumber(0),
                key_tag: 0,
                signer_name: Name::root(),
            };

            let rrsig = RRSIG(SIG { input, sig: vec![] });
            let mut rrsig_record =
                Record::from_rdata(name.clone(), 3600, RData::DNSSEC(DNSSECRData::RRSIG(rrsig)));
            rrsig_record.set_dns_class(DNSClass::IN);
            rrset.insert_rrsig(rrsig_record);
        }

        assert!(rrset.records_with_rrsigs().any(|r| {
            if let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = r.data() {
                sig.input.algorithm == Algorithm::ED25519
            } else {
                false
            }
        },));

        assert!(rrset.records_with_rrsigs().any(|r| {
            if let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = r.data() {
                sig.input.algorithm == Algorithm::ECDSAP384SHA384
            } else {
                false
            }
        }));

        assert!(rrset.records_with_rrsigs().any(|r| {
            if let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = r.data() {
                sig.input.algorithm == Algorithm::ED25519
            } else {
                false
            }
        }));
    }
}
