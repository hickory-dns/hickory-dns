/*
 * Copyright (C) 2015-2019 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! record data enum variants

use crate::error::*;
use crate::rr::rdata::DNSSECRecordType;
use crate::rr::{Name, RData, RecordType};
use crate::serialize::txt::rdata_parsers::*;

pub(crate) trait RDataParser: Sized {
    fn parse<'i, I: Iterator<Item = &'i str>>(
        record_type: RecordType,
        tokens: I,
        origin: Option<&Name>,
    ) -> ParseResult<Self>;
}

#[warn(clippy::wildcard_enum_match_arm)] // make sure all cases are handled despite of non_exhaustive
impl RDataParser for RData {
    /// Parse the RData from a set of Tokens
    fn parse<'i, I: Iterator<Item = &'i str>>(
        record_type: RecordType,
        tokens: I,
        origin: Option<&Name>,
    ) -> ParseResult<Self> {
        let rdata = match record_type {
            RecordType::A => RData::A(a::parse(tokens)?),
            RecordType::AAAA => RData::AAAA(aaaa::parse(tokens)?),
            RecordType::ANAME => RData::ANAME(name::parse(tokens, origin)?),
            RecordType::ANY => return Err(ParseError::from("parsing ANY doesn't make sense")),
            RecordType::AXFR => return Err(ParseError::from("parsing AXFR doesn't make sense")),
            RecordType::CAA => caa::parse(tokens).map(RData::CAA)?,
            RecordType::CNAME => RData::CNAME(name::parse(tokens, origin)?),
            RecordType::HINFO => RData::HINFO(hinfo::parse(tokens)?),
            RecordType::HTTPS => svcb::parse(tokens).map(RData::SVCB)?,
            RecordType::IXFR => return Err(ParseError::from("parsing IXFR doesn't make sense")),
            RecordType::MX => RData::MX(mx::parse(tokens, origin)?),
            RecordType::NAPTR => RData::NAPTR(naptr::parse(tokens, origin)?),
            RecordType::NULL => RData::NULL(null::parse(tokens)?),
            RecordType::NS => RData::NS(name::parse(tokens, origin)?),
            RecordType::OPENPGPKEY => RData::OPENPGPKEY(openpgpkey::parse(tokens)?),
            RecordType::OPT => return Err(ParseError::from("parsing OPT doesn't make sense")),
            RecordType::PTR => RData::PTR(name::parse(tokens, origin)?),
            RecordType::SOA => RData::SOA(soa::parse(tokens, origin)?),
            RecordType::SRV => RData::SRV(srv::parse(tokens, origin)?),
            RecordType::SSHFP => RData::SSHFP(sshfp::parse(tokens)?),
            RecordType::SVCB => svcb::parse(tokens).map(RData::SVCB)?,
            RecordType::TLSA => RData::TLSA(tlsa::parse(tokens)?),
            RecordType::TXT => RData::TXT(txt::parse(tokens)?),
            RecordType::DNSSEC(DNSSECRecordType::SIG) => {
                return Err(ParseError::from("parsing SIG doesn't make sense"))
            }
            RecordType::DNSSEC(DNSSECRecordType::DNSKEY) => {
                return Err(ParseError::from("DNSKEY should be dynamically generated"))
            }
            RecordType::DNSSEC(DNSSECRecordType::KEY) => {
                return Err(ParseError::from("KEY should be dynamically generated"))
            }
            RecordType::DNSSEC(DNSSECRecordType::DS) => {
                return Err(ParseError::from("DS should be dynamically generated"))
            }
            RecordType::DNSSEC(DNSSECRecordType::NSEC) => {
                return Err(ParseError::from("NSEC should be dynamically generated"))
            }
            RecordType::DNSSEC(DNSSECRecordType::NSEC3) => {
                return Err(ParseError::from("NSEC3 should be dynamically generated"))
            }
            RecordType::DNSSEC(DNSSECRecordType::NSEC3PARAM) => {
                return Err(ParseError::from(
                    "NSEC3PARAM should be dynamically generated",
                ))
            }
            RecordType::DNSSEC(DNSSECRecordType::RRSIG) => {
                return Err(ParseError::from("RRSIG should be dynamically generated"))
            }
            RecordType::DNSSEC(DNSSECRecordType::Unknown(code)) => {
                return Err(ParseError::from(ParseErrorKind::UnknownRecordType(code)))
            }
            RecordType::Unknown(code) => {
                // TODO: add a way to associate generic record types to the zone
                return Err(ParseError::from(ParseErrorKind::UnknownRecordType(code)));
            }
            RecordType::ZERO => RData::ZERO,
            r @ trust_dns_proto::rr::RecordType::DNSSEC(..) | r => {
                return Err(ParseError::from(ParseErrorKind::UnknownRecordType(
                    u16::from(r),
                )))
            }
        };

        Ok(rdata)
    }
}
