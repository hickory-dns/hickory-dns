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
use crate::rr::{Name, RData, RecordType};
use crate::serialize::txt::rdata_parsers::*;

pub(crate) trait RDataParser: Sized {
    fn parse<'i, I: Iterator<Item = &'i str>>(
        record_type: RecordType,
        tokens: I,
        origin: Option<&Name>,
    ) -> ParseResult<Self>;
}

#[warn(clippy::wildcard_enum_match_arm)] // make sure all cases are handled
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
            RecordType::CSYNC => csync::parse(tokens).map(RData::CSYNC)?,
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
            RecordType::SIG => return Err(ParseError::from("parsing SIG doesn't make sense")),
            RecordType::DNSKEY => {
                return Err(ParseError::from("DNSKEY should be dynamically generated"))
            }
            RecordType::CDNSKEY => {
                return Err(ParseError::from("CDNSKEY should be dynamically generated"))
            }
            RecordType::KEY => return Err(ParseError::from("KEY should be dynamically generated")),
            RecordType::DS => return Err(ParseError::from("DS should be dynamically generated")),
            RecordType::CDS => return Err(ParseError::from("CDS should be dynamically generated")),
            RecordType::NSEC => {
                return Err(ParseError::from("NSEC should be dynamically generated"))
            }
            RecordType::NSEC3 => {
                return Err(ParseError::from("NSEC3 should be dynamically generated"))
            }
            RecordType::NSEC3PARAM => {
                return Err(ParseError::from(
                    "NSEC3PARAM should be dynamically generated",
                ))
            }
            RecordType::RRSIG => {
                return Err(ParseError::from("RRSIG should be dynamically generated"))
            }
            RecordType::TSIG => return Err(ParseError::from("TSIG is only used during AXFR")),
            RecordType::ZERO => RData::ZERO,
            r @ RecordType::Unknown(..) | r => {
                // TODO: add a way to associate generic record types to the zone
                return Err(ParseError::from(ParseErrorKind::UnsupportedRecordType(r)));
            }
        };

        Ok(rdata)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;
    use crate::rr::domain::Name;
    use crate::rr::rdata::*;
    use std::str::FromStr;

    #[test]
    fn test_a() {
        let tokens = vec!["192.168.0.1"];
        let name = Name::from_str("example.com.").unwrap();
        let record =
            RData::parse(RecordType::A, tokens.iter().map(AsRef::as_ref), Some(&name)).unwrap();

        assert_eq!(record, RData::A("192.168.0.1".parse().unwrap()));
    }

    #[test]
    fn test_aaaa() {
        let tokens = vec!["::1"];
        let name = Name::from_str("example.com.").unwrap();
        let record = RData::parse(
            RecordType::AAAA,
            tokens.iter().map(AsRef::as_ref),
            Some(&name),
        )
        .unwrap();

        assert_eq!(record, RData::AAAA("::1".parse().unwrap()));
    }

    #[test]
    fn test_csync() {
        let tokens = vec!["123", "1", "A", "NS"];
        let name = Name::from_str("example.com.").unwrap();
        let record = RData::parse(
            RecordType::CSYNC,
            tokens.iter().map(AsRef::as_ref),
            Some(&name),
        )
        .unwrap();

        assert_eq!(
            record,
            RData::CSYNC(CSYNC::new(
                123,
                true,
                false,
                vec![RecordType::A, RecordType::NS]
            ))
        );
    }

    #[test]
    fn test_any() {
        let tokens = vec!["test"];
        let name = Name::from_str("example.com.").unwrap();
        let result = RData::parse(
            RecordType::ANY,
            tokens.iter().map(AsRef::as_ref),
            Some(&name),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_dynamically_generated() {
        let dynamically_generated = vec![
            RecordType::DS,
            RecordType::CDS,
            RecordType::DNSKEY,
            RecordType::CDNSKEY,
            RecordType::KEY,
            RecordType::NSEC,
            RecordType::NSEC3,
            RecordType::NSEC3PARAM,
            RecordType::RRSIG,
        ];

        let tokens = vec!["test"];

        let name = Name::from_str("example.com.").unwrap();

        for record_type in dynamically_generated {
            let result = RData::parse(record_type, tokens.iter().map(AsRef::as_ref), Some(&name));
            assert!(result.is_err());
        }
    }
}
