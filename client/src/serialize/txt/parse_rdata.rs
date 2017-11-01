/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
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

use error::*;
use rr::{Name, RData, RecordType};
use rr::rdata::DNSSECRecordType;
use serialize::txt::Token;
use serialize::txt::rdata_parsers::*;

pub trait RDataParser: Sized {
    fn parse(
        record_type: RecordType,
        tokens: &Vec<Token>,
        origin: Option<&Name>,
    ) -> ParseResult<Self>;
}

impl RDataParser for RData {
    /// Parse the RData from a set of Tokens
    fn parse(
        record_type: RecordType,
        tokens: &Vec<Token>,
        origin: Option<&Name>,
    ) -> ParseResult<Self> {
        let rdata = match record_type {
            RecordType::A => RData::A(a::parse(tokens)?),
            RecordType::AAAA => RData::AAAA(aaaa::parse(tokens)?),
            RecordType::ANY => panic!("parsing ANY doesn't make sense"), // valid panic, never should happen
            RecordType::AXFR => panic!("parsing AXFR doesn't make sense"), // valid panic, never should happen
            RecordType::CAA => caa::parse(tokens, origin).map(RData::CAA)?,
            RecordType::CNAME => RData::CNAME(name::parse(tokens, origin)?),
            RecordType::IXFR => panic!("parsing IXFR doesn't make sense"), // valid panic, never should happen
            RecordType::MX => RData::MX(mx::parse(tokens, origin)?),
            RecordType::NULL => RData::NULL(null::parse(tokens)?),
            RecordType::NS => RData::NS(name::parse(tokens, origin)?),
            RecordType::OPT => panic!("parsing OPT doesn't make sense"), // valid panic, never should happen
            RecordType::PTR => RData::PTR(name::parse(tokens, origin)?),
            RecordType::SOA => RData::SOA(soa::parse(tokens, origin)?),
            RecordType::SRV => RData::SRV(srv::parse(tokens, origin)?),
            RecordType::TXT => RData::TXT(txt::parse(tokens)?),
            RecordType::DNSSEC(DNSSECRecordType::SIG) => panic!("parsing SIG doesn't make sense"), // valid panic, never should happen
            RecordType::DNSSEC(DNSSECRecordType::DNSKEY) => panic!("DNSKEY should be dynamically generated"), // valid panic, never should happen
            RecordType::DNSSEC(DNSSECRecordType::KEY) => panic!("KEY should be dynamically generated"), // valid panic, never should happen
            RecordType::DNSSEC(DNSSECRecordType::DS) => panic!("DS should be dynamically generated"), // valid panic, never should happen
            RecordType::DNSSEC(DNSSECRecordType::NSEC) => panic!("NSEC should be dynamically generated"), // valid panic, never should happen
            RecordType::DNSSEC(DNSSECRecordType::NSEC3) => panic!("NSEC3 should be dynamically generated"), // valid panic, never should happen
            RecordType::DNSSEC(DNSSECRecordType::NSEC3PARAM) => panic!("NSEC3PARAM should be dynamically generated"), // valid panic, never should happen
            RecordType::DNSSEC(DNSSECRecordType::RRSIG) => panic!("RRSIG should be dynamically generated"), // valid panic, never should happen

        };

        Ok(rdata)
    }
}
