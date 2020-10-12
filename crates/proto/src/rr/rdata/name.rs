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

//! Record type for all cname like records.
//!
//! A generic struct for all {*}NAME pointer RData records, CNAME, NS, and PTR. Here is the text for
//! CNAME from RFC 1035, Domain Implementation and Specification, November 1987:
//!
//! [RFC 1035, DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987](https://tools.ietf.org/html/rfc1035)
//!
//! ```text
//! 3.3.1. CNAME RDATA format
//!
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     /                     CNAME                     /
//!     /                                               /
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!
//! where:
//!
//! CNAME           A <domain-name> which specifies the canonical or primary
//!                 name for the owner.  The owner name is an alias.
//!
//! CNAME RRs cause no additional section processing, but name servers may
//! choose to restart the query at the canonical name in certain cases.  See
//! the description of name server logic in [RFC-1034] for details.
//! ```

use crate::error::*;
use crate::rr::domain::Name;
use crate::serialize::binary::*;

/// Read the RData from the given Decoder
pub fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<Name> {
    Name::read(decoder)
}

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
pub fn emit(encoder: &mut BinEncoder<'_>, name_data: &Name) -> ProtoResult<()> {
    let is_canonical_names = encoder.is_canonical_names();
    name_data.emit_with_lowercase(encoder, is_canonical_names)?;
    Ok(())
}

#[test]
pub fn test() {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    let rdata = Name::from_ascii("WWW.example.com.").unwrap();

    let mut bytes = Vec::new();
    let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
    assert!(emit(&mut encoder, &rdata).is_ok());
    let bytes = encoder.into_bytes();

    println!("bytes: {:?}", bytes);

    let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
    let read_rdata = read(&mut decoder).expect("Decoding error");
    assert_eq!(rdata, read_rdata);
}
