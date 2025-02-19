// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

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

use core::{fmt, ops::Deref};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    error::ProtoResult,
    rr::{RData, RecordData, RecordType, domain::Name},
    serialize::binary::*,
};

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

    // to_lowercase for rfc4034 and rfc6840
    name_data.emit_with_lowercase(encoder, is_canonical_names)?;
    Ok(())
}

macro_rules! name_rdata {
    ($name: ident) => {
        #[doc = stringify!(new type for the RecordData of $name)]
        #[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
        #[derive(Debug, PartialEq, Eq, Hash, Clone)]
        pub struct $name(pub Name);

        impl BinEncodable for $name {
            fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
                emit(encoder, &self.0)
            }
        }

        impl<'r> BinDecodable<'r> for $name {
            fn read(decoder: &mut BinDecoder<'r>) -> ProtoResult<Self> {
                Name::read(decoder).map(Self)
            }
        }

        impl RecordData for $name {
            fn try_from_rdata(data: RData) -> Result<Self, RData> {
                match data {
                    RData::$name(data) => Ok(data),
                    _ => Err(data),
                }
            }

            fn try_borrow(data: &RData) -> Option<&Self> {
                match data {
                    RData::$name(data) => Some(data),
                    _ => None,
                }
            }

            fn record_type(&self) -> RecordType {
                RecordType::$name
            }

            fn into_rdata(self) -> RData {
                RData::$name(self)
            }
        }

        impl Deref for $name {
            type Target = Name;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(f, "{}", self.0)
            }
        }
    };
}

name_rdata!(CNAME);
name_rdata!(NS);
name_rdata!(PTR);
name_rdata!(ANAME);

#[cfg(test)]
mod tests {

    use alloc::{string::ToString, vec::Vec};
    use std::println;

    use super::*;

    #[test]
    fn test_it_to_string_should_not_stack_overflow() {
        assert_eq!(PTR("abc.com".parse().unwrap()).to_string(), "abc.com");
    }

    #[test]
    fn test() {
        #![allow(clippy::dbg_macro, clippy::print_stdout)]

        let rdata = Name::from_ascii("WWW.example.com.").unwrap();

        let mut bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut bytes);
        assert!(emit(&mut encoder, &rdata).is_ok());
        let bytes = encoder.into_bytes();

        println!("bytes: {bytes:?}");

        let mut decoder = BinDecoder::new(bytes);
        let read_rdata = read(&mut decoder).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }
}
