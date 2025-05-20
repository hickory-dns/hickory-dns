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

macro_rules! name_rdata {
    ($name: ident, $rdata_policy: expr) => {
        #[doc = stringify!(new type for the RecordData of $name)]
        #[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
        #[derive(Debug, PartialEq, Eq, Hash, Clone)]
        pub struct $name(pub Name);

        impl BinEncodable for $name {
            fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
                let mut encoder = encoder.with_rdata_behavior($rdata_policy);
                self.0.emit(&mut encoder)
            }
        }

        impl<'r> BinDecodable<'r> for $name {
            fn read(decoder: &mut BinDecoder<'r>) -> ProtoResult<Self> {
                Name::read(decoder).map(Self)
            }
        }

        impl RecordData for $name {
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

name_rdata!(CNAME, RDataEncoding::StandardRecord);
name_rdata!(NS, RDataEncoding::StandardRecord);
name_rdata!(PTR, RDataEncoding::StandardRecord);
name_rdata!(ANAME, RDataEncoding::Other);

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn test_it_to_string_should_not_stack_overflow() {
        assert_eq!(PTR("abc.com".parse().unwrap()).to_string(), "abc.com");
    }
}
