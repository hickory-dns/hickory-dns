// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Object-safe authority and lookup traits

#[cfg(feature = "__dnssec")]
use crate::proto::dnssec::Proof;
use crate::proto::rr::Record;

/// DNSSEC status of an answer
#[derive(Clone, Copy, Debug)]
pub enum DnssecSummary {
    /// All records have been DNSSEC validated
    Secure,
    /// At least one record is in the Bogus state
    Bogus,
    /// Insecure / Indeterminate (e.g. "Island of security")
    Insecure,
}

impl DnssecSummary {
    /// Whether the records have been DNSSEC validated or not
    #[cfg(feature = "__dnssec")]
    pub fn from_records<'a>(records: impl Iterator<Item = &'a Record>) -> Self {
        let mut all_secure = None;
        for record in records {
            match record.proof() {
                Proof::Secure => {
                    all_secure.get_or_insert(true);
                }
                Proof::Bogus => return Self::Bogus,
                _ => all_secure = Some(false),
            }
        }

        if all_secure.unwrap_or(false) {
            Self::Secure
        } else {
            Self::Insecure
        }
    }

    /// Whether the records have been DNSSEC validated or not
    #[cfg(not(feature = "__dnssec"))]
    fn from_records<'a>(_: impl Iterator<Item = &'a Record>) -> Self {
        Self::Insecure
    }
}
