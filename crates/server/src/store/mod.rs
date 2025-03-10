// Copyright 2015-2018 Benjamin Fry <benjaminfry -@- me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! All persistent store implementations

pub mod blocklist;
pub mod file;
pub mod forwarder;
pub mod in_memory;
pub mod recursor;
#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(all(feature = "__dnssec", any(feature = "resolver", feature = "recursor")))]
use std::{fs, path::Path};

#[cfg(all(feature = "__dnssec", any(feature = "resolver", feature = "recursor")))]
use crate::proto::{
    dnssec::{TrustAnchor, Verifier},
    serialize::txt::trust_anchor::{self, Entry},
};

#[cfg(all(feature = "__dnssec", any(feature = "resolver", feature = "recursor")))]
fn read_trust_anchor(path: &Path) -> Result<TrustAnchor, String> {
    let contents = fs::read_to_string(path).map_err(|e| e.to_string())?;

    parse_trust_anchor(&contents)
}

#[cfg(all(feature = "__dnssec", any(feature = "resolver", feature = "recursor")))]
fn parse_trust_anchor(input: &str) -> Result<TrustAnchor, String> {
    let parser = trust_anchor::Parser::new(input);
    let entries = parser.parse().map_err(|e| e.to_string())?;

    let mut trust_anchor = TrustAnchor::new();
    for entry in entries {
        if let Entry::DNSKEY(record) = entry {
            let dnskey = record.data();
            // XXX should we filter based on `dnskey.flags()`?
            let key = dnskey.key().map_err(|e| e.to_string())?;
            trust_anchor.insert_trust_anchor(&*key);
        }
    }

    Ok(trust_anchor)
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "__dnssec", any(feature = "resolver", feature = "recursor")))]
    use crate::store::parse_trust_anchor;

    #[cfg(all(feature = "__dnssec", any(feature = "resolver", feature = "recursor")))]
    #[test]
    fn can_load_trust_anchor_file() {
        let input = include_str!("../../../proto/tests/test-data/root.key");

        let trust_anchor = parse_trust_anchor(input).unwrap();
        assert_eq!(3, trust_anchor.len());
    }
}
