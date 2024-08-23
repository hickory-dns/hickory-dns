// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! A recursive DNS resolver based on the Hickory DNS (stub) resolver

#![warn(
    clippy::default_trait_access,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::unimplemented,
    missing_copy_implementations,
    missing_docs,
    non_snake_case,
    non_upper_case_globals,
    rust_2018_idioms,
    unreachable_pub
)]
#![allow(
    clippy::single_component_path_imports,
    clippy::upper_case_acronyms, // can be removed on a major release boundary
)]
#![recursion_limit = "2048"]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod error;
mod recursor;
mod recursor_dns_handle;
pub(crate) mod recursor_pool;

#[cfg(feature = "dnssec")]
use std::sync::Arc;
use std::time::Instant;

pub use error::{Error, ErrorKind};
pub use hickory_proto as proto;
pub use hickory_resolver as resolver;
pub use hickory_resolver::config::{NameServerConfig, NameServerConfigGroup};
#[cfg(feature = "dnssec")]
use proto::rr::dnssec::TrustAnchor;

use proto::{op::Query, xfer::DnsResponse};
pub use recursor::{Recursor, RecursorBuilder};
use resolver::{dns_lru::DnsLru, lookup::Lookup, Name};
use tracing::{info, warn};

/// `Recursor`'s DNSSEC policy
// `Copy` can only be implemented when `dnssec` is disabled we don't want to remove a trait
// implementation when a feature is enabled as features are meant to be additive
#[allow(missing_copy_implementations)]
#[derive(Clone)]
pub enum DnssecPolicy {
    /// security unaware; DNSSEC records will not be requested nor processed
    SecurityUnaware,

    /// DNSSEC validation is disabled; DNSSEC records will be requested and processed
    #[cfg(feature = "dnssec")]
    ValidationDisabled,

    /// DNSSEC validation is enabled and will use the chosen `trust_anchor` set of keys
    #[cfg(feature = "dnssec")]
    ValidateWithStaticKey {
        /// set to `None` to use built-in trust anchor
        trust_anchor: Option<Arc<TrustAnchor>>,
    },
    // TODO RFC5011
    // ValidateWithInitialKey { ..  },}
}

impl DnssecPolicy {
    pub(crate) fn is_security_aware(&self) -> bool {
        !matches!(self, Self::SecurityUnaware)
    }
}

/// caches the `response` to `query` in `record_cache`
///
/// `now` indicates when the `response` was obtained
///
/// if `zone` is present, records in `response` that do not belong to `zone` will be discarded
fn cache_response(
    response: DnsResponse,
    zone: Option<&Name>,
    record_cache: &DnsLru,
    query: Query,
    now: Instant,
) -> Result<Lookup, Error> {
    let mut response = response.into_message();
    info!("response: {}", response.header());

    let records = response
        .take_answers()
        .into_iter()
        .chain(response.take_name_servers())
        .chain(response.take_additionals())
        .filter(|x| {
            if let Some(zone) = zone {
                if !is_subzone(zone, x.name()) {
                    warn!("Dropping out of bailiwick record {x} for zone {}", zone);
                    false
                } else {
                    true
                }
            } else {
                true
            }
        });

    let lookup = record_cache.insert_records(query, records, now);

    lookup.ok_or_else(|| Error::from("no records found"))
}

// as per section 3.2.1 of RFC4035
fn maybe_strip_dnssec_records(query_has_dnssec_ok: bool, lookup: Lookup, query: Query) -> Lookup {
    if query_has_dnssec_ok {
        return lookup;
    }

    let records = lookup
        .records()
        .iter()
        .filter(|rrset| {
            let record_type = rrset.record_type();
            record_type == query.query_type() || !record_type.is_dnssec()
        })
        .cloned()
        .collect();

    Lookup::new_with_deadline(query, records, lookup.valid_until())
}

/// Bailiwick/sub zone checking.
///
/// # Overview
///
/// This function checks that two host names have a parent/child relationship, but does so more strictly than elsewhere in the libraries
/// (see implementation notes.)
///
/// A resolver should not return answers outside of its delegated authority -- if we receive a delegation from the root servers for
/// "example.com", that server should only return answers related to example.com or a sub-domain thereof.  Note that record data may point
/// to out-of-bailwick records (e.g., example.com could return a CNAME record for www.example.com that points to example.cdnprovider.net,)
/// but it should not return a record name that is out-of-bailiwick (e.g., we ask for www.example.com and it returns www.otherdomain.com.)
///
/// Out-of-bailiwick responses have been used in cache poisoning attacks.
///
/// ## Examples
///
/// | Parent       | Child                | Expected Result                                                  |
/// |--------------|----------------------|------------------------------------------------------------------|
/// | .            | com.                 | In-bailiwick (true)                                              |
/// | com.         | example.net.         | Out-of-bailiwick (false)                                         |
/// | example.com. | www.example.com.     | In-bailiwick (true)                                              |
/// | example.com. | www.otherdomain.com. | Out-of-bailiwick (false)                                         |
/// | example.com  | www.example.com.     | Out-of-bailiwick (false, note the parent is not fully qualified) |
///
/// # Implementation Notes
///
/// * This function is nominally a wrapper around Name::zone_of, with two additional checks:
/// * If the caller doesn't provide a parent at all, we'll return false.
/// * If the domains have mixed qualification -- that is, if one is fully-qualified and the other partially-qualified, we'll return
///    false.
///
/// # References
///
/// * [RFC 8499](https://datatracker.ietf.org/doc/html/rfc8499) -- DNS Terminology (see page 25)
/// * [The Hitchiker's Guide to DNS Cache Poisoning](https://www.cs.utexas.edu/%7Eshmat/shmat_securecomm10.pdf) -- for a more in-depth
///   discussion of DNS cache poisoning attacks, see section 4, specifically, for a discussion of the Bailiwick rule.
fn is_subzone(parent: &Name, child: &Name) -> bool {
    if parent.is_empty() {
        return false;
    }

    if (parent.is_fqdn() && !child.is_fqdn()) || (!parent.is_fqdn() && child.is_fqdn()) {
        return false;
    }

    parent.zone_of(child)
}

#[test]
fn is_subzone_test() {
    use core::str::FromStr;

    assert!(is_subzone(
        &Name::from_str(".").unwrap(),
        &Name::from_str("com.").unwrap(),
    ));
    assert!(is_subzone(
        &Name::from_str("com.").unwrap(),
        &Name::from_str("example.com.").unwrap(),
    ));
    assert!(is_subzone(
        &Name::from_str("example.com.").unwrap(),
        &Name::from_str("host.example.com.").unwrap(),
    ));
    assert!(is_subzone(
        &Name::from_str("example.com.").unwrap(),
        &Name::from_str("host.multilevel.example.com.").unwrap(),
    ));
    assert!(!is_subzone(
        &Name::from_str("").unwrap(),
        &Name::from_str("example.com.").unwrap(),
    ));
    assert!(!is_subzone(
        &Name::from_str("com.").unwrap(),
        &Name::from_str("example.net.").unwrap(),
    ));
    assert!(!is_subzone(
        &Name::from_str("example.com.").unwrap(),
        &Name::from_str("otherdomain.com.").unwrap(),
    ));
    assert!(!is_subzone(
        &Name::from_str("com").unwrap(),
        &Name::from_str("example.com.").unwrap(),
    ));
}
