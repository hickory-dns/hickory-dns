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
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod error;
#[cfg(all(test, feature = "metrics"))]
mod metrics_tests;
mod recursor;
mod recursor_dns_handle;
pub(crate) mod recursor_pool;

use std::net::IpAddr;

#[cfg(feature = "__dnssec")]
use std::sync::Arc;

pub use error::{Error, ErrorKind};
pub use hickory_proto as proto;
pub use hickory_resolver as resolver;
pub use hickory_resolver::config::NameServerConfig;
#[cfg(feature = "__dnssec")]
use proto::dnssec::TrustAnchors;
use proto::{
    op::{Message, Query},
    rr::Record,
};
pub use recursor::{Recursor, RecursorBuilder};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::PrefixSet;
use resolver::Name;
use tracing::{debug, warn};

/// `Recursor`'s DNSSEC policy
// `Copy` can only be implemented when `dnssec` is disabled we don't want to remove a trait
// implementation when a feature is enabled as features are meant to be additive
#[allow(missing_copy_implementations)]
#[derive(Clone)]
pub enum DnssecPolicy {
    /// security unaware; DNSSEC records will not be requested nor processed
    SecurityUnaware,

    /// DNSSEC validation is disabled; DNSSEC records will be requested and processed
    #[cfg(feature = "__dnssec")]
    ValidationDisabled,

    /// DNSSEC validation is enabled and will use the chosen `trust_anchor` set of keys
    #[cfg(feature = "__dnssec")]
    ValidateWithStaticKey {
        /// set to `None` to use built-in trust anchor
        trust_anchor: Option<Arc<TrustAnchors>>,
        /// NSEC3 soft iteration limit.  Responses with NSEC3 records having an iteration count
        /// exceeding this value, but less than the hard limit, will return Proof::Insecure
        nsec3_soft_iteration_limit: Option<u16>,
        /// NSEC3 hard iteration limit.  Responses with NSEC3 responses having an iteration count
        /// exceeding this value will return Proof::Bogus
        nsec3_hard_iteration_limit: Option<u16>,
    },
    // TODO RFC5011
    // ValidateWithInitialKey { ..  },}
}

impl DnssecPolicy {
    pub(crate) fn is_security_aware(&self) -> bool {
        !matches!(self, Self::SecurityUnaware)
    }
}

/// An IPv4/IPv6 access control set.  This mainly hides the complexity of supporting v4 and v6
/// addresses concurrently in a given set.  The AccessControlSet differs from a typical Access
/// Control List in that there is no order.  The access semantics are:
///
/// +-----------------------+----------------------+----------+
/// | Present in allow list | Present in deny list |  Result  |
/// +-----------------------+----------------------+----------+
/// |                  true |                false |  allowed |
/// |                  true |                 true |  allowed |
/// |                 false |                false |  allowed |
/// |                 false |                 true |   denied |
/// +-----------------------+----------------------+----------+
#[derive(Clone)]
pub(crate) struct AccessControlSet {
    v4_allow: PrefixSet<Ipv4Net>,
    v4_deny: PrefixSet<Ipv4Net>,
    v6_allow: PrefixSet<Ipv6Net>,
    v6_deny: PrefixSet<Ipv6Net>,
}

impl AccessControlSet {
    pub(crate) fn new(name: &'static str, allow: &[IpNet], deny: &[IpNet]) -> Self {
        let mut v4_allow = PrefixSet::new();
        let mut v4_deny = PrefixSet::new();
        let mut v6_allow = PrefixSet::new();
        let mut v6_deny = PrefixSet::new();

        for network in allow {
            debug!("adding {network} to the {name} list");
            match network {
                IpNet::V4(network) => {
                    v4_allow.insert(*network);
                }
                IpNet::V6(network) => {
                    v6_allow.insert(*network);
                }
            }
        }

        for network in deny {
            debug!("adding {network} to the {name} list");
            match network {
                IpNet::V4(network) => {
                    v4_deny.insert(*network);
                }
                IpNet::V6(network) => {
                    v6_deny.insert(*network);
                }
            }
        }

        Self {
            v4_allow,
            v4_deny,
            v6_allow,
            v6_deny,
        }
    }

    pub(crate) fn denied(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                self.v4_allow.get_spm(&ip.into()).is_none()
                    && self.v4_deny.get_spm(&ip.into()).is_some()
            }
            IpAddr::V6(ip) => {
                self.v6_allow.get_spm(&ip.into()).is_none()
                    && self.v6_deny.get_spm(&ip.into()).is_some()
            }
        }
    }
}

// as per section 3.2.1 of RFC4035
fn maybe_strip_dnssec_records(
    query_has_dnssec_ok: bool,
    mut response: Message,
    query: Query,
) -> Message {
    if query_has_dnssec_ok {
        return response;
    }

    let predicate = |record: &Record| {
        let record_type = record.record_type();
        record_type == query.query_type() || !record_type.is_dnssec()
    };

    response.answers_mut().retain(predicate);
    response.authorities_mut().retain(predicate);
    response.additionals_mut().retain(predicate);

    response
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
///   false.
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
