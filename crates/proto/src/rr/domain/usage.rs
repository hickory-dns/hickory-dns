// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Reserved zone names.
//!
//! see [Special-Use Domain Names](https://tools.ietf.org/html/rfc6761), RFC 6761 February, 2013

use core::iter;

use crate::rr::domain::Name;

/// Returns true if `name` falls within `localhost.`
///
/// [Special-Use Domain Names](https://tools.ietf.org/html/rfc6761), RFC 6761 February, 2013
///
/// ```text
/// 6.3.  Domain Name Reservation Considerations for "localhost."
///
///    The domain "localhost." and any names falling within ".localhost."
///    are special in the following ways:
/// ```
pub(super) fn is_localhost(name: &Name) -> bool {
    in_zone(name, ["localhost"])
}

/// Returns true if `name` falls within `127.in-addr.arpa.`
///
/// 127/8 is reserved for loopback.
pub(super) fn is_in_addr_arpa_127(name: &Name) -> bool {
    in_zone(name, ["arpa", "in-addr", "127"])
}

/// Returns true if `name` falls within `1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.`
///
/// `::1/128` is the only address in ipv6 loopback, so names in this zone should be treated
/// like [`is_localhost()`] names.
pub(super) fn is_ip6_arpa_loopback(name: &Name) -> bool {
    in_zone(
        name,
        ["arpa", "ip6"]
            .into_iter()
            .chain(iter::repeat_n("0", 31))
            .chain(["1"]),
    )
}

/// Returns true if `name` falls within `local.`
///
/// [Multicast DNS](https://tools.ietf.org/html/rfc6762), RFC 6762  February 2013
///
/// ```text
/// This document specifies that the DNS top-level domain ".local." is a
///   special domain with special semantics, namely that any fully
///   qualified name ending in ".local." is link-local, and names within
///   this domain are meaningful only on the link where they originate.
///   This is analogous to IPv4 addresses in the 169.254/16 prefix or IPv6
///   addresses in the FE80::/10 prefix, which are link-local and
///   meaningful only on the link where they originate.
/// ```
pub(super) fn is_local(name: &Name) -> bool {
    in_zone(name, ["local"])
}

// RFC 6762                      Multicast DNS                February 2013

/// Returns true if `name` falls within `invalid.`
///
/// [Special-Use Domain Names](https://tools.ietf.org/html/rfc6761), RFC 6761 February, 2013
///
/// ```text
/// 6.4.  Domain Name Reservation Considerations for "invalid."
///
///    The domain "invalid." and any names falling within ".invalid." are
///    special in the ways listed below.  In the text below, the term
///    "invalid" is used in quotes to signify such names, as opposed to
///    names that may be invalid for other reasons (e.g., being too long).
/// ```
pub(super) fn is_invalid(name: &Name) -> bool {
    in_zone(name, ["invalid"])
}

/// Returns true if `name` falls within `onion.`
///
/// [The ".onion" Special-Use Domain Name](https://tools.ietf.org/html/rfc7686), RFC 7686 October, 2015
///
/// ```text
/// 1.  Introduction
///
///   The Tor network has the ability to host network
///   services using the ".onion" Special-Use Top-Level Domain Name.  Such
///   names can be used as other domain names would be (e.g., in URLs
///   [RFC3986]), but instead of using the DNS infrastructure, .onion names
///   functionally correspond to the identity of a given service, thereby
///   combining location and authentication.
/// ```
pub fn is_onion(name: &Name) -> bool {
    in_zone(name, ["onion"])
}

/// Returns true if the trailing labels of `name` match `zone` (given from the root down)
fn in_zone(name: &Name, zone: impl IntoIterator<Item = &'static str>) -> bool {
    let mut labels = name.iter().rev();
    zone.into_iter().all(|expected| {
        labels
            .next()
            .is_some_and(|label| label.eq_ignore_ascii_case(expected.as_bytes()))
    })
}

/// Name Resolution APIs and Libraries:
///
///   Are writers of name resolution APIs and libraries expected to
///   make their software recognize these names as special and treat
///   them differently?  If so, how?
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ResolverUsage {
    /// Name resolution APIs and libraries SHOULD NOT recognize these
    /// names as special and SHOULD NOT treat them differently.  Name
    /// resolution APIs SHOULD send queries for these names to their
    /// configured caching DNS server(s).
    ///
    /// Name resolution APIs and libraries SHOULD NOT recognize test
    /// names as special and SHOULD NOT treat them differently.  Name
    /// resolution APIs SHOULD send queries for test names to their
    /// configured caching DNS server(s).
    ///
    /// Name resolution APIs and libraries SHOULD NOT recognize example
    /// names as special and SHOULD NOT treat them differently.  Name
    /// resolution APIs SHOULD send queries for example names to their
    /// configured caching DNS server(s).
    Normal,

    /// Name resolution APIs and libraries SHOULD recognize localhost
    /// names as special and SHOULD always return the IP loopback address
    /// for address queries and negative responses for all other query
    /// types.  Name resolution APIs SHOULD NOT send queries for
    /// localhost names to their configured caching DNS server(s).
    Loopback,

    /// Link local, generally for mDNS
    ///
    /// Any DNS query for a name ending with ".local." MUST be sent to the
    /// mDNS IPv4 link-local multicast address 224.0.0.251 (or its IPv6
    /// equivalent FF02::FB).  The design rationale for using a fixed
    /// multicast address instead of selecting from a range of multicast
    /// addresses using a hash function is discussed in Appendix B.
    /// Implementers MAY choose to look up such names concurrently via other
    /// mechanisms (e.g., Unicast DNS) and coalesce the results in some
    /// fashion.  Implementers choosing to do this should be aware of the
    /// potential for user confusion when a given name can produce different
    /// results depending on external network conditions (such as, but not
    /// limited to, which name lookup mechanism responds faster).
    LinkLocal,

    /// Name resolution APIs and libraries SHOULD recognize "invalid"
    /// names as special and SHOULD always return immediate negative
    /// responses.  Name resolution APIs SHOULD NOT send queries for
    /// "invalid" names to their configured caching DNS server(s).
    NxDomain,
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn single_label_zones() {
        for (predicate, zone) in [
            (is_localhost as fn(&Name) -> bool, "localhost"),
            (is_local, "local"),
            (is_invalid, "invalid"),
            (is_onion, "onion"),
        ] {
            for name in [
                zone.to_string(),
                format!("{zone}."),
                zone.to_ascii_uppercase(),
                format!("foo.{zone}."),
            ] {
                assert!(predicate(&Name::from_ascii(&name).unwrap()), "{name}");
            }

            for name in [
                ".".to_string(),
                "example.".to_string(),
                format!("{zone}.example."),
                format!("{zone}x."),
            ] {
                assert!(!predicate(&Name::from_ascii(&name).unwrap()), "{name}");
            }
        }
    }

    #[test]
    fn in_addr_arpa_127() {
        for name in ["127.in-addr.arpa.", "1.0.0.127.IN-ADDR.ARPA."] {
            assert!(
                is_in_addr_arpa_127(&Name::from_ascii(name).unwrap()),
                "{name}"
            );
        }

        for name in [
            "in-addr.arpa.",
            "128.in-addr.arpa.",
            "1.0.0.127.in-addr.example.",
        ] {
            assert!(
                !is_in_addr_arpa_127(&Name::from_ascii(name).unwrap()),
                "{name}"
            );
        }
    }

    #[test]
    fn ip6_arpa_loopback() {
        let loopback = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa";
        for name in [
            loopback.to_string(),
            format!("{loopback}."),
            loopback.to_ascii_uppercase(),
            format!("foo.{loopback}."),
        ] {
            assert!(
                is_ip6_arpa_loopback(&Name::from_ascii(&name).unwrap()),
                "{name}"
            );
        }

        for name in [
            ".",
            "arpa.",
            "ip6.arpa.",
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
            "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.example.",
            "1.127.in-addr.arpa.",
        ] {
            assert!(
                !is_ip6_arpa_loopback(&Name::from_ascii(name).unwrap()),
                "{name}"
            );
        }
    }
}
