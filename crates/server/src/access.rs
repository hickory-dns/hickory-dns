use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::{Prefix, PrefixSet};

/// Type to evaluate access from a source address for accessing the server.
///
/// Two modes are available:
///
/// **Default (carve-out) mode** — preserved for backwards compatibility.
/// Allowed networks override denied networks: if a network is allowed,
/// the deny rules will not be evaluated. Allowed networks are processed
/// in the context of denied networks, that is, if there are no denied
/// networks, then the allowed list will effectively deny access to
/// anything that's not in the allowed list. On the other hand, if
/// denied networks are specified, then allowed networks will only apply
/// if the deny rule matched, but otherwise the address will be allowed.
///
/// **Strict-allowlist mode** — enabled by `set_strict_allow(true)` or the
/// `allow_networks_strict = true` config field. `allow_networks` acts
/// as a firewall-style allowlist: when the family-specific allow list
/// is non-empty, any source IP that doesn't match an allow entry is
/// refused regardless of the deny list. The deny list is still honoured
/// for IPs that do match an allow entry (more-specific deny wins,
/// matching the default mode's precedence).
///
/// Strict mode is scoped per address family: if you list only IPv4
/// allow rules, IPv6 traffic falls back to the default-mode logic for
/// its own family — operators who want to block other families add
/// explicit deny rules there.
#[derive(Default)]
pub(crate) struct AccessControl {
    ipv4: InnerAccessControl<Ipv4Net>,
    ipv6: InnerAccessControl<Ipv6Net>,
    /// When true, a non-empty allow list for a family rejects every
    /// source IP in that family that isn't explicitly listed —
    /// firewall-style semantics. Off by default to keep the original
    /// carve-out behaviour for existing operators.
    strict_allow: bool,
}

impl AccessControl {
    /// Insert a new network that is denied access to the server
    pub(crate) fn insert_deny(&mut self, networks: impl IntoIterator<Item = IpNet>) {
        for network in networks {
            match network {
                IpNet::V4(v4) => {
                    self.ipv4.deny.insert(v4);
                }
                IpNet::V6(v6) => {
                    self.ipv6.deny.insert(v6);
                }
            }
        }
    }

    /// Insert a new network that is allowed access to the server
    pub(crate) fn insert_allow(&mut self, networks: impl IntoIterator<Item = IpNet>) {
        for network in networks {
            match network {
                IpNet::V4(v4) => {
                    self.ipv4.allow.insert(v4);
                }
                IpNet::V6(v6) => {
                    self.ipv6.allow.insert(v6);
                }
            }
        }
    }

    /// Toggle strict-allowlist semantics on this controller.
    ///
    /// When `strict` is `true`, a non-empty allow list rejects every
    /// source IP in that family that isn't explicitly listed (see the
    /// struct-level docs for the precise contract). When `false` —
    /// the default — the carve-out semantics that have shipped since
    /// the access-control feature was introduced are preserved.
    pub(crate) fn set_strict_allow(&mut self, strict: bool) {
        self.strict_allow = strict;
    }

    /// Evaluate the IP address against the allowed networks
    ///
    /// # Arguments
    ///
    /// * `ip` - source ip address to evaluate
    ///
    /// # Return
    ///
    /// Ok if access is granted, Err otherwise
    #[must_use]
    pub(crate) fn allow(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(v4) => {
                let v4 = Ipv4Net::from(v4);

                self.ipv4.allow(&v4, self.strict_allow)
            }
            IpAddr::V6(v6) => {
                let v6 = Ipv6Net::from(v6);

                self.ipv6.allow(&v6, self.strict_allow)
            }
        }
    }
}

#[derive(Default)]
struct InnerAccessControl<I: Prefix> {
    allow: PrefixSet<I>,
    deny: PrefixSet<I>,
}

impl<I: Prefix> InnerAccessControl<I> {
    /// Evaluate the IP address against the allowed networks
    ///
    /// This allows for generic evaluation over IPv4 or IPv6 address spaces
    ///
    /// # Arguments
    ///
    /// * `ip` - source ip address to evaluate
    /// * `strict_allow` - when `true`, treat `allow` as a strict
    ///   firewall-style allowlist for this family: a non-empty allow
    ///   list refuses any source IP that doesn't match an allow
    ///   entry, even if the deny list wouldn't otherwise reject it.
    ///   See `AccessControl`'s struct docs for the precise contract.
    ///   When `false` (the default), the original carve-out semantics
    ///   apply.
    ///
    /// # Return
    ///
    /// Ok if access is granted, Err otherwise
    #[must_use]
    fn allow(&self, ip: &I, strict_allow: bool) -> bool {
        // If there are no allows or denies specified, we will always default to allow.
        // Allows without denies always translate to deny all except those in the allow list.
        // Denies without allows only deny those in the specified deny list.
        // If there are both allow and deny lists, then the deny list takes precedent with the allow list
        //  overriding the deny if it is more specific (carve-out mode) — unless
        //  `strict_allow` is set, in which case an unmatched source is refused as long as the allow list
        //  has any entry for this family.
        match (self.deny.get_lpm(ip), self.allow.get_lpm(ip)) {
            (Some(denied), Some(allowed)) => allowed.prefix_len() > denied.prefix_len(),
            (Some(_denied), None) => false,
            (None, Some(_allowed)) => true,
            (None, None) => {
                let has_deny = self.deny.iter().next().is_some();
                let has_allow = self.allow.iter().next().is_some();
                // Strict-allowlist short-circuit: as soon as the
                // operator listed any allow entry for this family,
                // an unmatched source is refused regardless of the
                // deny list's contents. Only kicks in when the
                // caller opts into strict mode; otherwise the
                // existing (carve-out) fall-through runs.
                if strict_allow && has_allow {
                    return false;
                }
                match (has_deny, has_allow) {
                    (true, _) => true,      // there are deny entries, but this isn't one
                    (false, true) => false, // there are only allow entries, but this isn't one
                    (false, false) => true, // there are no entries
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none() {
        let access = AccessControl::default();
        assert!(access.allow("192.168.1.1".parse().unwrap()));
        assert!(access.allow("fd00::1".parse().unwrap()));
    }

    #[test]
    fn test_v4() {
        let mut access = AccessControl::default();
        access.insert_allow(["192.168.1.0/24".parse().unwrap()]);

        assert!(access.allow("192.168.1.1".parse().unwrap()));
        assert!(access.allow("192.168.1.255".parse().unwrap()));
        assert!(!access.allow("192.168.2.1".parse().unwrap()));
        assert!(!access.allow("192.168.0.0".parse().unwrap()));
    }

    #[test]
    fn test_v6() {
        let mut access = AccessControl::default();
        access.insert_allow(["fd00::/120".parse().unwrap()]);

        assert!(access.allow("fd00::1".parse().unwrap()));
        assert!(access.allow("fd00::00ff".parse().unwrap()));
        assert!(!access.allow("fd00::ffff".parse().unwrap()));
        assert!(!access.allow("fd00::1:1".parse().unwrap()));
    }

    #[test]
    fn test_deny_v4() {
        let mut access = AccessControl::default();
        access.insert_deny(["192.168.1.0/24".parse().unwrap()]);

        assert!(!access.allow("192.168.1.1".parse().unwrap()));
        assert!(!access.allow("192.168.1.255".parse().unwrap()));
        assert!(access.allow("192.168.2.1".parse().unwrap()));
        assert!(access.allow("192.168.0.0".parse().unwrap()));
    }

    #[test]
    fn test_deny_v6() {
        let mut access = AccessControl::default();
        access.insert_deny(["fd00::/120".parse().unwrap()]);

        assert!(!access.allow("fd00::1".parse().unwrap()));
        assert!(!access.allow("fd00::00ff".parse().unwrap()));
        assert!(access.allow("fd00::ffff".parse().unwrap()));
        assert!(access.allow("fd00::1:1".parse().unwrap()));
    }

    #[test]
    fn test_deny_allow_v4() {
        let mut access = AccessControl::default();
        access.insert_deny(["192.168.0.0/16".parse().unwrap()]);
        access.insert_allow(["192.168.1.0/24".parse().unwrap()]);

        assert!(access.allow("192.168.1.1".parse().unwrap()));
        assert!(access.allow("192.168.1.255".parse().unwrap()));
        assert!(!access.allow("192.168.2.1".parse().unwrap()));
        assert!(!access.allow("192.168.0.0".parse().unwrap()));

        // but all other networks should be allowed
        assert!(access.allow("10.0.0.1".parse().unwrap()));
    }

    // A dual-stack listener delivers a v4 client as `::ffff:a.b.c.d`. That
    // source must still hit the v4 deny prefix the operator configured.
    #[test]
    fn test_v4_mapped_v6_matches_v4_deny() {
        let mut access = AccessControl::default();
        access.insert_deny(["192.168.0.0/16".parse().unwrap()]);
        access.insert_deny(["10.0.0.0/8".parse().unwrap()]);

        assert!(!access.allow("192.168.1.1".parse().unwrap()));
        assert!(!access.allow("10.2.3.4".parse().unwrap()));

        assert!(!access.allow("::ffff:192.168.1.1".parse().unwrap()));
        assert!(!access.allow("::ffff:10.2.3.4".parse().unwrap()));

        assert!(access.allow("8.8.8.8".parse().unwrap()));
        assert!(access.allow("::ffff:8.8.8.8".parse().unwrap()));
        assert!(access.allow("2001:db8::1".parse().unwrap()));
    }

    // Allow-list overrides must follow the same canonicalisation so a v4
    // exception applies to the matching `::ffff:` source too.
    #[test]
    fn test_v4_mapped_v6_honours_v4_allow_override() {
        let mut access = AccessControl::default();
        access.insert_deny(["10.0.0.0/8".parse().unwrap()]);
        access.insert_allow(["10.1.2.3/32".parse().unwrap()]);

        assert!(!access.allow("10.2.3.4".parse().unwrap()));
        assert!(access.allow("10.1.2.3".parse().unwrap()));

        assert!(!access.allow("::ffff:10.2.3.4".parse().unwrap()));
        assert!(access.allow("::ffff:10.1.2.3".parse().unwrap()));
    }

    // --- strict-allowlist mode ---------------------------------------
    //
    // `set_strict_allow(true)` flips the semantics so `allow_networks`
    // acts as a firewall-style allowlist: an unmatched source is
    // refused even when the deny list has nothing to say about it.
    // These tests pin down the documented contract.

    // Without strict mode (default), an IP outside both lists is
    // allowed when any deny entry exists — the original carve-out
    // semantics. Pin that here so a future refactor can't silently
    // regress the default.
    #[test]
    fn test_default_mode_allows_unmatched_when_deny_set() {
        let mut access = AccessControl::default();
        access.insert_deny(["192.168.0.0/16".parse().unwrap()]);
        access.insert_allow(["192.168.1.0/24".parse().unwrap()]);

        // Unmatched source: not in deny, not in allow. Carve-out
        // semantics let it through.
        assert!(access.allow("10.0.0.1".parse().unwrap()));
    }

    // Strict mode: same allow/deny pair, but the unmatched source is
    // refused because the allow list is non-empty.
    #[test]
    fn test_strict_mode_refuses_unmatched_when_allow_set() {
        let mut access = AccessControl::default();
        access.insert_deny(["192.168.0.0/16".parse().unwrap()]);
        access.insert_allow(["192.168.1.0/24".parse().unwrap()]);
        access.set_strict_allow(true);

        assert!(!access.allow("10.0.0.1".parse().unwrap()));
        // Allowed entries still pass (allow overrides deny when more
        // specific — same as the default mode).
        assert!(access.allow("192.168.1.1".parse().unwrap()));
        // Deny entries that aren't carved out still refused.
        assert!(!access.allow("192.168.2.1".parse().unwrap()));
    }

    // Strict mode with an allow-only list behaves exactly like the
    // default — every unmatched source already gets refused via the
    // existing `(false, true)` arm. Test verifies the strict flag
    // doesn't break that case.
    #[test]
    fn test_strict_mode_allow_only_matches_default() {
        let mut access = AccessControl::default();
        access.insert_allow(["192.168.1.0/24".parse().unwrap()]);
        access.set_strict_allow(true);

        assert!(access.allow("192.168.1.1".parse().unwrap()));
        assert!(!access.allow("192.168.2.1".parse().unwrap()));
        assert!(!access.allow("10.0.0.1".parse().unwrap()));
    }

    // Strict mode with a deny-only list should NOT lock everyone out.
    // The short-circuit only fires when the allow list has entries
    // for the family.
    #[test]
    fn test_strict_mode_deny_only_unaffected() {
        let mut access = AccessControl::default();
        access.insert_deny(["192.168.0.0/16".parse().unwrap()]);
        access.set_strict_allow(true);

        // No allow entries → strict has nothing to enforce → default
        // deny-only semantics: anything outside deny is allowed.
        assert!(access.allow("10.0.0.1".parse().unwrap()));
        assert!(!access.allow("192.168.5.5".parse().unwrap()));
    }

    // Strict mode is scoped per family. v4 allow rules don't lock out
    // v6 traffic — operators who want both families locked down add
    // explicit v6 entries.
    #[test]
    fn test_strict_mode_per_family_scope() {
        let mut access = AccessControl::default();
        access.insert_allow(["192.168.1.0/24".parse().unwrap()]);
        access.set_strict_allow(true);

        // v4 client outside the allow list → refused.
        assert!(!access.allow("10.0.0.1".parse().unwrap()));
        // v6 client → the v6 family has no allow entries, so strict
        // has nothing to enforce and the source is allowed.
        assert!(access.allow("2001:db8::1".parse().unwrap()));
    }

    // Strict mode honours the more-specific-wins precedence between
    // overlapping allow and deny rules — same as default mode.
    #[test]
    fn test_strict_mode_more_specific_deny_wins() {
        let mut access = AccessControl::default();
        access.insert_allow(["10.0.0.0/8".parse().unwrap()]);
        access.insert_deny(["10.99.0.0/24".parse().unwrap()]);
        access.set_strict_allow(true);

        // In the allow set, deny doesn't apply → allow.
        assert!(access.allow("10.1.2.3".parse().unwrap()));
        // In a deny that's more specific than its overlapping allow
        // → refuse.
        assert!(!access.allow("10.99.0.5".parse().unwrap()));
        // Outside the allow set → refuse (strict semantics).
        assert!(!access.allow("172.16.0.1".parse().unwrap()));
    }
}
