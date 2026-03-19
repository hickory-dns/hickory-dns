//! Utility functions that are used in multiple crates
use core::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::PrefixSet;
use tracing::debug;

use crate::ProtoError;

/// A builder interface for constructing an [`AccessControlSet`].
pub struct AccessControlSetBuilder(AccessControlSet);

impl<'a> AccessControlSetBuilder {
    /// Construct a builder for an access control set with the given `name`.
    ///
    /// The `name` is used to contextualize logging when an [`IpAddr`] is denied.
    pub fn new(name: &'static str) -> Self {
        Self(AccessControlSet::new(name))
    }

    /// Override the [`Self::deny()`] list for the provided IP networks, allowing access.
    ///
    /// Existing networks allowed by prior [`Self::allow()`] calls are not removed.
    ///
    /// See [`AccessControlSet`] for more information on the access semantics.
    pub fn allow(mut self, allow: impl Iterator<Item = &'a IpNet>) -> Self {
        for network in allow {
            debug!(name = self.0.name, ?network, "appending to allow list");
            match network {
                IpNet::V4(network) => {
                    self.0.v4_allow.insert(*network);
                }
                IpNet::V6(network) => {
                    self.0.v6_allow.insert(*network);
                }
            }
        }
        self
    }

    /// Deny clients from the provided IP networks, unless present in the [`Self::allow()`] list.
    ///
    /// Existing networks denied by prior [`Self::deny()`] calls are not removed.
    ///
    /// See [`AccessControlSet`] for more information on the access semantics.
    pub fn deny(mut self, deny: impl Iterator<Item = &'a IpNet>) -> Self {
        for network in deny {
            debug!(name = self.0.name, ?network, "appending to deny list");
            match network {
                IpNet::V4(network) => {
                    self.0.v4_deny.insert(*network);
                }
                IpNet::V6(network) => {
                    self.0.v6_deny.insert(*network);
                }
            }
        }
        self
    }

    /// Clear all IP networks previous allowed with [`Self::allow()`].
    pub fn clear_allow(mut self) -> Self {
        self.0.v4_allow.clear();
        self.0.v6_allow.clear();
        self
    }

    /// Clear all IP networks previously denied with [`Self::deny()`].
    pub fn clear_deny(mut self) -> Self {
        self.0.v4_deny.clear();
        self.0.v6_deny.clear();
        self
    }

    /// Consume the builder and produce an [`AccessControlSet`].
    ///
    /// Returns an error if [`Self::allow()`] was used to add deny list override networks
    /// without using [`Self::deny()`] to specify one or more denied networks.
    pub fn build(self) -> Result<AccessControlSet, ProtoError> {
        let deny_empty = self.0.v4_deny.is_empty() && self.0.v6_deny.is_empty();
        let allowed_count = self.0.v4_allow.iter().count() + self.0.v6_allow.iter().count();
        if deny_empty && allowed_count != 0 {
            return Err(format!(
                "access control set {name:?} has {allowed_count} allowed overrides, but no denied networks to override",
                name = self.0.name
            ).into());
        }
        Ok(self.0)
    }
}

/// An IPv4/IPv6 access control set.
///
/// Use [`AccessControlSetBuilder`] to construct an instance.
/// When determining if an [`IpAddr`] is denied with [`Self::denied()`], the deny list
/// is considered first, and the allow list may override the deny
/// decision.
///
/// The full access semantics are:
///
/// | Present in deny list | Present in allow list |  Result  |
/// |-----------------------|----------------------|----------|
/// |                  true |                false |  denied |
/// |                 false |                false |  allowed |
/// |                  true |                 true |  allowed |
/// |                 false |                 true |  allowed |
#[derive(Clone, Debug)]
pub struct AccessControlSet {
    name: &'static str,
    v4_allow: PrefixSet<Ipv4Net>,
    v4_deny: PrefixSet<Ipv4Net>,
    v6_allow: PrefixSet<Ipv6Net>,
    v6_deny: PrefixSet<Ipv6Net>,
}

impl AccessControlSet {
    /// Construct an access control set with the given `name`.
    ///
    /// The name is used to contextualize logging when an [`IpAddr`] is denied.
    fn new(name: &'static str) -> Self {
        Self {
            name,
            v4_allow: PrefixSet::new(),
            v4_deny: PrefixSet::new(),
            v6_allow: PrefixSet::new(),
            v6_deny: PrefixSet::new(),
        }
    }

    /// Construct an empty access control set with the given `name` that allows all networks.
    pub fn empty(name: &'static str) -> Self {
        Self::new(name)
    }

    /// Returns true if the access control set allows all addresses.
    ///
    /// This is true when no IPv4 or IPv6 networks are denied.
    pub fn allows_all(&self) -> bool {
        self.v4_deny.is_empty() && self.v4_deny.is_empty()
    }

    /// Check if the IP address `ip` should be denied.
    ///
    /// If the IP address is in a network previously denied by [`AccessControlSetBuilder::deny()`]
    /// that wasn't explicitly allowed with [`AccessControlSetBuilder::allow()`], this function
    /// will return true.
    ///
    /// All other combinations will return false (i.e., [`AccessControlSetBuilder::allow()`] acts
    /// like an exception list for [`AccessControlSetBuilder::deny()`])
    pub fn denied(&self, ip: IpAddr) -> bool {
        // If both deny lists are empty, short-circuit. There's nothing to consider.
        if self.allows_all() {
            return false;
        }
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

#[cfg(test)]
mod tests {
    use crate::access_control::AccessControlSetBuilder;

    #[test]
    fn access_control_set_networks_test() {
        let acs = AccessControlSetBuilder::new("test acs")
            .deny(
                [
                    "10.0.0.0/8".parse().unwrap(),
                    "172.16.0.0/12".parse().unwrap(),
                    "192.168.0.0/16".parse().unwrap(),
                    "fe80::/10".parse().unwrap(),
                ]
                .iter(),
            )
            .allow(
                [
                    "10.1.0.3/29".parse().unwrap(),
                    "192.168.1.10/32".parse().unwrap(),
                    "fe80::200/128".parse().unwrap(),
                ]
                .iter(),
            )
            .build()
            .unwrap();

        // 10.1.0.3/29 above should cause 10.1.0.0/29 to be placed into the allow list; validate the
        // address before and after are blocked, and addresses within the subnet are allowed
        assert!(acs.denied([10, 0, 254, 254].into()));
        assert!(!acs.denied([10, 1, 0, 0].into()));
        assert!(!acs.denied([10, 1, 0, 3].into()));
        assert!(!acs.denied([10, 1, 0, 7].into()));
        assert!(acs.denied([10, 1, 0, 8].into()));

        assert!(acs.denied([192, 168, 1, 1].into()));
        assert!(!acs.denied([192, 168, 1, 10].into()));

        assert!(!acs.denied([0xfe80, 0, 0, 0, 0, 0, 0, 0x200].into()));
        assert!(acs.denied([0xfe80, 0, 0, 0, 0, 0, 0, 1].into()));
    }

    // Test the access control semantics described in the Rustdoc of `AccessControlSet`
    #[test]
    fn access_control_semantics_test() {
        struct TestCase {
            name: &'static str,
            in_deny: bool,
            in_allow: bool,
            expected_build_err: bool,
            expected_denied: bool,
        }

        let test_cases = [
            TestCase {
                name: "deny=true, allow=false -> denied",
                in_deny: true,
                in_allow: false,
                expected_build_err: false,
                expected_denied: true,
            },
            TestCase {
                name: "deny=false, allow=false -> allowed",
                in_deny: false,
                in_allow: false,
                expected_build_err: false,
                expected_denied: false,
            },
            TestCase {
                name: "deny=true, allow=true -> allowed",
                in_deny: true,
                in_allow: true,
                expected_build_err: false,
                expected_denied: false,
            },
            TestCase {
                name: "deny=false, allow=true -> allowed",
                in_deny: false,
                in_allow: true,
                expected_build_err: true,
                expected_denied: false,
            },
        ];

        let test_v4 = [192, 0, 2, 1].into();
        let test_v4_net = "192.0.2.0/24".parse().unwrap();
        let test_v6 = [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into();
        let test_v6_net = "2001:db8::/32".parse().unwrap();

        for tc in &test_cases {
            let mut builder = AccessControlSetBuilder::new(tc.name);
            if tc.in_deny {
                builder = builder.deny([test_v4_net, test_v6_net].iter());
            }
            if tc.in_allow {
                builder = builder.allow([test_v4_net, test_v6_net].iter());
            }

            let Ok(acs) = builder.build() else {
                match tc.expected_build_err {
                    true => continue,
                    false => panic!("unexpected builder error"),
                }
            };
            assert_eq!(
                acs.denied(test_v4),
                tc.expected_denied,
                "IPv4 case '{}' failed",
                tc.name
            );
            assert_eq!(
                acs.denied(test_v6),
                tc.expected_denied,
                "IPv6 case '{}' failed",
                tc.name
            );
        }
    }
}
