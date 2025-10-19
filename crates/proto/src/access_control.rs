//! Utility functions that are used in multiple crates
use core::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::PrefixSet;
use tracing::debug;

/// An IPv4/IPv6 access control set.  This mainly hides the complexity of supporting v4 and v6
/// addresses concurrently in a given set.  The AccessControlSet differs from a typical Access
/// Control List in that there is no order.  The access semantics are:
///
/// | Present in allow list | Present in deny list |  Result  |
/// |-----------------------|----------------------|----------|
/// |                  true |                false |  allowed |
/// |                  true |                 true |  allowed |
/// |                 false |                false |  allowed |
/// |                 false |                 true |   denied |
#[derive(Clone, Debug)]
pub struct AccessControlSet {
    name: &'static str,
    v4_allow: PrefixSet<Ipv4Net>,
    v4_deny: PrefixSet<Ipv4Net>,
    v6_allow: PrefixSet<Ipv6Net>,
    v6_deny: PrefixSet<Ipv6Net>,
}

impl<'a> AccessControlSet {
    /// Construct a new AccessControlSet with the given `name`.  `name` is an arbitrary string used
    /// in log messages.
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            v4_allow: PrefixSet::new(),
            v4_deny: PrefixSet::new(),
            v6_allow: PrefixSet::new(),
            v6_deny: PrefixSet::new(),
        }
    }

    /// Insert new subnets in the allow list.  Existing subnets will not be removed.
    pub fn allow(&mut self, allow: impl Iterator<Item = &'a IpNet>) {
        for network in allow {
            debug!(self.name, ?network, "appending to allow list");
            match network {
                IpNet::V4(network) => {
                    self.v4_allow.insert(*network);
                }
                IpNet::V6(network) => {
                    self.v6_allow.insert(*network);
                }
            }
        }
    }

    /// Insert new subnets in the deny list.  Existing subnets will not be removed.
    pub fn deny(&mut self, deny: impl Iterator<Item = &'a IpNet>) {
        for network in deny {
            debug!(self.name, ?network, "appending to deny list");
            match network {
                IpNet::V4(network) => {
                    self.v4_deny.insert(*network);
                }
                IpNet::V6(network) => {
                    self.v6_deny.insert(*network);
                }
            }
        }
    }

    /// Clear all subnets from the allow list.
    pub fn clear_allow(&mut self) {
        self.v4_allow.clear();
        self.v6_allow.clear();
    }

    /// Clear all subnets from the deny list.
    pub fn clear_deny(&mut self) {
        self.v4_deny.clear();
        self.v6_deny.clear();
    }

    /// Check if the IP address `ip` should be denied.  If the IP address is in the deny list
    /// and not in the allow list, this function will return true.  All other combinations will
    /// return false (i.e., the allow list acts like an exception list.)
    pub fn denied(&self, ip: IpAddr) -> bool {
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

/// A builder interface for the AccessControlSet
pub struct AccessControlSetBuilder(AccessControlSet);

impl<'a> AccessControlSetBuilder {
    /// Set `name` for logging purposes on the AccessControlSetBuilder
    pub fn new(name: &'static str) -> Self {
        Self(AccessControlSet::new(name))
    }

    /// Add allow list IP addresses for the AccessControlSetBuilder
    pub fn allow(mut self, allow: impl Iterator<Item = &'a IpNet>) -> Self {
        self.0.allow(allow);
        self
    }

    /// Add deny list IP addresses for the AccessControlSetBuilder
    pub fn deny(mut self, deny: impl Iterator<Item = &'a IpNet>) -> Self {
        self.0.deny(deny);
        self
    }

    /// Construct the AccessControlSet
    pub fn build(self) -> AccessControlSet {
        self.0
    }
}

#[test]
fn access_control_set_test() {
    use super::access_control::AccessControlSetBuilder;

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
        .build();

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
