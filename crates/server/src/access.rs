use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::{Prefix, PrefixSet};

/// Type to evaluate access from a source address for accessing the server.
///
/// Allowed networks will override denied networks, i.e. if a network is allowed, the deny rules will not be evaluated.
/// Allowed networks are processed in the context of denied networks, that is, if there are no denied networks, then
///   the allowed list will effectively deny access to anything that's not in the allowed list. On the other hand, if
///   denied networks are specified, then allowed networks will only apply if the deny rule matched, but otherwise the
///   address will be allowed.
#[derive(Default)]
pub(crate) struct AccessControl {
    ipv4: InnerAccessControl<Ipv4Net>,
    ipv6: InnerAccessControl<Ipv6Net>,
}

impl AccessControl {
    /// Insert a new network that is denied access to the server
    pub(crate) fn insert_deny(&mut self, networks: &[IpNet]) {
        for network in networks {
            match network {
                IpNet::V4(v4) => {
                    self.ipv4.deny.insert(*v4);
                }
                IpNet::V6(v6) => {
                    self.ipv6.deny.insert(*v6);
                }
            }
        }
    }

    /// Insert a new network that is allowed access to the server
    pub(crate) fn insert_allow(&mut self, networks: &[IpNet]) {
        for network in networks {
            match network {
                IpNet::V4(v4) => {
                    self.ipv4.allow.insert(*v4);
                }
                IpNet::V6(v6) => {
                    self.ipv6.allow.insert(*v6);
                }
            }
        }
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
        match ip {
            IpAddr::V4(v4) => {
                let v4 = Ipv4Net::from(v4);

                self.ipv4.allow(&v4)
            }
            IpAddr::V6(v6) => {
                let v6 = Ipv6Net::from(v6);

                self.ipv6.allow(&v6)
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
    ///
    /// # Return
    ///
    /// Ok if access is granted, Err otherwise
    #[must_use]
    fn allow(&self, ip: &I) -> bool {
        // If there are no allows or denies specified, we will always default to allow.
        // Allows without denies always translate to deny all except those in the allow list.
        // Denies without allows only deny those in the specified deny list.
        // If there are both allow and deny lists, then the deny list takes precedent with the allow list
        //  overriding the deny if it is more specific.
        match (self.deny.get_lpm(ip), self.allow.get_lpm(ip)) {
            (Some(denied), Some(allowed)) => allowed.prefix_len() > denied.prefix_len(),
            (Some(_denied), None) => false,
            (None, Some(_allowed)) => true,
            (None, None) => match (
                self.deny.iter().next().is_some(),
                self.allow.iter().next().is_some(),
            ) {
                (true, _) => true,      // there are deny entries, but this isn't one
                (false, true) => false, // there are only allow entries, but this isn't one
                (false, false) => true, // there are no entries
            },
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
        access.insert_allow(&["192.168.1.0/24".parse().unwrap()]);

        assert!(access.allow("192.168.1.1".parse().unwrap()));
        assert!(access.allow("192.168.1.255".parse().unwrap()));
        assert!(!access.allow("192.168.2.1".parse().unwrap()));
        assert!(!access.allow("192.168.0.0".parse().unwrap()));
    }

    #[test]
    fn test_v6() {
        let mut access = AccessControl::default();
        access.insert_allow(&["fd00::/120".parse().unwrap()]);

        assert!(access.allow("fd00::1".parse().unwrap()));
        assert!(access.allow("fd00::00ff".parse().unwrap()));
        assert!(!access.allow("fd00::ffff".parse().unwrap()));
        assert!(!access.allow("fd00::1:1".parse().unwrap()));
    }

    #[test]
    fn test_deny_v4() {
        let mut access = AccessControl::default();
        access.insert_deny(&["192.168.1.0/24".parse().unwrap()]);

        assert!(!access.allow("192.168.1.1".parse().unwrap()));
        assert!(!access.allow("192.168.1.255".parse().unwrap()));
        assert!(access.allow("192.168.2.1".parse().unwrap()));
        assert!(access.allow("192.168.0.0".parse().unwrap()));
    }

    #[test]
    fn test_deny_v6() {
        let mut access = AccessControl::default();
        access.insert_deny(&["fd00::/120".parse().unwrap()]);

        assert!(!access.allow("fd00::1".parse().unwrap()));
        assert!(!access.allow("fd00::00ff".parse().unwrap()));
        assert!(access.allow("fd00::ffff".parse().unwrap()));
        assert!(access.allow("fd00::1:1".parse().unwrap()));
    }

    #[test]
    fn test_deny_allow_v4() {
        let mut access = AccessControl::default();
        access.insert_deny(&["192.168.0.0/16".parse().unwrap()]);
        access.insert_allow(&["192.168.1.0/24".parse().unwrap()]);

        assert!(access.allow("192.168.1.1".parse().unwrap()));
        assert!(access.allow("192.168.1.255".parse().unwrap()));
        assert!(!access.allow("192.168.2.1".parse().unwrap()));
        assert!(!access.allow("192.168.0.0".parse().unwrap()));

        // but all other networks should be allowed
        assert!(access.allow("10.0.0.1".parse().unwrap()));
    }
}
