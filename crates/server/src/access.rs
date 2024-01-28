use std::net::IpAddr;

use hickory_proto::error::{ProtoError, ProtoErrorKind};
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
    pub(crate) fn insert_deny(&mut self, network: IpNet) {
        match network {
            IpNet::V4(v4) => {
                self.ipv4.deny.insert(v4);
            }
            IpNet::V6(v6) => {
                self.ipv6.deny.insert(v6);
            }
        }
    }

    /// Insert a new network that is allowed access to the server
    pub(crate) fn insert_allow(&mut self, network: IpNet) {
        match network {
            IpNet::V4(v4) => {
                self.ipv4.allow.insert(v4);
            }
            IpNet::V6(v6) => {
                self.ipv6.allow.insert(v6);
            }
        }
    }

    pub(crate) fn insert_deny_all(&mut self, networks: &[IpNet]) {
        for net in networks {
            self.insert_deny(*net);
        }
    }

    pub(crate) fn insert_allow_all(&mut self, networks: &[IpNet]) {
        for net in networks {
            self.insert_allow(*net);
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
    pub(crate) fn allow(&self, ip: IpAddr) -> Result<(), ProtoError> {
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
    fn allow(&self, ip: &I) -> Result<(), ProtoError> {
        // If the IP is denied, there might be an override, otherwise we default to the result of the deny
        //   Allows are the in the context of deny, so if there are any networks in the deny, then allow is only applied
        //   if the network is denied. If there were no denies, then allow is applied and only those networks specified
        //   are allowed
        let allowed = match (self.deny.get_lpm(ip), self.allow.get_lpm(ip)) {
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
        };

        if allowed {
            Ok(())
        } else {
            Err(ProtoErrorKind::RequestRefused.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none() {
        let access = AccessControl::default();
        assert!(access.allow("192.168.1.1".parse().unwrap()).is_ok());
        assert!(access.allow("fd00::1".parse().unwrap()).is_ok());
    }

    #[test]
    fn test_v4() {
        let mut access = AccessControl::default();
        access.insert_allow("192.168.1.0/24".parse().unwrap());

        assert!(access.allow("192.168.1.1".parse().unwrap()).is_ok());
        assert!(access.allow("192.168.1.255".parse().unwrap()).is_ok());
        assert!(access.allow("192.168.2.1".parse().unwrap()).is_err());
        assert!(access.allow("192.168.0.0".parse().unwrap()).is_err());
    }

    #[test]
    fn test_v6() {
        let mut access = AccessControl::default();
        access.insert_allow("fd00::/120".parse().unwrap());

        assert!(access.allow("fd00::1".parse().unwrap()).is_ok());
        assert!(access.allow("fd00::00ff".parse().unwrap()).is_ok());
        assert!(access.allow("fd00::ffff".parse().unwrap()).is_err());
        assert!(access.allow("fd00::1:1".parse().unwrap()).is_err());
    }

    #[test]
    fn test_deny_v4() {
        let mut access = AccessControl::default();
        access.insert_deny("192.168.1.0/24".parse().unwrap());

        assert!(access.allow("192.168.1.1".parse().unwrap()).is_err());
        assert!(access.allow("192.168.1.255".parse().unwrap()).is_err());
        assert!(access.allow("192.168.2.1".parse().unwrap()).is_ok());
        assert!(access.allow("192.168.0.0".parse().unwrap()).is_ok());
    }

    #[test]
    fn test_deny_v6() {
        let mut access = AccessControl::default();
        access.insert_deny("fd00::/120".parse().unwrap());

        assert!(access.allow("fd00::1".parse().unwrap()).is_err());
        assert!(access.allow("fd00::00ff".parse().unwrap()).is_err());
        assert!(access.allow("fd00::ffff".parse().unwrap()).is_ok());
        assert!(access.allow("fd00::1:1".parse().unwrap()).is_ok());
    }

    #[test]
    fn test_deny_allow_v4() {
        let mut access = AccessControl::default();
        access.insert_deny("192.168.0.0/16".parse().unwrap());
        access.insert_allow("192.168.1.0/24".parse().unwrap());

        assert!(access.allow("192.168.1.1".parse().unwrap()).is_ok());
        assert!(access.allow("192.168.1.255".parse().unwrap()).is_ok());
        assert!(access.allow("192.168.2.1".parse().unwrap()).is_err());
        assert!(access.allow("192.168.0.0".parse().unwrap()).is_err());

        // but all other networks should be allowed
        assert!(access.allow("10.0.0.1".parse().unwrap()).is_ok());
    }
}
