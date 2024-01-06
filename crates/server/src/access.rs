use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::PrefixSet;

/// Type to evaluate access from a source address for accessing the server.
#[derive(Default)]
pub(crate) struct Access {
    allow_ipv4: Option<PrefixSet<Ipv4Net>>,
    allow_ipv6: Option<PrefixSet<Ipv6Net>>,
}

impl Access {
    /// Insert a new network that is allowed access to the server
    pub(crate) fn insert(&mut self, network: IpNet) {
        match network {
            IpNet::V4(v4) => {
                if self.allow_ipv4.is_none() {
                    self.allow_ipv4 = Some(PrefixSet::default());
                }

                self.allow_ipv4.as_mut().unwrap().insert(v4);
            }
            IpNet::V6(v6) => {
                if self.allow_ipv6.is_none() {
                    self.allow_ipv6 = Some(PrefixSet::default());
                }

                self.allow_ipv6.as_mut().unwrap().insert(v6);
            }
        }
    }

    /// Evaluate the IP address against the allowed networks
    ///
    /// # Return
    ///
    /// Ok if access is granted, Err otherwise
    pub(crate) fn allow(&self, ip: IpAddr) -> Result<(), ()> {
        match ip {
            IpAddr::V4(v4) => {
                let v4 = Ipv4Net::from(v4);
                self.allow_ipv4.as_ref().map_or(Ok(()), |allow_ipv4| {
                    allow_ipv4.get_lpm(&v4).map(|_| ()).ok_or(())
                })
            }
            IpAddr::V6(v6) => {
                let v6 = Ipv6Net::from(v6);
                self.allow_ipv6.as_ref().map_or(Ok(()), |allow_ipv6| {
                    allow_ipv6.get_lpm(&v6).map(|_| ()).ok_or(())
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none() {
        let mut access = Access::default();
        assert!(access.allow("192.168.1.1".parse().unwrap()).is_ok());
        assert!(access.allow("fd00::1".parse().unwrap()).is_ok());
    }

    #[test]
    fn test_v4() {
        let mut access = Access::default();
        access.insert("192.168.1.0/24".parse().unwrap());

        assert!(access.allow("192.168.1.1".parse().unwrap()).is_ok());
        assert!(access.allow("192.168.1.255".parse().unwrap()).is_ok());
        assert!(access.allow("192.168.2.1".parse().unwrap()).is_err());
        assert!(access.allow("192.168.0.0".parse().unwrap()).is_err());
    }

    #[test]
    fn test_v6() {
        let mut access = Access::default();
        access.insert("fd00::/120".parse().unwrap());

        assert!(access.allow("fd00::1".parse().unwrap()).is_ok());
        assert!(access.allow("fd00::00ff".parse().unwrap()).is_ok());
        assert!(access.allow("fd00::ffff".parse().unwrap()).is_err());
        assert!(access.allow("fd00::1:1".parse().unwrap()).is_err());
    }
}
