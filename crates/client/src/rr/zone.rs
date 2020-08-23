//! Reserved Zone and related information

pub use crate::proto::rr::domain::usage::*;
use crate::proto::rr::domain::{BorrowedName, DnsName, Label, Name};
use crate::proto::serialize::binary::BinEncodable;

use lazy_static::lazy_static;
use radix_trie::{Trie, TrieKey};

// Reserved reverse IPs
//
// [Special-Use Domain Names](https://tools.ietf.org/html/rfc6761), RFC 6761 February, 2013
//
// ```text
// 6.1.  Domain Name Reservation Considerations for Private Addresses
//
//    The private-address [RFC1918] reverse-mapping domains listed below,
//    and any names falling within those domains, are Special-Use Domain
//    Names:
//
//      10.in-addr.arpa.      21.172.in-addr.arpa.  26.172.in-addr.arpa.
//      16.172.in-addr.arpa.  22.172.in-addr.arpa.  27.172.in-addr.arpa.
//      17.172.in-addr.arpa.  30.172.in-addr.arpa.  28.172.in-addr.arpa.
//      18.172.in-addr.arpa.  23.172.in-addr.arpa.  29.172.in-addr.arpa.
//      19.172.in-addr.arpa.  24.172.in-addr.arpa.  31.172.in-addr.arpa.
//      20.172.in-addr.arpa.  25.172.in-addr.arpa.  168.192.in-addr.arpa.
// ```
lazy_static! {
    /// 10.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_10: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("10").unwrap().to_name().append_domain(&*IN_ADDR_ARPA));

    static ref IN_ADDR_ARPA_172: Name = Name::from_ascii("172").unwrap().to_name().append_domain(&*IN_ADDR_ARPA);

    /// 16.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_16: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("16").unwrap().to_name().append_domain(&*IN_ADDR_ARPA_172));
    /// 17.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_17: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("17").unwrap().to_name().append_domain(&*IN_ADDR_ARPA_172));
    /// 18.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_18: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("18").unwrap().to_name().append_domain(&*IN_ADDR_ARPA_172));
    /// 19.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_19: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("19").unwrap().to_name().append_domain(&*IN_ADDR_ARPA_172));
    /// 20.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_20: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("20").unwrap().to_name().append_domain(&*IN_ADDR_ARPA_172));
    /// 21.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_21: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("21").unwrap().to_name().append_domain(&*IN_ADDR_ARPA_172));
    /// 22.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_22: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("22").unwrap().to_name().append_domain(&*IN_ADDR_ARPA_172));
    /// 23.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_23: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("23").unwrap().to_name().append_domain(&*IN_ADDR_ARPA_172));
    /// 24.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_24: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("24").unwrap().to_name().append_domain(&*IN_ADDR_ARPA_172));
    /// 25.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_25: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("25").unwrap().to_name().append_domain(&*IN_ADDR_ARPA_172));
    /// 26.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_26: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("26").unwrap().to_name().append_domain(&*IN_ADDR_ARPA_172));
    /// 27.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_27: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("27").unwrap().to_name().append_domain(&*IN_ADDR_ARPA_172));
    /// 28.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_28: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("28").unwrap().to_name().append_domain(&*IN_ADDR_ARPA_172));
    /// 29.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_29: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("29").unwrap().to_name().append_domain(&*IN_ADDR_ARPA_172));
    /// 30.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_30: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("30").unwrap().to_name().append_domain(&*IN_ADDR_ARPA_172));
    /// 31.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_31: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("31").unwrap().to_name().append_domain(&*IN_ADDR_ARPA_172));

    /// 168.192.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_192_168: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("168.192").unwrap().to_name().append_domain(&*IN_ADDR_ARPA));
}

// example., example.com., example.net., and example.org.
//
// [Special-Use Domain Names](https://tools.ietf.org/html/rfc6761), RFC 6761 February, 2013
//
// ```text
// 6.5.  Domain Name Reservation Considerations for Example Domains
//
//    The domains "example.", "example.com.", "example.net.",
//    "example.org.", and any names falling within those domains, are
//    special in the following ways:
// ```
lazy_static! {
    static ref COM: Label = Label::from_ascii("com").unwrap();
    static ref NET: Label = Label::from_ascii("net").unwrap();
    static ref ORG: Label = Label::from_ascii("org").unwrap();
    static ref EXAMPLE_L: Label = Label::from_ascii("example").unwrap();

    /// example. usage
    pub static ref EXAMPLE: ZoneUsage = ZoneUsage::example(Name::from_labels(vec![EXAMPLE_L.clone()]).unwrap());
    /// example.com. usage
    pub static ref EXAMPLE_COM: ZoneUsage = ZoneUsage::example(Name::from_labels(vec![EXAMPLE_L.clone(), COM.clone()]).unwrap());
    /// example.com. usage
    pub static ref EXAMPLE_NET: ZoneUsage = ZoneUsage::example(Name::from_labels(vec![EXAMPLE_L.clone(), NET.clone()]).unwrap());
    /// example.com. usage
    pub static ref EXAMPLE_ORG: ZoneUsage = ZoneUsage::example(Name::from_labels(vec![EXAMPLE_L.clone(), ORG.clone()]).unwrap());
}

// test.
//
// [Special-Use Domain Names](https://tools.ietf.org/html/rfc6761), RFC 6761 February, 2013
//
// ```text
// 6.2.  Domain Name Reservation Considerations for "test."
//
//    The domain "test.", and any names falling within ".test.", are
//    special in the following ways:
// ```
lazy_static! {
    /// test. usage
    pub static ref TEST: ZoneUsage = ZoneUsage::test(Name::from_ascii("test.").unwrap().to_name());
}

// #[derive(Clone, Eq, PartialEq)]
// struct TrieName(Name);

// impl From<Name> for TrieName {
//     fn from(n: Name) -> Self {
//         TrieName(n)
//     }
// }

// impl TrieKey for TrieName {
//     /// Returns this name in byte form, reversed for searching from zone to local label
//     ///
//     /// # Panics
//     ///
//     /// This will panic on bad names
//     fn encode_bytes(&self) -> Vec<u8> {
//         let mut bytes = self.0.to_bytes().expect("bad name for trie");
//         bytes.reverse();
//         bytes
//     }
// }

#[derive(Eq, PartialEq)]
struct TrieNameRef<'n>(&'n BorrowedName<'n>);

impl<'n, N: DnsName> From<&'n N> for TrieNameRef<'n> {
    fn from(n: &'n N) -> Self {
        TrieNameRef(n.borrowed_name())
    }
}

impl<'n> TrieKey for TrieNameRef<'n> {
    /// Returns this name in byte form, reversed for searching from zone to local label
    ///
    /// # Panics
    ///
    /// This will panic on bad names
    fn encode_bytes(&self) -> Vec<u8> {
        let mut bytes = self.0.to_bytes().expect("bad name for trie");
        bytes.reverse();
        bytes
    }
}

/// A Trie of all reserved Zones
pub struct UsageTrie(Trie<TrieNameRef<'static>, &'static ZoneUsage>);

impl UsageTrie {
    #[allow(clippy::cognitive_complexity)]
    fn default() -> Self {
        let mut trie: Trie<TrieNameRef<'static>, &'static ZoneUsage> = Trie::new();

        assert!(trie.insert(DEFAULT.name().into(), &DEFAULT).is_none());

        assert!(trie
            .insert(IN_ADDR_ARPA_10.name().into(), &IN_ADDR_ARPA_10)
            .is_none());
        assert!(trie
            .insert(IN_ADDR_ARPA_172_16.name().into(), &IN_ADDR_ARPA_172_16)
            .is_none());
        assert!(trie
            .insert(IN_ADDR_ARPA_172_17.name().into(), &IN_ADDR_ARPA_172_17)
            .is_none());
        assert!(trie
            .insert(IN_ADDR_ARPA_172_18.name().into(), &IN_ADDR_ARPA_172_18)
            .is_none());
        assert!(trie
            .insert(IN_ADDR_ARPA_172_19.name().into(), &IN_ADDR_ARPA_172_19)
            .is_none());
        assert!(trie
            .insert(IN_ADDR_ARPA_172_20.name().into(), &IN_ADDR_ARPA_172_20)
            .is_none());
        assert!(trie
            .insert(IN_ADDR_ARPA_172_21.name().into(), &IN_ADDR_ARPA_172_21)
            .is_none());
        assert!(trie
            .insert(IN_ADDR_ARPA_172_22.name().into(), &IN_ADDR_ARPA_172_22)
            .is_none());
        assert!(trie
            .insert(IN_ADDR_ARPA_172_23.name().into(), &IN_ADDR_ARPA_172_23)
            .is_none());
        assert!(trie
            .insert(IN_ADDR_ARPA_172_24.name().into(), &IN_ADDR_ARPA_172_24)
            .is_none());
        assert!(trie
            .insert(IN_ADDR_ARPA_172_25.name().into(), &IN_ADDR_ARPA_172_25)
            .is_none());
        assert!(trie
            .insert(IN_ADDR_ARPA_172_26.name().into(), &IN_ADDR_ARPA_172_26)
            .is_none());
        assert!(trie
            .insert(IN_ADDR_ARPA_172_27.name().into(), &IN_ADDR_ARPA_172_27)
            .is_none());
        assert!(trie
            .insert(IN_ADDR_ARPA_172_28.name().into(), &IN_ADDR_ARPA_172_28)
            .is_none());
        assert!(trie
            .insert(IN_ADDR_ARPA_172_29.name().into(), &IN_ADDR_ARPA_172_29)
            .is_none());
        assert!(trie
            .insert(IN_ADDR_ARPA_172_30.name().into(), &IN_ADDR_ARPA_172_30)
            .is_none());
        assert!(trie
            .insert(IN_ADDR_ARPA_172_31.name().into(), &IN_ADDR_ARPA_172_31)
            .is_none());
        assert!(trie
            .insert(IN_ADDR_ARPA_192_168.name().into(), &IN_ADDR_ARPA_192_168)
            .is_none());

        assert!(trie.insert(TEST.name().into(), &TEST).is_none());

        assert!(trie.insert(LOCALHOST.name().into(), &LOCALHOST).is_none());
        assert!(trie
            .insert(IN_ADDR_ARPA_127.name().into(), &IN_ADDR_ARPA_127)
            .is_none());
        assert!(trie.insert(IP6_ARPA_1.name().into(), &IP6_ARPA_1).is_none());

        assert!(trie.insert(INVALID.name().into(), &INVALID).is_none());

        assert!(trie.insert(EXAMPLE.name().into(), &EXAMPLE).is_none());
        assert!(trie
            .insert(EXAMPLE_COM.name().into(), &EXAMPLE_COM)
            .is_none());
        assert!(trie
            .insert(EXAMPLE_NET.name().into(), &EXAMPLE_NET)
            .is_none());
        assert!(trie
            .insert(EXAMPLE_ORG.name().into(), &EXAMPLE_ORG)
            .is_none());

        UsageTrie(trie)
    }

    /// Fetches the ZoneUsage
    ///
    /// # Returns
    ///
    /// Matches the closest zone encapsulating `name`, at a minimum the default root zone usage will be returned
    pub fn get<N: DnsName>(&self, name: &N) -> &'static ZoneUsage {
        self.0
            .get_ancestor_value(&TrieNameRef::from(name))
            .expect("DEFAULT root ZoneUsage should have been returned")
    }
}

lazy_static! {
    /// All default usage mappings
    pub static ref USAGE: UsageTrie = UsageTrie::default();
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn test_root() {
        let name = Name::from_ascii("com.").unwrap();

        let usage = USAGE.get(&name);
        assert!(usage.is_root());
    }

    #[test]
    fn test_local_networks() {
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(9, 0, 0, 1))).name(),
            DEFAULT.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(10, 0, 0, 1))).name(),
            IN_ADDR_ARPA_10.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(11, 0, 0, 1))).name(),
            DEFAULT.name()
        );

        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(172, 16, 0, 0))).name(),
            IN_ADDR_ARPA_172_16.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(172, 17, 0, 0))).name(),
            IN_ADDR_ARPA_172_17.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(172, 18, 0, 0))).name(),
            IN_ADDR_ARPA_172_18.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(172, 19, 0, 0))).name(),
            IN_ADDR_ARPA_172_19.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(172, 20, 0, 0))).name(),
            IN_ADDR_ARPA_172_20.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(172, 21, 0, 0))).name(),
            IN_ADDR_ARPA_172_21.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(172, 22, 0, 0))).name(),
            IN_ADDR_ARPA_172_22.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(172, 23, 0, 0))).name(),
            IN_ADDR_ARPA_172_23.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(172, 24, 0, 0))).name(),
            IN_ADDR_ARPA_172_24.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(172, 25, 0, 0))).name(),
            IN_ADDR_ARPA_172_25.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(172, 26, 0, 0))).name(),
            IN_ADDR_ARPA_172_26.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(172, 27, 0, 0))).name(),
            IN_ADDR_ARPA_172_27.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(172, 28, 0, 0))).name(),
            IN_ADDR_ARPA_172_28.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(172, 29, 0, 0))).name(),
            IN_ADDR_ARPA_172_29.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(172, 30, 0, 0))).name(),
            IN_ADDR_ARPA_172_30.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(172, 31, 0, 0))).name(),
            IN_ADDR_ARPA_172_31.name()
        );

        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(172, 15, 0, 0))).name(),
            DEFAULT.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(172, 32, 0, 0))).name(),
            DEFAULT.name()
        );

        assert_eq!(
            USAGE
                .get(&Name::from(Ipv4Addr::new(192, 167, 255, 255)))
                .name(),
            DEFAULT.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(192, 168, 2, 3))).name(),
            IN_ADDR_ARPA_192_168.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(192, 169, 0, 0))).name(),
            DEFAULT.name()
        );
    }

    #[test]
    fn test_example() {
        let name = Name::from_ascii("example.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name(), EXAMPLE.name());

        let name = Name::from_ascii("example.com.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name(), EXAMPLE_COM.name());

        let name = Name::from_ascii("example.net.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name(), EXAMPLE_NET.name());

        let name = Name::from_ascii("example.org.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name(), EXAMPLE_ORG.name());

        let name = Name::from_ascii("www.example.org.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name(), EXAMPLE_ORG.name());
    }

    #[test]
    fn test_localhost() {
        let name = Name::from_ascii("localhost.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name(), LOCALHOST.name());

        let name = Name::from_ascii("this.localhost.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name(), LOCALHOST.name());

        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(127, 0, 0, 1))).name(),
            IN_ADDR_ARPA_127.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(127, 0, 0, 2))).name(),
            IN_ADDR_ARPA_127.name()
        );
        assert_eq!(
            USAGE.get(&Name::from(Ipv4Addr::new(127, 255, 0, 0))).name(),
            IN_ADDR_ARPA_127.name()
        );
        assert_eq!(
            USAGE
                .get(&Name::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
                .name(),
            IP6_ARPA_1.name()
        );
    }

    #[test]
    fn test_invalid() {
        let name = Name::from_ascii("invalid.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name(), INVALID.name());

        let name = Name::from_ascii("something.invalid.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name(), INVALID.name());
    }

    #[test]
    fn test_test() {
        let name = Name::from_ascii("test.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name(), TEST.name());

        let name = Name::from_ascii("foo.bar.test.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name(), TEST.name());
    }
}
