// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Reserved zone names.
//!
//! see [Special-Use Domain Names](https://tools.ietf.org/html/rfc6761), RFC 6761 February, 2013

use std::ops::Deref;

use radix_trie::Trie;

use rr::domain::{Label, Name};


lazy_static!{
    /// Default Name usage, everything is normal...
    pub static ref DEFAULT: ZoneUsage = ZoneUsage::default();
}

/// Reserved reverse IPs
///
/// [Special-Use Domain Names](https://tools.ietf.org/html/rfc6761), RFC 6761 February, 2013
///
/// ```text
/// 6.1.  Domain Name Reservation Considerations for Private Addresses
/// 
///    The private-address [RFC1918] reverse-mapping domains listed below,
///    and any names falling within those domains, are Special-Use Domain
///    Names:
/// 
///      10.in-addr.arpa.      21.172.in-addr.arpa.  26.172.in-addr.arpa.
///      16.172.in-addr.arpa.  22.172.in-addr.arpa.  27.172.in-addr.arpa.
///      17.172.in-addr.arpa.  30.172.in-addr.arpa.  28.172.in-addr.arpa.
///      18.172.in-addr.arpa.  23.172.in-addr.arpa.  29.172.in-addr.arpa.
///      19.172.in-addr.arpa.  24.172.in-addr.arpa.  31.172.in-addr.arpa.
///      20.172.in-addr.arpa.  25.172.in-addr.arpa.  168.192.in-addr.arpa.
/// ```
lazy_static! {
    static ref ARPA: Name = Name::from_ascii("arpa.").unwrap();
    static ref IN_ADDR_ARPA: Name = Name::from_ascii("in-addr").unwrap().append_domain(&*ARPA);
    static ref IP6_ARPA: Name = Name::from_ascii("ip6").unwrap().append_domain(&*ARPA);
    
    /// 10.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_10: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("10").unwrap().append_domain(&*IN_ADDR_ARPA));

    static ref IN_ADDR_ARPA_172: Name = Name::from_ascii("172").unwrap().append_domain(&*IN_ADDR_ARPA);
    
    /// 16.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_16: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("16").unwrap().append_domain(&*IN_ADDR_ARPA_172));
    /// 17.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_17: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("17").unwrap().append_domain(&*IN_ADDR_ARPA_172));
    /// 18.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_18: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("18").unwrap().append_domain(&*IN_ADDR_ARPA_172));
    /// 19.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_19: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("19").unwrap().append_domain(&*IN_ADDR_ARPA_172));
    /// 20.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_20: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("20").unwrap().append_domain(&*IN_ADDR_ARPA_172));
    /// 21.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_21: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("21").unwrap().append_domain(&*IN_ADDR_ARPA_172));
    /// 22.172.in-addr.arpa. usage    
    pub static ref IN_ADDR_ARPA_172_22: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("22").unwrap().append_domain(&*IN_ADDR_ARPA_172));
    /// 23.172.in-addr.arpa. usage    
    pub static ref IN_ADDR_ARPA_172_23: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("23").unwrap().append_domain(&*IN_ADDR_ARPA_172));
    /// 24.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_24: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("24").unwrap().append_domain(&*IN_ADDR_ARPA_172));
    /// 25.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_25: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("25").unwrap().append_domain(&*IN_ADDR_ARPA_172));
    /// 26.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_26: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("26").unwrap().append_domain(&*IN_ADDR_ARPA_172));
    /// 27.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_27: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("27").unwrap().append_domain(&*IN_ADDR_ARPA_172));
    /// 28.172.in-addr.arpa. usage    
    pub static ref IN_ADDR_ARPA_172_28: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("28").unwrap().append_domain(&*IN_ADDR_ARPA_172));
    /// 29.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_29: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("29").unwrap().append_domain(&*IN_ADDR_ARPA_172));
    /// 30.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_30: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("30").unwrap().append_domain(&*IN_ADDR_ARPA_172));
    /// 31.172.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_172_31: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("31").unwrap().append_domain(&*IN_ADDR_ARPA_172));

    /// 168.192.in-addr.arpa. usage
    pub static ref IN_ADDR_ARPA_192_168: ZoneUsage = ZoneUsage::reverse(Name::from_ascii("168.192").unwrap().append_domain(&*IN_ADDR_ARPA));
}

/// test.
///
/// [Special-Use Domain Names](https://tools.ietf.org/html/rfc6761), RFC 6761 February, 2013
///
/// ```text
/// 6.2.  Domain Name Reservation Considerations for "test."
/// 
///    The domain "test.", and any names falling within ".test.", are
///    special in the following ways:
/// ```
lazy_static! {
    /// test. usage
    pub static ref TEST: ZoneUsage = ZoneUsage::test(Name::from_ascii("test.").unwrap());
}

/// localhost.
///
/// [Special-Use Domain Names](https://tools.ietf.org/html/rfc6761), RFC 6761 February, 2013
///
/// ```text
/// 6.3.  Domain Name Reservation Considerations for "localhost."
/// 
///    The domain "localhost." and any names falling within ".localhost."
///    are special in the following ways:
/// ```
lazy_static! {
    /// localhost. usage
    pub static ref LOCALHOST: ZoneUsage = ZoneUsage::localhost(Name::from_ascii("localhost.").unwrap());

    /// 127.in-addr.arpa. usage; 127/8 is reserved for loopback
    pub static ref IN_ADDR_ARPA_127: ZoneUsage = ZoneUsage::localhost(Name::from_ascii("127").unwrap().append_domain(&*IN_ADDR_ARPA));

    /// 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa. usage; 1/128 is the only address in ipv6 loopback
    pub static ref IP6_ARPA_1: ZoneUsage = ZoneUsage::localhost(Name::from_ascii("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0").unwrap().append_domain(&*IP6_ARPA));
}

/// invalid.
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
lazy_static! {
    /// invalid. name usage
    pub static ref INVALID: ZoneUsage = ZoneUsage::invalid(Name::from_ascii("invalid.").unwrap());
}


/// example., example.com., example.net., and example.org. 
///
/// [Special-Use Domain Names](https://tools.ietf.org/html/rfc6761), RFC 6761 February, 2013
///
/// ```text
/// 6.5.  Domain Name Reservation Considerations for Example Domains
/// 
///    The domains "example.", "example.com.", "example.net.",
///    "example.org.", and any names falling within those domains, are
///    special in the following ways:
/// ```
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

/// Users:
///
///   Are human users expected to recognize these names as special and
///   use them differently?  In what way?
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UserUsage {
    /// Users are free to use these names as they would any other
    /// reverse-mapping names.  However, since there is no central
    /// authority responsible for use of private addresses, users SHOULD
    /// be aware that these names are likely to yield different results
    /// on different networks.
    Normal,
    /// Users are free to use localhost names as they would any other
    /// domain names.  Users may assume that IPv4 and IPv6 address
    /// queries for localhost names will always resolve to the respective
    /// IP loopback address.
    Loopback,
    /// Users are free to use "invalid" names as they would any other
    /// domain names.  Users MAY assume that queries for "invalid" names
    /// will always return NXDOMAIN responses.
    NxDomain,
}

/// Application Software:
///
///   Are writers of application software expected to make their
///   software recognize these names as special and treat them
///   differently?  In what way?  (For example, if a human user enters
///   such a name, should the application software reject it with an
///   error message?)
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AppUsage {
    /// Application software SHOULD NOT recognize these names as special,
    /// and SHOULD use these names as they would other reverse-mapping
    /// names.
    ///
    /// Application software SHOULD NOT recognize test names as special,
    /// and SHOULD use test names as they would other domain names.
    ///
    /// Application software SHOULD NOT recognize example names as
    /// special and SHOULD use example names as they would other domain
    /// names.
    Normal,

    /// Application software MAY recognize localhost names as special, or
    /// MAY pass them to name resolution APIs as they would for other
    /// domain names.
    Loopback,


    /// Application software MAY recognize "invalid" names as special or
    /// MAY pass them to name resolution APIs as they would for other
    /// domain names.
    NxDomain,
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

    /// Name resolution APIs and libraries SHOULD recognize "invalid"
    /// names as special and SHOULD always return immediate negative
    /// responses.  Name resolution APIs SHOULD NOT send queries for
    /// "invalid" names to their configured caching DNS server(s).
    NxDomain,
}

/// Caching DNS Servers:
///
///   Are developers of caching domain name servers expected to make
///   their implementations recognize these names as special and treat
///   them differently?  If so, how?
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CacheUsage{
    /// Caching DNS servers SHOULD recognize these names as special and
    /// SHOULD NOT, by default, attempt to look up NS records for them,
    /// or otherwise query authoritative DNS servers in an attempt to
    /// resolve these names.  Instead, caching DNS servers SHOULD, by
    /// default, generate immediate (positive or negative) responses for
    /// all such queries.  This is to avoid unnecessary load on the root
    /// name servers and other name servers.  Caching DNS servers SHOULD
    /// offer a configuration option (disabled by default) to enable
    /// upstream resolution of such names, for use in private networks
    /// where private-address reverse-mapping names are known to be
    /// handled by an authoritative DNS server in said private network.
    NonRecursive,

    /// Caching DNS servers SHOULD recognize "invalid" names as special
    /// and SHOULD NOT attempt to look up NS records for them, or
    /// otherwise query authoritative DNS servers in an attempt to
    /// resolve "invalid" names.  Instead, caching DNS servers SHOULD
    /// generate immediate NXDOMAIN responses for all such queries.  This
    /// is to avoid unnecessary load on the root name servers and other
    /// name servers.
    NxDomain,

    /// Caching DNS servers SHOULD recognize localhost names as special
    /// and SHOULD NOT attempt to look up NS records for them, or
    /// otherwise query authoritative DNS servers in an attempt to
    /// resolve localhost names.  Instead, caching DNS servers SHOULD,
    /// for all such address queries, generate an immediate positive
    /// response giving the IP loopback address, and for all other query
    /// types, generate an immediate negative response.  This is to avoid
    /// unnecessary load on the root name servers and other name servers.
    Loopback,

    /// Caching DNS servers SHOULD NOT recognize example names as special
    /// and SHOULD resolve them normally.
    Normal,
}

/// Authoritative DNS Servers:
///
///   Are developers of authoritative domain name servers expected to
///   make their implementations recognize these names as special and
///   treat them differently?  If so, how?
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AuthUsage{
    /// Authoritative DNS servers SHOULD recognize these names as special
    /// and SHOULD, by default, generate immediate negative responses for
    /// all such queries, unless explicitly configured by the
    /// administrator to give positive answers for private-address
    /// reverse-mapping names.
    Local,

    /// Authoritative DNS servers SHOULD recognize these names as special
    /// and SHOULD, by default, generate immediate negative responses for
    /// all such queries, unless explicitly configured by the
    /// administrator to give positive answers for private-address
    /// reverse-mapping names.
    NxDomain,

    /// Authoritative DNS servers SHOULD recognize localhost names as
    /// special and handle them as described above for caching DNS
    /// servers.
    Loopback,

    /// Authoritative DNS servers SHOULD NOT recognize example names as
    /// special.
    Normal,
}

/// DNS Server Operators:
///
///   Does this reserved Special-Use Domain Name have any potential
///   impact on DNS server operators?  If they try to configure their
///   authoritative DNS server as authoritative for this reserved name,
///   will compliant name server software reject it as invalid?  Do DNS
///   server operators need to know about that and understand why?
///   Even if the name server software doesn't prevent them from using
///   this reserved name, are there other ways that it may not work as
///  expected, of which the DNS server operator should be aware?
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OpUsage {
    /// DNS server operators SHOULD, if they are using private addresses,
    /// configure their authoritative DNS servers to act as authoritative
    /// for these names.
    ///
    /// DNS server operators SHOULD, if they are using test names,
    /// configure their authoritative DNS servers to act as authoritative
    /// for test names.
    Normal,

    /// DNS server operators SHOULD be aware that the effective RDATA for
    /// localhost names is defined by protocol specification and cannot
    /// be modified by local configuration.
    Loopback,

    /// DNS server operators SHOULD be aware that the effective RDATA for
    /// "invalid" names is defined by protocol specification to be
    /// nonexistent and cannot be modified by local configuration.
    NxDomain,
}

/// DNS Registries/Registrars:
///
///   How should DNS Registries/Registrars treat requests to register
///   this reserved domain name?  Should such requests be denied?
///   Should such requests be allowed, but only to a specially-
///   designated entity?  (For example, the name "www.example.org" is
///   reserved for documentation examples and is not available for
///   registration; however, the name is in fact registered; and there
///   is even a web site at that name, which states circularly that the
///   name is reserved for use in documentation and cannot be
///   registered!)
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RegistryUsage{
    /// Stanard checks apply
    Normal,

    /// DNS Registries/Registrars MUST NOT grant requests to register
    /// test names in the normal way to any person or entity.  Test names
    /// are reserved for use in private networks and fall outside the set
    /// of names available for allocation by registries/registrars.
    /// Attempting to allocate a test name as if it were a normal DNS
    /// domain name will probably not work as desired, for reasons 4, 5,
    /// and 6 above.
    ///
    /// DNS Registries/Registrars MUST NOT grant requests to register
    /// localhost names in the normal way to any person or entity.
    /// Localhost names are defined by protocol specification and fall
    /// outside the set of names available for allocation by registries/
    /// registrars.  Attempting to allocate a localhost name as if it
    /// were a normal DNS domain name will probably not work as desired,
    /// for reasons 2, 3, 4, and 5 above.
    ///
    /// DNS Registries/Registrars MUST NOT grant requests to register
    /// "invalid" names in the normal way to any person or entity.  These
    /// "invalid" names are defined by protocol specification to be
    /// nonexistent, and they fall outside the set of names available for
    /// allocation by registries/registrars.  Attempting to allocate a
    /// "invalid" name as if it were a normal DNS domain name will
    /// probably not work as desired, for reasons 2, 3, 4, and 5 above.
    ///
    /// DNS Registries/Registrars MUST NOT grant requests to register
    /// example names in the normal way to any person or entity.  All
    /// example names are registered in perpetuity to IANA:
    Reserved,
}

/// ZoneUsage represents information about how a name falling in a given zone should be treated
pub struct ZoneUsage {
    name: Name,
    user: UserUsage,
    app: AppUsage,
    resolver: ResolverUsage,
    cache: CacheUsage,
    auth: AuthUsage,
    op: OpUsage,
    registry: RegistryUsage,
}

impl ZoneUsage {
    fn new(name: Name, user: UserUsage, app: AppUsage, resolver: ResolverUsage, cache: CacheUsage, auth: AuthUsage, op: OpUsage, registry: RegistryUsage) -> Self {
        ZoneUsage {name, user, app, resolver, cache, auth, op, registry}
    }

    fn default() -> Self {
        Self::new(Name::root(), UserUsage::Normal, AppUsage::Normal, ResolverUsage::Normal, CacheUsage::Normal, AuthUsage::Normal, OpUsage::Normal, RegistryUsage::Normal)
    }

    fn reverse(name: Name) -> Self {
        Self::new(name, UserUsage::Normal, AppUsage::Normal, ResolverUsage::Normal, CacheUsage::NonRecursive, AuthUsage::Local, OpUsage::Normal, RegistryUsage::Reserved)
    }

    fn test(name: Name) -> Self {
        Self::new(name, UserUsage::Normal, AppUsage::Normal, ResolverUsage::Normal, CacheUsage::NonRecursive, AuthUsage::Local, OpUsage::Normal, RegistryUsage::Reserved)
    }

    fn localhost(name: Name) -> Self {
        Self::new(name, UserUsage::Loopback, AppUsage::Loopback, ResolverUsage::Loopback, CacheUsage::Loopback, AuthUsage::Loopback, OpUsage::Loopback, RegistryUsage::Reserved)
    }

    fn invalid(name: Name) -> Self {
        Self::new(name, UserUsage::NxDomain, AppUsage::NxDomain, ResolverUsage::NxDomain, CacheUsage::NxDomain, AuthUsage::NxDomain, OpUsage::NxDomain, RegistryUsage::Reserved)
    }

    fn example(name: Name) -> Self {
        Self::new(name, UserUsage::Normal, AppUsage::Normal, ResolverUsage::Normal, CacheUsage::Normal, AuthUsage::Normal, OpUsage::Normal, RegistryUsage::Reserved)
    }

    /// Returnes the UserUsage of this zone
    pub fn user(&self) -> UserUsage {
        self.user
    }

    /// Returnes the AppUsage of this zone
    pub fn app(&self) -> AppUsage {
        self.app
    }

    /// Returnes the ResolverUsage of this zone
    pub fn resolver(&self) -> ResolverUsage {
        self.resolver
    }

    /// Returnes the CacheUsage of this zone
    pub fn cache(&self) -> CacheUsage {
        self.cache
    }

    /// Returnes the AuthUsage of this zone
    pub fn auth(&self) -> AuthUsage {
        self.auth
    }

    /// Returnes the OpUsage of this zone
    pub fn op(&self) -> OpUsage {
        self.op
    }

    /// Returnes the RegistryUsage of this zone
    pub fn registry(&self) -> RegistryUsage {
        self.registry
    }
}

impl Deref for ZoneUsage {
    type Target = Name;

    fn deref(&self) -> &Self::Target {
        &self.name
    }
}

/// A Trie of all reserved Zones
pub struct UsageTrie(Trie<Name, &'static ZoneUsage>);

impl UsageTrie {
    fn default() -> Self {
        let mut trie: Trie<Name, &'static ZoneUsage> = Trie::new();

        assert!(trie.insert(DEFAULT.clone(), &DEFAULT).is_none());
        
        assert!(trie.insert(IN_ADDR_ARPA_10.clone(), &IN_ADDR_ARPA_10).is_none());
        assert!(trie.insert(IN_ADDR_ARPA_172_16.clone(), &IN_ADDR_ARPA_172_16).is_none());
        assert!(trie.insert(IN_ADDR_ARPA_172_17.clone(), &IN_ADDR_ARPA_172_17).is_none());
        assert!(trie.insert(IN_ADDR_ARPA_172_18.clone(), &IN_ADDR_ARPA_172_18).is_none());
        assert!(trie.insert(IN_ADDR_ARPA_172_19.clone(), &IN_ADDR_ARPA_172_19).is_none());
        assert!(trie.insert(IN_ADDR_ARPA_172_20.clone(), &IN_ADDR_ARPA_172_20).is_none());
        assert!(trie.insert(IN_ADDR_ARPA_172_21.clone(), &IN_ADDR_ARPA_172_21).is_none());
        assert!(trie.insert(IN_ADDR_ARPA_172_22.clone(), &IN_ADDR_ARPA_172_22).is_none());
        assert!(trie.insert(IN_ADDR_ARPA_172_23.clone(), &IN_ADDR_ARPA_172_23).is_none());
        assert!(trie.insert(IN_ADDR_ARPA_172_24.clone(), &IN_ADDR_ARPA_172_24).is_none());
        assert!(trie.insert(IN_ADDR_ARPA_172_25.clone(), &IN_ADDR_ARPA_172_25).is_none());
        assert!(trie.insert(IN_ADDR_ARPA_172_26.clone(), &IN_ADDR_ARPA_172_26).is_none());
        assert!(trie.insert(IN_ADDR_ARPA_172_27.clone(), &IN_ADDR_ARPA_172_27).is_none());
        assert!(trie.insert(IN_ADDR_ARPA_172_28.clone(), &IN_ADDR_ARPA_172_28).is_none());
        assert!(trie.insert(IN_ADDR_ARPA_172_29.clone(), &IN_ADDR_ARPA_172_29).is_none());
        assert!(trie.insert(IN_ADDR_ARPA_172_30.clone(), &IN_ADDR_ARPA_172_30).is_none());
        assert!(trie.insert(IN_ADDR_ARPA_172_31.clone(), &IN_ADDR_ARPA_172_31).is_none());
        assert!(trie.insert(IN_ADDR_ARPA_192_168.clone(), &IN_ADDR_ARPA_192_168).is_none());

        assert!(trie.insert(TEST.clone(), &TEST).is_none());
        
        assert!(trie.insert(LOCALHOST.clone(), &LOCALHOST).is_none());
        assert!(trie.insert(IN_ADDR_ARPA_127.clone(), &IN_ADDR_ARPA_127).is_none());
        assert!(trie.insert(IP6_ARPA_1.clone(), &IP6_ARPA_1).is_none());
        
        assert!(trie.insert(INVALID.clone(), &INVALID).is_none());

        assert!(trie.insert(EXAMPLE.clone(), &EXAMPLE).is_none());
        assert!(trie.insert(EXAMPLE_COM.clone(), &EXAMPLE_COM).is_none());
        assert!(trie.insert(EXAMPLE_NET.clone(), &EXAMPLE_NET).is_none());
        assert!(trie.insert(EXAMPLE_ORG.clone(), &EXAMPLE_ORG).is_none());
        
        UsageTrie(trie)
    }

    /// Fetches the ZoneUsage
    ///
    /// # Returns
    ///
    /// Matches the closest zone encapsulating `name`, at a minimum the default root zone usage will be returned
    pub fn get(&self, name: &Name) -> &'static ZoneUsage {
        self.0.get_ancestor_value(name).expect("DEFAULT root ZoneUsage should have been returned")
    }
}

lazy_static!{
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
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(9,0,0,1))).name, DEFAULT.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(10,0,0,1))).name, IN_ADDR_ARPA_10.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(11,0,0,1))).name, DEFAULT.name);

        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(172,16,0,0))).name, IN_ADDR_ARPA_172_16.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(172,17,0,0))).name, IN_ADDR_ARPA_172_17.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(172,18,0,0))).name, IN_ADDR_ARPA_172_18.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(172,19,0,0))).name, IN_ADDR_ARPA_172_19.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(172,20,0,0))).name, IN_ADDR_ARPA_172_20.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(172,21,0,0))).name, IN_ADDR_ARPA_172_21.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(172,22,0,0))).name, IN_ADDR_ARPA_172_22.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(172,23,0,0))).name, IN_ADDR_ARPA_172_23.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(172,24,0,0))).name, IN_ADDR_ARPA_172_24.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(172,25,0,0))).name, IN_ADDR_ARPA_172_25.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(172,26,0,0))).name, IN_ADDR_ARPA_172_26.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(172,27,0,0))).name, IN_ADDR_ARPA_172_27.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(172,28,0,0))).name, IN_ADDR_ARPA_172_28.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(172,29,0,0))).name, IN_ADDR_ARPA_172_29.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(172,30,0,0))).name, IN_ADDR_ARPA_172_30.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(172,31,0,0))).name, IN_ADDR_ARPA_172_31.name);

        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(172,15,0,0))).name, DEFAULT.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(172,32,0,0))).name, DEFAULT.name);
        
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(192,167,255,255))).name, DEFAULT.name); 
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(192,168,2,3))).name, IN_ADDR_ARPA_192_168.name); 
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(192,169,0,0))).name, DEFAULT.name); 
    }

    #[test]
    fn test_example() {
        let name = Name::from_ascii("example.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name, EXAMPLE.name);

        let name = Name::from_ascii("example.com.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name, EXAMPLE_COM.name);

        let name = Name::from_ascii("example.net.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name, EXAMPLE_NET.name);

        let name = Name::from_ascii("example.org.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name, EXAMPLE_ORG.name);

        let name = Name::from_ascii("www.example.org.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name, EXAMPLE_ORG.name);
    }

    #[test]
    fn test_localhost() {
        let name = Name::from_ascii("localhost.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name, LOCALHOST.name);

        let name = Name::from_ascii("this.localhost.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name, LOCALHOST.name);
    
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(127,0,0,1))).name, IN_ADDR_ARPA_127.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(127,0,0,2))).name, IN_ADDR_ARPA_127.name);
        assert_eq!(USAGE.get(&Name::from(Ipv4Addr::new(127,255,0,0))).name, IN_ADDR_ARPA_127.name);
        assert_eq!(USAGE.get(&Name::from(Ipv6Addr::new(0,0,0,0,0,0,0,1))).name, IP6_ARPA_1.name);
    }

    #[test]
    fn test_invalid() {
        let name = Name::from_ascii("invalid.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name, INVALID.name);

        let name = Name::from_ascii("something.invalid.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name, INVALID.name);
    }

    #[test]
    fn test_test() {
        let name = Name::from_ascii("test.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name, TEST.name);

        let name = Name::from_ascii("foo.bar.test.").unwrap();

        let usage = USAGE.get(&name);
        assert_eq!(usage.name, TEST.name);
    }
}