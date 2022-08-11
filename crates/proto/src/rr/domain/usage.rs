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

use lazy_static::lazy_static;

use crate::rr::domain::Name;

lazy_static! {
    /// Default Name usage, everything is normal...
    pub static ref DEFAULT: ZoneUsage = ZoneUsage::default();
}

lazy_static! {
    static ref ARPA: Name = Name::from_ascii("arpa.").unwrap();
    /// zone for ipv4 reverse addresses
    pub static ref IN_ADDR_ARPA: Name = Name::from_ascii("in-addr").unwrap().append_domain(&ARPA).unwrap();
    /// zone for ipv6 reverse addresses
    pub static ref IP6_ARPA: Name = Name::from_ascii("ip6").unwrap().append_domain(&ARPA).unwrap();
}

lazy_static! {
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

    /// localhost. usage
    pub static ref LOCALHOST: ZoneUsage = ZoneUsage::localhost(Name::from_ascii("localhost.").unwrap());

    /// 127.in-addr.arpa. usage; 127/8 is reserved for loopback
    pub static ref IN_ADDR_ARPA_127: ZoneUsage = ZoneUsage::localhost(Name::from_ascii("127").unwrap().append_domain(&IN_ADDR_ARPA).unwrap());

    /// 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa. usage; 1/128 is the only address in ipv6 loopback
    pub static ref IP6_ARPA_1: ZoneUsage = ZoneUsage::localhost(Name::from_ascii("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0").unwrap().append_domain(&IP6_ARPA).unwrap());
}

lazy_static! {
    /// .local.
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

    /// localhost. usage
    pub static ref LOCAL: ZoneUsage = ZoneUsage::local(Name::from_ascii("local.").unwrap());

    // RFC 6762                      Multicast DNS                February 2013

    // Any DNS query for a name ending with "254.169.in-addr.arpa." MUST
    //  be sent to the mDNS IPv4 link-local multicast address 224.0.0.251
    //  or the mDNS IPv6 multicast address FF02::FB.  Since names under
    //  this domain correspond to IPv4 link-local addresses, it is logical
    //  that the local link is the best place to find information
    //  pertaining to those names.
    //
    //  Likewise, any DNS query for a name within the reverse mapping
    //  domains for IPv6 link-local addresses ("8.e.f.ip6.arpa.",
    //  "9.e.f.ip6.arpa.", "a.e.f.ip6.arpa.", and "b.e.f.ip6.arpa.") MUST
    //  be sent to the mDNS IPv6 link-local multicast address FF02::FB or
    //  the mDNS IPv4 link-local multicast address 224.0.0.251.

    /// 254.169.in-addr.arpa. usage link-local, i.e. mDNS
    pub static ref IN_ADDR_ARPA_169_254: ZoneUsage = ZoneUsage::local(Name::from_ascii("254.169").unwrap().append_domain(&IN_ADDR_ARPA).unwrap());

    /// 254.169.in-addr.arpa. usage link-local, i.e. mDNS
    pub static ref IP6_ARPA_FE_8: ZoneUsage = ZoneUsage::local(Name::from_ascii("8.e.f").unwrap().append_domain(&IP6_ARPA).unwrap());
    /// 254.169.in-addr.arpa. usage link-local, i.e. mDNS
    pub static ref IP6_ARPA_FE_9: ZoneUsage = ZoneUsage::local(Name::from_ascii("9.e.f").unwrap().append_domain(&IP6_ARPA).unwrap());
    /// 254.169.in-addr.arpa. usage link-local, i.e. mDNS
    pub static ref IP6_ARPA_FE_B: ZoneUsage = ZoneUsage::local(Name::from_ascii("b.e.f").unwrap().append_domain(&IP6_ARPA).unwrap());
}

lazy_static! {
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

    /// invalid. name usage
    pub static ref INVALID: ZoneUsage = ZoneUsage::invalid(Name::from_ascii("invalid.").unwrap());
}

lazy_static! {
    /// invalid.
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

    /// onion. name usage
    pub static ref ONION: ZoneUsage = ZoneUsage {
        user: UserUsage::Normal, // the domain is special, but this is what seems to match the most
        app: AppUsage::Normal, // the domain is special, but this is what seems to match the most
        .. ZoneUsage::invalid(Name::from_ascii("onion.").unwrap())
    };
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

    /// Multi-cast link-local usage
    LinkLocal,

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

    /// Link local, generally for mDNS
    LinkLocal,

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

/// Caching DNS Servers:
///
///   Are developers of caching domain name servers expected to make
///   their implementations recognize these names as special and treat
///   them differently?  If so, how?
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CacheUsage {
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
pub enum AuthUsage {
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
pub enum RegistryUsage {
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
    /// Constructs a new ZoneUsage with the associated values
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: Name,
        user: UserUsage,
        app: AppUsage,
        resolver: ResolverUsage,
        cache: CacheUsage,
        auth: AuthUsage,
        op: OpUsage,
        registry: RegistryUsage,
    ) -> Self {
        Self {
            name,
            user,
            app,
            resolver,
            cache,
            auth,
            op,
            registry,
        }
    }

    /// Constructs a new Default, with all no restrictions
    pub fn default() -> Self {
        Self::new(
            Name::root(),
            UserUsage::Normal,
            AppUsage::Normal,
            ResolverUsage::Normal,
            CacheUsage::Normal,
            AuthUsage::Normal,
            OpUsage::Normal,
            RegistryUsage::Normal,
        )
    }

    /// Restrictions for reverse zones
    pub fn reverse(name: Name) -> Self {
        Self::new(
            name,
            UserUsage::Normal,
            AppUsage::Normal,
            ResolverUsage::Normal,
            CacheUsage::NonRecursive,
            AuthUsage::Local,
            OpUsage::Normal,
            RegistryUsage::Reserved,
        )
    }

    /// Restrictions for the .test. zone
    pub fn test(name: Name) -> Self {
        Self::new(
            name,
            UserUsage::Normal,
            AppUsage::Normal,
            ResolverUsage::Normal,
            CacheUsage::NonRecursive,
            AuthUsage::Local,
            OpUsage::Normal,
            RegistryUsage::Reserved,
        )
    }

    /// Restrictions for the .localhost. zone
    pub fn localhost(name: Name) -> Self {
        Self::new(
            name,
            UserUsage::Loopback,
            AppUsage::Loopback,
            ResolverUsage::Loopback,
            CacheUsage::Loopback,
            AuthUsage::Loopback,
            OpUsage::Loopback,
            RegistryUsage::Reserved,
        )
    }

    /// Restrictions for the .local. zone
    pub fn local(name: Name) -> Self {
        Self::new(
            name,
            UserUsage::LinkLocal,
            AppUsage::LinkLocal,
            ResolverUsage::LinkLocal,
            CacheUsage::Normal,
            AuthUsage::Local,
            OpUsage::Normal,
            RegistryUsage::Reserved,
        )
    }

    /// Restrictions for the .invalid. zone
    pub fn invalid(name: Name) -> Self {
        Self::new(
            name,
            UserUsage::NxDomain,
            AppUsage::NxDomain,
            ResolverUsage::NxDomain,
            CacheUsage::NxDomain,
            AuthUsage::NxDomain,
            OpUsage::NxDomain,
            RegistryUsage::Reserved,
        )
    }

    /// Restrictions for the .example. zone
    pub fn example(name: Name) -> Self {
        Self::new(
            name,
            UserUsage::Normal,
            AppUsage::Normal,
            ResolverUsage::Normal,
            CacheUsage::Normal,
            AuthUsage::Normal,
            OpUsage::Normal,
            RegistryUsage::Reserved,
        )
    }

    /// A reference to this zone name
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Returns the UserUsage of this zone
    pub fn user(&self) -> UserUsage {
        self.user
    }

    /// Returns the AppUsage of this zone
    pub fn app(&self) -> AppUsage {
        self.app
    }

    /// Returns the ResolverUsage of this zone
    pub fn resolver(&self) -> ResolverUsage {
        self.resolver
    }

    /// Returns the CacheUsage of this zone
    pub fn cache(&self) -> CacheUsage {
        self.cache
    }

    /// Returns the AuthUsage of this zone
    pub fn auth(&self) -> AuthUsage {
        self.auth
    }

    /// Returns the OpUsage of this zone
    pub fn op(&self) -> OpUsage {
        self.op
    }

    /// Returns the RegistryUsage of this zone
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
