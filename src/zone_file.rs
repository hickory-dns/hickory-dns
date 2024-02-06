//! BIND-style zone file
//!
//! Note that
//! - the `@` syntax is not used to avoid relying on the order of the entries
//! - relative domain names are not used; all domain names must be in fully-qualified form

use core::fmt;
use std::net::Ipv4Addr;

use crate::FQDN;

pub struct ZoneFile<'a> {
    pub origin: FQDN<'a>,
    pub ttl: u32,
    pub soa: SOA<'a>,
    pub entries: Vec<Entry<'a>>,
}

impl<'a> ZoneFile<'a> {
    /// Convenience constructor that uses "reasonable" defaults
    pub fn new(origin: FQDN<'a>, soa: SOA<'a>) -> Self {
        Self {
            origin,
            ttl: 1800,
            soa,
            entries: Vec::new(),
        }
    }

    /// Appends an entry
    pub fn entry(&mut self, entry: impl Into<Entry<'a>>) {
        self.entries.push(entry.into())
    }

    /// Appends a NS + A entry pair
    pub fn referral(&mut self, zone: FQDN<'a>, nameserver: FQDN<'a>, ipv4_addr: Ipv4Addr) {
        self.entry(NS {
            zone: zone.clone(),
            nameserver: nameserver.clone(),
        });
        self.entry(A {
            fqdn: nameserver,
            ipv4_addr,
        });
    }
}

impl fmt::Display for ZoneFile<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            origin,
            ttl,
            soa,
            entries,
        } = self;

        writeln!(f, "$ORIGIN {origin}")?;
        writeln!(f, "$TTL {ttl}")?;
        writeln!(f, "{soa}")?;

        for entry in entries {
            writeln!(f, "{entry}")?;
        }

        Ok(())
    }
}

pub struct Root<'a> {
    pub ipv4_addr: Ipv4Addr,
    pub ns: FQDN<'a>,
    pub ttl: u32,
}

impl<'a> Root<'a> {
    /// Convenience constructor that uses "reasonable" defaults
    pub fn new(ns: FQDN<'a>, ipv4_addr: Ipv4Addr) -> Self {
        Self {
            ipv4_addr,
            ns,
            ttl: 3600000, // 1000 hours
        }
    }
}

impl fmt::Display for Root<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { ipv4_addr, ns, ttl } = self;

        writeln!(f, ".\t{ttl}\tNS\t{ns}")?;
        write!(f, "{ns}\t{ttl}\tA\t{ipv4_addr}")
    }
}

pub enum Entry<'a> {
    A(A<'a>),
    NS(NS<'a>),
}

impl<'a> From<A<'a>> for Entry<'a> {
    fn from(v: A<'a>) -> Self {
        Self::A(v)
    }
}

impl<'a> From<NS<'a>> for Entry<'a> {
    fn from(v: NS<'a>) -> Self {
        Self::NS(v)
    }
}

impl fmt::Display for Entry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Entry::A(a) => a.fmt(f),
            Entry::NS(ns) => ns.fmt(f),
        }
    }
}

#[derive(Clone)]
pub struct A<'a> {
    pub fqdn: FQDN<'a>,
    pub ipv4_addr: Ipv4Addr,
}

impl fmt::Display for A<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { fqdn, ipv4_addr } = self;

        write!(f, "{fqdn}\tIN\tA\t{ipv4_addr}")
    }
}

pub struct NS<'a> {
    pub zone: FQDN<'a>,
    pub nameserver: FQDN<'a>,
}

impl fmt::Display for NS<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            zone,
            nameserver: ns,
        } = self;

        write!(f, "{zone}\tIN\tNS\t{ns}")
    }
}

pub struct SOA<'a> {
    pub zone: FQDN<'a>,
    pub nameserver: FQDN<'a>,
    pub admin: FQDN<'a>,
    pub settings: SoaSettings,
}

impl fmt::Display for SOA<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            zone,
            nameserver: ns,
            admin,
            settings,
        } = self;

        write!(f, "{zone}\tIN\tSOA\t{ns}\t{admin}\t{settings}")
    }
}

pub struct SoaSettings {
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

impl Default for SoaSettings {
    fn default() -> Self {
        Self {
            serial: 2024010101,
            refresh: 1800,  // 30 minutes
            retry: 900,     // 15 minutes
            expire: 604800, // 1 week
            minimum: 86400, // 1 day
        }
    }
}

impl fmt::Display for SoaSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } = self;

        write!(f, "( {serial} {refresh} {retry} {expire} {minimum} )")
    }
}

#[cfg(test)]
mod tests {
    use crate::Result;

    use super::*;

    #[test]
    fn a_to_string() -> Result<()> {
        let expected = "e.gtld-servers.net.	IN	A	192.12.94.30";
        let a = example_a()?;
        assert_eq!(expected, a.to_string());

        Ok(())
    }

    #[test]
    fn ns_to_string() -> Result<()> {
        let expected = "com.	IN	NS	e.gtld-servers.net.";
        let ns = example_ns()?;
        assert_eq!(expected, ns.to_string());

        Ok(())
    }

    #[test]
    fn root_to_string() -> Result<()> {
        let expected = ".	3600000	NS	a.root-servers.net.
a.root-servers.net.	3600000	A	198.41.0.4";
        let root = Root::new(FQDN("a.root-servers.net.")?, Ipv4Addr::new(198, 41, 0, 4));
        assert_eq!(expected, root.to_string());
        Ok(())
    }

    #[test]
    fn soa_to_string() -> Result<()> {
        let expected =
            ".	IN	SOA	a.root-servers.net.	nstld.verisign-grs.com.	( 2024010101 1800 900 604800 86400 )";
        let soa = example_soa()?;
        assert_eq!(expected, soa.to_string());

        Ok(())
    }

    #[test]
    fn zone_file_to_string() -> Result<()> {
        let expected = "$ORIGIN .
$TTL 1800
.	IN	SOA	a.root-servers.net.	nstld.verisign-grs.com.	( 2024010101 1800 900 604800 86400 )
com.	IN	NS	e.gtld-servers.net.
e.gtld-servers.net.	IN	A	192.12.94.30
";
        let mut zone = ZoneFile::new(FQDN::ROOT, example_soa()?);
        zone.entry(example_ns()?);
        zone.entry(example_a()?);

        assert_eq!(expected, zone.to_string());

        Ok(())
    }

    fn example_a() -> Result<A<'static>> {
        Ok(A {
            fqdn: FQDN("e.gtld-servers.net.")?,
            ipv4_addr: Ipv4Addr::new(192, 12, 94, 30),
        })
    }

    fn example_ns() -> Result<NS<'static>> {
        Ok(NS {
            zone: FQDN::COM,
            nameserver: FQDN("e.gtld-servers.net.")?,
        })
    }

    fn example_soa() -> Result<SOA<'static>> {
        Ok(SOA {
            zone: FQDN::ROOT,
            nameserver: FQDN("a.root-servers.net.")?,
            admin: FQDN("nstld.verisign-grs.com.")?,
            settings: SoaSettings::default(),
        })
    }
}
