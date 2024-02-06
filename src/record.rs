//! DNS records in BIND syntax
//!
//! Note that the `@` syntax is not used to avoid relying on the order of the records

use core::fmt;
use std::net::Ipv4Addr;

use crate::FQDN;

pub struct ZoneFile<'a> {
    pub origin: FQDN<'a>,
    pub ttl: u32,
    pub soa: Soa<'a>,
    pub records: Vec<Record<'a>>,
}

impl<'a> ZoneFile<'a> {
    /// Convenience constructor that uses "reasonable" defaults
    pub fn new(origin: FQDN<'a>, soa: Soa<'a>) -> Self {
        Self {
            origin,
            ttl: 1800,
            soa,
            records: Vec::new(),
        }
    }

    /// Appends a record
    pub fn record(&mut self, record: impl Into<Record<'a>>) {
        self.records.push(record.into())
    }

    /// Appends a NS + A record pair
    pub fn referral(&mut self, referral: &Referral<'a>) {
        let Referral {
            domain,
            ipv4_addr,
            ns,
        } = referral;

        self.record(Ns {
            domain: domain.clone(),
            ns: ns.clone(),
        });
        self.record(A {
            domain: ns.clone(),
            ipv4_addr: *ipv4_addr,
        });
    }
}

impl fmt::Display for ZoneFile<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            origin,
            ttl,
            soa,
            records,
        } = self;

        writeln!(f, "$ORIGIN {origin}")?;
        writeln!(f, "$TTL {ttl}")?;
        writeln!(f, "{soa}")?;

        for record in records {
            writeln!(f, "{record}")?;
        }

        Ok(())
    }
}

pub struct Referral<'a> {
    pub domain: FQDN<'a>,
    pub ipv4_addr: Ipv4Addr,
    pub ns: FQDN<'a>,
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

pub enum Record<'a> {
    A(A<'a>),
    Ns(Ns<'a>),
}

impl<'a> From<A<'a>> for Record<'a> {
    fn from(v: A<'a>) -> Self {
        Self::A(v)
    }
}

impl<'a> From<Ns<'a>> for Record<'a> {
    fn from(v: Ns<'a>) -> Self {
        Self::Ns(v)
    }
}

impl fmt::Display for Record<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Record::A(a) => a.fmt(f),
            Record::Ns(ns) => ns.fmt(f),
        }
    }
}

#[derive(Clone)]
pub struct A<'a> {
    pub domain: FQDN<'a>,
    pub ipv4_addr: Ipv4Addr,
}

impl fmt::Display for A<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { domain, ipv4_addr } = self;

        write!(f, "{domain}\tIN\tA\t{ipv4_addr}")
    }
}

pub struct Ns<'a> {
    pub domain: FQDN<'a>,
    pub ns: FQDN<'a>,
}

impl fmt::Display for Ns<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { domain, ns } = self;

        write!(f, "{domain}\tIN\tNS\t{ns}")
    }
}

pub struct Soa<'a> {
    pub domain: FQDN<'a>,
    pub ns: FQDN<'a>,
    pub admin: FQDN<'a>,
    pub settings: SoaSettings,
}

impl fmt::Display for Soa<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            domain,
            ns,
            admin,
            settings,
        } = self;

        write!(f, "{domain}\tIN\tSOA\t{ns}\t{admin}\t{settings}")
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
        zone.record(example_ns()?);
        zone.record(example_a()?);

        assert_eq!(expected, zone.to_string());

        Ok(())
    }

    fn example_a() -> Result<A<'static>> {
        Ok(A {
            domain: FQDN("e.gtld-servers.net.")?,
            ipv4_addr: Ipv4Addr::new(192, 12, 94, 30),
        })
    }

    fn example_ns() -> Result<Ns<'static>> {
        Ok(Ns {
            domain: FQDN::COM,
            ns: FQDN("e.gtld-servers.net.")?,
        })
    }

    fn example_soa() -> Result<Soa<'static>> {
        Ok(Soa {
            domain: FQDN::ROOT,
            ns: FQDN("a.root-servers.net.")?,
            admin: FQDN("nstld.verisign-grs.com.")?,
            settings: SoaSettings::default(),
        })
    }
}
