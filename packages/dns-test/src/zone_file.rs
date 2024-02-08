//! BIND-style zone file
//!
//! Note that
//! - the `@` syntax is not used to avoid relying on the order of the entries
//! - relative domain names are not used; all domain names must be in fully-qualified form

use core::{array, fmt};
use std::net::Ipv4Addr;
use std::str::FromStr;

use crate::{Error, FQDN};

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
    DNSKEY(DNSKEY),
    DS(DS),
    NS(NS<'a>),
}

impl<'a> From<DS> for Entry<'a> {
    fn from(v: DS) -> Self {
        Self::DS(v)
    }
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
            Entry::DNSKEY(dnskey) => dnskey.fmt(f),
            Entry::DS(ds) => ds.fmt(f),
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

// integer types chosen based on bit sizes in section 2.1 of RFC4034
#[derive(Clone, Debug)]
pub struct DNSKEY {
    zone: FQDN<'static>,
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: String,

    // extra information in `+multiline` format and `ldns-keygen`'s output
    bits: u16,
    key_tag: u16,
}

impl DNSKEY {
    pub fn bits(&self) -> u16 {
        self.bits
    }

    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }
}

impl FromStr for DNSKEY {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (before, after) = input.split_once(';').ok_or("comment was not found")?;
        let mut columns = before.split_whitespace();

        let [Some(zone), Some(class), Some(record_type), Some(flags), Some(protocol), Some(algorithm), Some(public_key), None] =
            array::from_fn(|_| columns.next())
        else {
            return Err("expected 7 columns".into());
        };

        if record_type != "DNSKEY" {
            return Err(format!("tried to parse `{record_type}` record as a DNSKEY record").into());
        }

        if class != "IN" {
            return Err(format!("unknown class: {class}").into());
        }

        // {id = 24975 (zsk), size = 1024b}
        let error = "invalid comment syntax";
        let (id_expr, size_expr) = after.split_once(',').ok_or(error)?;

        // {id = 24975 (zsk)
        let (id_lhs, id_rhs) = id_expr.split_once('=').ok_or(error)?;
        if id_lhs.trim() != "{id" {
            return Err(error.into());
        }

        // 24975 (zsk)
        let (key_tag, _key_type) = id_rhs.trim().split_once(' ').ok_or(error)?;

        //  size = 1024b}
        let (size_lhs, size_rhs) = size_expr.split_once('=').ok_or(error)?;
        if size_lhs.trim() != "size" {
            return Err(error.into());
        }
        let bits = size_rhs.trim().strip_suffix("b}").ok_or(error)?.parse()?;

        Ok(Self {
            zone: zone.parse()?,
            flags: flags.parse()?,
            protocol: protocol.parse()?,
            algorithm: algorithm.parse()?,
            public_key: public_key.to_string(),

            key_tag: key_tag.parse()?,
            bits,
        })
    }
}

impl fmt::Display for DNSKEY {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            zone,
            flags,
            protocol,
            algorithm,
            public_key,
            bits: _,
            key_tag: _,
        } = self;

        write!(
            f,
            "{zone}\tIN\tDNSKEY\t{flags}\t{protocol}\t{algorithm}\t{public_key}"
        )
    }
}

#[derive(Clone)]
pub struct DS {
    zone: FQDN<'static>,
    _ttl: u32,
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: String,
}

impl FromStr for DS {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut columns = input.split_whitespace();

        let [Some(zone), Some(ttl), Some(class), Some(record_type), Some(key_tag), Some(algorithm), Some(digest_type), Some(digest), None] =
            array::from_fn(|_| columns.next())
        else {
            return Err("expected 8 columns".into());
        };

        let expected = "DS";
        if record_type != expected {
            return Err(
                format!("tried to parse `{record_type}` entry as a {expected} entry").into(),
            );
        }

        if class != "IN" {
            return Err(format!("unknown class: {class}").into());
        }

        Ok(Self {
            zone: zone.parse()?,
            _ttl: ttl.parse()?,
            key_tag: key_tag.parse()?,
            algorithm: algorithm.parse()?,
            digest_type: digest_type.parse()?,
            digest: digest.to_string(),
        })
    }
}

/// NOTE does NOT include the TTL field
impl fmt::Display for DS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            zone,
            _ttl,
            key_tag,
            algorithm,
            digest_type,
            digest,
        } = self;

        write!(
            f,
            "{zone}\tIN\tDS\t{key_tag}\t{algorithm}\t{digest_type}\t{digest}"
        )
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

    // not quite roundtrip because we drop the TTL field when doing `to_string`
    #[test]
    fn ds_roundtrip() -> Result<()> {
        let input =
            ".	1800	IN	DS	31153	7	2	7846338aaacde9cc9518f1f450082adc015a207c45a1e69d6e660e6836f4ef3b";
        let ds: DS = input.parse()?;
        let output = ds.to_string();

        let expected =
            ".	IN	DS	31153	7	2	7846338aaacde9cc9518f1f450082adc015a207c45a1e69d6e660e6836f4ef3b";
        assert_eq!(expected, output);

        Ok(())
    }

    #[test]
    fn dnskey_roundtrip() -> Result<()> {
        let input = "example.com.	IN	DNSKEY	256	3	7	AwEAAdIpMlio4GJas7GbIZ9xRpzpB2pf4SxBJcsquN/0yNBPGNE2rzcFykqMAKmLwypk1/1q/EdHVa4tQ5RlK0w09CRhgSXfCaph+yLNJKpiPyuVcXKl2k0RnO4p835sgVEUIvx8qGTDo7c7DA9UBje+/3ViFKqVhOBaWyT6gHAmNVpb ;{id = 24975 (zsk), size = 1024b}";

        let dnskey: DNSKEY = input.parse()?;

        assert_eq!(256, dnskey.flags);
        assert_eq!(3, dnskey.protocol);
        assert_eq!(7, dnskey.algorithm);
        let expected = "AwEAAdIpMlio4GJas7GbIZ9xRpzpB2pf4SxBJcsquN/0yNBPGNE2rzcFykqMAKmLwypk1/1q/EdHVa4tQ5RlK0w09CRhgSXfCaph+yLNJKpiPyuVcXKl2k0RnO4p835sgVEUIvx8qGTDo7c7DA9UBje+/3ViFKqVhOBaWyT6gHAmNVpb";
        assert_eq!(expected, dnskey.public_key);
        assert_eq!(1024, dnskey.bits());
        assert_eq!(24975, dnskey.key_tag());

        let output = dnskey.to_string();
        assert!(input.starts_with(&output));

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
