//! BIND-style zone files
//!
//! Note that
//! - the `@` syntax is not used to avoid relying on the order of the entries
//! - relative domain names are not used; all domain names must be in fully-qualified form

use core::fmt;
use std::array;
use std::net::Ipv4Addr;
use std::str::FromStr;

use crate::record::{self, Record, SOA};
use crate::{Error, Result, DEFAULT_TTL, FQDN};

mod signer;

pub use signer::{SignSettings, Signer};

#[derive(Clone)]
pub struct ZoneFile {
    origin: FQDN,
    pub soa: SOA,
    pub records: Vec<Record>,
}

impl ZoneFile {
    /// Convenience constructor that uses "reasonable" defaults
    pub fn new(soa: SOA) -> Self {
        Self {
            origin: soa.zone.clone(),
            soa,
            records: Vec::new(),
        }
    }

    /// Adds the given `record` to the zone file
    pub fn add(&mut self, record: impl Into<Record>) {
        self.records.push(record.into())
    }

    /// Shortcut method for adding a referral (NS + A record pair)
    pub fn referral(&mut self, zone: FQDN, nameserver: FQDN, ipv4_addr: Ipv4Addr) {
        self.add(Record::ns(zone, nameserver.clone()));
        self.add(Record::a(nameserver, ipv4_addr));
    }

    pub(crate) fn origin(&self) -> &FQDN {
        &self.origin
    }
}

impl fmt::Display for ZoneFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { soa, records, .. } = self;

        writeln!(f, "{soa}")?;
        for record in records {
            writeln!(f, "{record}")?;
        }

        Ok(())
    }
}

impl FromStr for ZoneFile {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        let mut records = vec![];
        let mut maybe_soa = None;
        for line in input.lines() {
            let line = line.trim();

            if line.is_empty() {
                continue;
            }

            let record: Record = line.parse()?;
            if let Record::SOA(soa) = record {
                if maybe_soa.is_some() {
                    return Err("found more than one SOA record".into());
                }

                maybe_soa = Some(soa);
            } else {
                records.push(record)
            }
        }

        let soa = maybe_soa.ok_or("no SOA record found in zone file")?;
        Ok(Self {
            origin: soa.zone.clone(),
            soa,
            records,
        })
    }
}

/// A root (server) hint
#[derive(Clone)]
pub struct Root {
    pub ipv4_addr: Ipv4Addr,
    pub ns: FQDN,
    pub ttl: u32,
}

impl Root {
    /// Convenience constructor that uses "reasonable" defaults
    pub fn new(ns: FQDN, ipv4_addr: Ipv4Addr) -> Self {
        Self {
            ipv4_addr,
            ns,
            ttl: DEFAULT_TTL,
        }
    }
}

impl fmt::Display for Root {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { ipv4_addr, ns, ttl } = self;

        writeln!(f, ".\t{ttl}\tNS\t{ns}")?;
        write!(f, "{ns}\t{ttl}\tA\t{ipv4_addr}")
    }
}

// NOTE compared to `record::DNSKEY`, this zone file entry lacks the TTL field
#[allow(clippy::upper_case_acronyms)]
pub(crate) struct DNSKEY {
    zone: FQDN,
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: String,
}

impl DNSKEY {
    pub fn with_ttl(self, ttl: u32) -> record::DNSKEY {
        let Self {
            zone,
            flags,
            protocol,
            algorithm,
            public_key,
        } = self;

        record::DNSKEY {
            zone,
            ttl,
            flags,
            protocol,
            algorithm,
            public_key,
        }
    }
}

impl FromStr for DNSKEY {
    type Err = Error;

    fn from_str(mut input: &str) -> Result<Self> {
        // discard trailing comment
        if let Some((before, _after)) = input.split_once(';') {
            input = before.trim();
        }

        let mut columns = input.split_whitespace();

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

        Ok(Self {
            zone: zone.parse()?,
            flags: flags.parse()?,
            protocol: protocol.parse()?,
            algorithm: algorithm.parse()?,
            public_key: public_key.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn dnskey() -> Result<()> {
        let input = ".	IN	DNSKEY	256 3 7 AwEAAaCUpg+5lH7vart4WiMw4lbbkTNKfkvoyXWsAj09Cc5lT1bFo6sS7o4evhzXU9+iDGZkWZnnkwWg2thXfGgNdfQNTKW/Owz9UMDGv5yjkANKI3fI4jHn7Xp1qIZAwZG0W3RU26s7vkKWVcmA3mrKlDIX9r4BRIZrBVOtNgiHydbB ;{id = 42933 (zsk), size = 1024b}";

        let DNSKEY {
            zone,
            flags,
            protocol,
            algorithm,
            public_key,
        } = input.parse()?;

        assert_eq!(FQDN::ROOT, zone);
        assert_eq!(256, flags);
        assert_eq!(3, protocol);
        assert_eq!(7, algorithm);
        let expected = "AwEAAaCUpg+5lH7vart4WiMw4lbbkTNKfkvoyXWsAj09Cc5lT1bFo6sS7o4evhzXU9+iDGZkWZnnkwWg2thXfGgNdfQNTKW/Owz9UMDGv5yjkANKI3fI4jHn7Xp1qIZAwZG0W3RU26s7vkKWVcmA3mrKlDIX9r4BRIZrBVOtNgiHydbB";
        assert_eq!(expected, public_key);

        Ok(())
    }

    #[test]
    fn roundtrip() -> Result<()> {
        // `ldns-signzone`'s output minus trailing comments; long trailing fields have been split as well
        let input = include_str!("muster.zone");
        let zone: ZoneFile = input.parse()?;
        let output = zone.to_string();
        assert_eq!(input, output);

        Ok(())
    }
}
