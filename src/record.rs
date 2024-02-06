//! Text representation of DNS records

use core::array;
use core::result::Result as CoreResult;
use core::str::FromStr;
use std::net::Ipv4Addr;

use crate::{Error, Result, FQDN};

#[allow(clippy::upper_case_acronyms)]
pub enum RecordType {
    A,
    NS,
    SOA,
}

impl RecordType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::SOA => "SOA",
            RecordType::NS => "NS",
        }
    }
}

#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
pub enum Record {
    A(A),
    SOA(SOA),
}

impl Record {
    pub fn try_into_a(self) -> CoreResult<A, Self> {
        if let Self::A(v) = self {
            Ok(v)
        } else {
            Err(self)
        }
    }
}

impl FromStr for Record {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        let record_type = input
            .split_whitespace()
            .nth(3)
            .ok_or("record is missing the type column")?;

        let record = match record_type {
            "A" => Record::A(input.parse()?),
            "NS" => todo!(),
            "SOA" => Record::SOA(input.parse()?),
            _ => return Err(format!("unknown record type: {record_type}").into()),
        };

        Ok(record)
    }
}

#[derive(Debug)]
pub struct A {
    pub fqdn: FQDN<'static>,
    pub ttl: u32,
    pub ipv4_addr: Ipv4Addr,
}

impl FromStr for A {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        let mut columns = input.split_whitespace();

        let [Some(fqdn), Some(ttl), Some(class), Some(record_type), Some(ipv4_addr), None] =
            array::from_fn(|_| columns.next())
        else {
            return Err("expected 5 columns".into());
        };

        if record_type != "A" {
            return Err(format!("tried to parse `{record_type}` record as an A record").into());
        }

        if class != "IN" {
            return Err(format!("unknown class: {class}").into());
        }

        Ok(Self {
            fqdn: fqdn.parse()?,
            ttl: ttl.parse()?,
            ipv4_addr: ipv4_addr.parse()?,
        })
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub struct SOA {
    pub zone: FQDN<'static>,
    pub ttl: u32,
    pub nameserver: FQDN<'static>,
    pub admin: FQDN<'static>,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

impl FromStr for SOA {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        let mut columns = input.split_whitespace();

        let [Some(zone), Some(ttl), Some(class), Some(record_type), Some(nameserver), Some(admin), Some(serial), Some(refresh), Some(retry), Some(expire), Some(minimum), None] =
            array::from_fn(|_| columns.next())
        else {
            return Err("expected 11 columns".into());
        };

        if record_type != "SOA" {
            return Err(format!("tried to parse `{record_type}` record as a SOA record").into());
        }

        if class != "IN" {
            return Err(format!("unknown class: {class}").into());
        }

        Ok(Self {
            zone: zone.parse()?,
            ttl: ttl.parse()?,
            nameserver: nameserver.parse()?,
            admin: admin.parse()?,
            serial: serial.parse()?,
            refresh: refresh.parse()?,
            retry: retry.parse()?,
            expire: expire.parse()?,
            minimum: minimum.parse()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_parse_a_record() -> Result<()> {
        let input = "a.root-servers.net.	3600000	IN	A	198.41.0.4";
        let a: A = input.parse()?;

        assert_eq!("a.root-servers.net.", a.fqdn.as_str());
        assert_eq!(3600000, a.ttl);
        assert_eq!(Ipv4Addr::new(198, 41, 0, 4), a.ipv4_addr);

        Ok(())
    }

    #[test]
    fn can_parse_soa_record() -> Result<()> {
        let input = ".			15633	IN	SOA	a.root-servers.net. nstld.verisign-grs.com. 2024020501 1800 900 604800 86400";

        let soa: SOA = input.parse()?;

        assert_eq!(".", soa.zone.as_str());
        assert_eq!(15633, soa.ttl);
        assert_eq!("a.root-servers.net.", soa.nameserver.as_str());
        assert_eq!("nstld.verisign-grs.com.", soa.admin.as_str());
        assert_eq!(2024020501, soa.serial);
        assert_eq!(1800, soa.refresh);
        assert_eq!(900, soa.retry);
        assert_eq!(604800, soa.expire);
        assert_eq!(86400, soa.minimum);

        Ok(())
    }
}
