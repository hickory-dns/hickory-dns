//! Text representation of DNS records

use core::array;
use core::result::Result as CoreResult;
use core::str::FromStr;
use std::net::Ipv4Addr;

use crate::{Error, Result, FQDN};

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq)]
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

impl FromStr for RecordType {
    type Err = Error;

    fn from_str(input: &str) -> CoreResult<Self, Self::Err> {
        let record_type = match input {
            "A" => Self::A,
            "SOA" => Self::SOA,
            "NS" => Self::NS,
            _ => return Err(format!("unknown record type: {input}").into()),
        };

        Ok(record_type)
    }
}

#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
pub enum Record {
    A(A),
    RRSIG(RRSIG),
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

    pub fn try_into_rrsig(self) -> CoreResult<RRSIG, Self> {
        if let Self::RRSIG(v) = self {
            Ok(v)
        } else {
            Err(self)
        }
    }

    pub fn is_soa(&self) -> bool {
        matches!(self, Self::SOA(..))
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
            "RRSIG" => Record::RRSIG(input.parse()?),
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

        let expected = "A";
        if record_type != expected {
            return Err(
                format!("tried to parse `{record_type}` record as an {expected} record").into(),
            );
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
pub struct RRSIG {
    pub fqdn: FQDN<'static>,
    pub ttl: u32,
    pub type_covered: RecordType,
    pub algorithm: u32,
    pub labels: u32,
    pub original_ttl: u32,
    pub signature_expiration: u64,
    pub signature_inception: u64,
    pub key_tag: u32,
    pub signer_name: FQDN<'static>,
    /// base64 encoded
    pub signature: String,
}

impl FromStr for RRSIG {
    type Err = Error;

    fn from_str(input: &str) -> CoreResult<Self, Self::Err> {
        let mut columns = input.split_whitespace();

        let [Some(fqdn), Some(ttl), Some(class), Some(record_type), Some(type_covered), Some(algorithm), Some(labels), Some(original_ttl), Some(signature_expiration), Some(signature_inception), Some(key_tag), Some(signer_name)] =
            array::from_fn(|_| columns.next())
        else {
            return Err("expected at least 12 columns".into());
        };

        let expected = "RRSIG";
        if record_type != expected {
            return Err(
                format!("tried to parse `{record_type}` record as a {expected} record").into(),
            );
        }

        if class != "IN" {
            return Err(format!("unknown class: {class}").into());
        }

        let mut signature = String::new();
        for column in columns {
            signature.push_str(column);
        }

        Ok(Self {
            fqdn: fqdn.parse()?,
            ttl: ttl.parse()?,
            type_covered: type_covered.parse()?,
            algorithm: algorithm.parse()?,
            labels: labels.parse()?,
            original_ttl: original_ttl.parse()?,
            signature_expiration: signature_expiration.parse()?,
            signature_inception: signature_inception.parse()?,
            key_tag: key_tag.parse()?,
            signer_name: signer_name.parse()?,
            signature,
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

    #[test]
    fn can_parse_rrsig_record() -> Result<()> {
        let input = ".			1800	IN	RRSIG	SOA 7 0 1800 20240306132701 20240207132701 11264 . wXpRU4elJPGYm2kgVVsIwGf1IkYJcQ3UE4mwmItWdxj0XWSWY07MO4Ll DMJgsE0u64Q/345Ck7+aQ904uLebwCvpFnsmkyCxk82XIAfHN9FiwzSy qoR/zZEvBONaej3vrvsqPwh8q/pvypLft9647HcFdwY0juzZsbrAaDAX 8WY=";

        let rrsig: RRSIG = input.parse()?;

        assert_eq!(FQDN::ROOT, rrsig.fqdn);
        assert_eq!(1800, rrsig.ttl);
        assert_eq!(RecordType::SOA, rrsig.type_covered);
        assert_eq!(7, rrsig.algorithm);
        assert_eq!(0, rrsig.labels);
        assert_eq!(20240306132701, rrsig.signature_expiration);
        assert_eq!(20240207132701, rrsig.signature_inception);
        assert_eq!(11264, rrsig.key_tag);
        assert_eq!(FQDN::ROOT, rrsig.signer_name);
        let expected = "wXpRU4elJPGYm2kgVVsIwGf1IkYJcQ3UE4mwmItWdxj0XWSWY07MO4LlDMJgsE0u64Q/345Ck7+aQ904uLebwCvpFnsmkyCxk82XIAfHN9FiwzSyqoR/zZEvBONaej3vrvsqPwh8q/pvypLft9647HcFdwY0juzZsbrAaDAX8WY=";
        assert_eq!(expected, rrsig.signature);

        Ok(())
    }
}
