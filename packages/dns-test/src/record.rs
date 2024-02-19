//! Text representation of DNS records

use core::result::Result as CoreResult;
use core::str::FromStr;
use core::{array, fmt};
use std::fmt::Write;
use std::net::Ipv4Addr;

use crate::{Error, Result, DEFAULT_TTL, FQDN};

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq)]
pub enum RecordType {
    A,
    DS,
    NS,
    SOA,
    // excluded because cannot appear in RRSIG.type_covered
    // RRSIG,
}

impl RecordType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::DS => "DS",
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
            "DS" => Self::DS,
            "SOA" => Self::SOA,
            "NS" => Self::NS,
            _ => return Err(format!("unknown record type: {input}").into()),
        };

        Ok(record_type)
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            RecordType::A => "A",
            RecordType::DS => "DS",
            RecordType::NS => "NS",
            RecordType::SOA => "SOA",
        };

        f.write_str(s)
    }
}

#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
pub enum Record {
    A(A),
    DS(DS),
    NS(NS),
    RRSIG(RRSIG),
    SOA(SOA),
}

impl From<DS> for Record {
    fn from(v: DS) -> Self {
        Self::DS(v)
    }
}

impl From<A> for Record {
    fn from(v: A) -> Self {
        Self::A(v)
    }
}

impl From<NS> for Record {
    fn from(v: NS) -> Self {
        Self::NS(v)
    }
}

impl From<RRSIG> for Record {
    fn from(v: RRSIG) -> Self {
        Self::RRSIG(v)
    }
}

impl From<SOA> for Record {
    fn from(v: SOA) -> Self {
        Self::SOA(v)
    }
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

    pub fn a(fqdn: FQDN, ipv4_addr: Ipv4Addr) -> Self {
        A {
            fqdn,
            ttl: DEFAULT_TTL,
            ipv4_addr,
        }
        .into()
    }

    pub fn ns(zone: FQDN, nameserver: FQDN) -> Self {
        NS {
            zone,
            ttl: DEFAULT_TTL,
            nameserver,
        }
        .into()
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

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Record::A(a) => write!(f, "{a}"),
            Record::DS(ds) => write!(f, "{ds}"),
            Record::NS(ns) => write!(f, "{ns}"),
            Record::RRSIG(rrsig) => write!(f, "{rrsig}"),
            Record::SOA(soa) => write!(f, "{soa}"),
        }
    }
}

#[derive(Debug)]
pub struct A {
    pub fqdn: FQDN,
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

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            fqdn,
            ttl,
            ipv4_addr,
        } = self;

        write!(f, "{fqdn}\t{ttl}\tIN\tA\t{ipv4_addr}")
    }
}

// integer types chosen based on bit sizes in section 2.1 of RFC4034
#[derive(Clone, Debug)]
pub struct DNSKEY {
    pub zone: FQDN,
    pub ttl: u32,
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: String,
}

impl DNSKEY {
    /// formats the `DNSKEY` in the format `delv` expects
    pub(super) fn delv(&self) -> String {
        let Self {
            zone,
            flags,
            protocol,
            algorithm,
            public_key,
            ..
        } = self;

        format!("{zone} static-key {flags} {protocol} {algorithm} \"{public_key}\";\n")
    }
}

impl FromStr for DNSKEY {
    type Err = Error;

    fn from_str(input: &str) -> CoreResult<Self, Self::Err> {
        let mut columns = input.split_whitespace();

        let [Some(zone), Some(ttl), Some(class), Some(record_type), Some(flags), Some(protocol), Some(algorithm)] =
            array::from_fn(|_| columns.next())
        else {
            return Err("expected at least 7 columns".into());
        };

        if record_type != "DNSKEY" {
            return Err(format!("tried to parse `{record_type}` record as a DNSKEY record").into());
        }

        if class != "IN" {
            return Err(format!("unknown class: {class}").into());
        }

        let mut public_key = String::new();
        for column in columns {
            public_key.push_str(column);
        }

        Ok(Self {
            zone: zone.parse()?,
            ttl: ttl.parse()?,
            flags: flags.parse()?,
            protocol: protocol.parse()?,
            algorithm: algorithm.parse()?,
            public_key,
        })
    }
}

impl fmt::Display for DNSKEY {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            zone,
            ttl,
            flags,
            protocol,
            algorithm,
            public_key,
        } = self;

        write!(
            f,
            "{zone}\t{ttl}\tIN\tDNSKEY\t{flags} {protocol} {algorithm}"
        )?;

        write_split_long_string(f, public_key)
    }
}

#[derive(Clone, Debug)]
pub struct DS {
    zone: FQDN,
    ttl: u32,
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: String,
}

impl FromStr for DS {
    type Err = Error;

    fn from_str(input: &str) -> CoreResult<Self, Self::Err> {
        let mut columns = input.split_whitespace();

        let [Some(zone), Some(ttl), Some(class), Some(record_type), Some(key_tag), Some(algorithm), Some(digest_type)] =
            array::from_fn(|_| columns.next())
        else {
            return Err("expected at least 7 columns".into());
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

        let mut digest = String::new();
        for column in columns {
            digest.push_str(column);
        }

        Ok(Self {
            zone: zone.parse()?,
            ttl: ttl.parse()?,
            key_tag: key_tag.parse()?,
            algorithm: algorithm.parse()?,
            digest_type: digest_type.parse()?,
            digest,
        })
    }
}

impl fmt::Display for DS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            zone,
            ttl,
            key_tag,
            algorithm,
            digest_type,
            digest,
        } = self;

        write!(
            f,
            "{zone}\t{ttl}\tIN\tDS\t{key_tag} {algorithm} {digest_type}"
        )?;

        write_split_long_string(f, digest)
    }
}

#[derive(Debug)]
pub struct NS {
    pub zone: FQDN,
    pub ttl: u32,
    pub nameserver: FQDN,
}

impl fmt::Display for NS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            zone,
            ttl,
            nameserver,
        } = self;

        write!(f, "{zone}\t{ttl}\tIN\tNS {nameserver}")
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub struct RRSIG {
    pub fqdn: FQDN,
    pub ttl: u32,
    pub type_covered: RecordType,
    pub algorithm: u32,
    pub labels: u32,
    pub original_ttl: u32,
    pub signature_expiration: u64,
    pub signature_inception: u64,
    pub key_tag: u32,
    pub signer_name: FQDN,
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

impl fmt::Display for RRSIG {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            fqdn,
            ttl,
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name,
            signature,
        } = self;

        write!(f, "{fqdn}\t{ttl}\tIN\tRRSIG\t{type_covered} {algorithm} {labels} {original_ttl} {signature_expiration} {signature_inception} {key_tag} {signer_name}")?;

        write_split_long_string(f, signature)
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub struct SOA {
    pub zone: FQDN,
    pub ttl: u32,
    pub nameserver: FQDN,
    pub admin: FQDN,
    pub settings: SoaSettings,
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
            settings: SoaSettings {
                serial: serial.parse()?,
                refresh: refresh.parse()?,
                retry: retry.parse()?,
                expire: expire.parse()?,
                minimum: minimum.parse()?,
            },
        })
    }
}

impl fmt::Display for SOA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            zone,
            ttl,
            nameserver,
            admin,
            settings,
        } = self;

        write!(f, "{zone}\t{ttl}\tIN\tSOA\t{nameserver} {admin} {settings}")
    }
}

#[derive(Debug)]
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

        write!(f, "{serial} {refresh} {retry} {expire} {minimum}")
    }
}

fn write_split_long_string(f: &mut fmt::Formatter<'_>, field: &str) -> fmt::Result {
    for (index, c) in field.chars().enumerate() {
        if index % 56 == 0 {
            f.write_char(' ')?;
        }
        f.write_char(c)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a() -> Result<()> {
        // dig A a.root-servers.net
        let input = "a.root-servers.net.	77859	IN	A	198.41.0.4";
        let a @ A {
            fqdn,
            ttl,
            ipv4_addr,
        } = &input.parse()?;

        assert_eq!("a.root-servers.net.", fqdn.as_str());
        assert_eq!(77859, *ttl);
        assert_eq!(Ipv4Addr::new(198, 41, 0, 4), *ipv4_addr);

        let output = a.to_string();
        assert_eq!(output, input);

        Ok(())
    }

    #[test]
    fn dnskey() -> Result<()> {
        // dig DNSKEY .
        let input = ".	1116	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3 +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF 0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN R1AkUTV74bU=";

        let dnskey @ DNSKEY {
            zone,
            ttl,
            flags,
            protocol,
            algorithm,
            public_key,
        } = &input.parse()?;

        assert_eq!(FQDN::ROOT, *zone);
        assert_eq!(1116, *ttl);
        assert_eq!(257, *flags);
        assert_eq!(3, *protocol);
        assert_eq!(8, *algorithm);
        let expected = "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=";
        assert_eq!(expected, public_key);

        let output = dnskey.to_string();
        assert_eq!(output, input);

        Ok(())
    }

    #[test]
    fn ds() -> Result<()> {
        // dig DS com.
        let input = "com.	7612	IN	DS	19718 13 2 8ACBB0CD28F41250A80A491389424D341522D946B0DA0C0291F2D3D7 71D7805A";

        let ds @ DS {
            zone,
            ttl,
            key_tag,
            algorithm,
            digest_type,
            digest,
        } = &input.parse()?;

        assert_eq!(FQDN::COM, *zone);
        assert_eq!(7612, *ttl);
        assert_eq!(19718, *key_tag);
        assert_eq!(13, *algorithm);
        assert_eq!(2, *digest_type);
        let expected = "8ACBB0CD28F41250A80A491389424D341522D946B0DA0C0291F2D3D771D7805A";
        assert_eq!(expected, digest);

        let output = ds.to_string();
        assert_eq!(output, input);

        Ok(())
    }

    #[test]
    fn rrsig() -> Result<()> {
        // dig +dnssec SOA .
        let input = ".	1800	IN	RRSIG	SOA 7 0 1800 20240306132701 20240207132701 11264 . wXpRU4elJPGYm2kgVVsIwGf1IkYJcQ3UE4mwmItWdxj0XWSWY07MO4Ll DMJgsE0u64Q/345Ck7+aQ904uLebwCvpFnsmkyCxk82XIAfHN9FiwzSy qoR/zZEvBONaej3vrvsqPwh8q/pvypLft9647HcFdwY0juzZsbrAaDAX 8WY=";

        let rrsig @ RRSIG {
            fqdn,
            ttl,
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name,
            signature,
        } = &input.parse()?;

        assert_eq!(FQDN::ROOT, *fqdn);
        assert_eq!(1800, *ttl);
        assert_eq!(RecordType::SOA, *type_covered);
        assert_eq!(7, *algorithm);
        assert_eq!(0, *labels);
        assert_eq!(1800, *original_ttl);
        assert_eq!(20240306132701, *signature_expiration);
        assert_eq!(20240207132701, *signature_inception);
        assert_eq!(11264, *key_tag);
        assert_eq!(FQDN::ROOT, *signer_name);
        let expected = "wXpRU4elJPGYm2kgVVsIwGf1IkYJcQ3UE4mwmItWdxj0XWSWY07MO4LlDMJgsE0u64Q/345Ck7+aQ904uLebwCvpFnsmkyCxk82XIAfHN9FiwzSyqoR/zZEvBONaej3vrvsqPwh8q/pvypLft9647HcFdwY0juzZsbrAaDAX8WY=";
        assert_eq!(expected, signature);

        let output = rrsig.to_string();
        assert_eq!(input, output);

        Ok(())
    }

    #[test]
    fn soa() -> Result<()> {
        // dig SOA .
        let input = ".	15633	IN	SOA	a.root-servers.net. nstld.verisign-grs.com. 2024020501 1800 900 604800 86400";

        let soa: SOA = input.parse()?;

        assert_eq!(".", soa.zone.as_str());
        assert_eq!(15633, soa.ttl);
        assert_eq!("a.root-servers.net.", soa.nameserver.as_str());
        assert_eq!("nstld.verisign-grs.com.", soa.admin.as_str());
        let settings = &soa.settings;
        assert_eq!(2024020501, settings.serial);
        assert_eq!(1800, settings.refresh);
        assert_eq!(900, settings.retry);
        assert_eq!(604800, settings.expire);
        assert_eq!(86400, settings.minimum);

        let output = soa.to_string();
        assert_eq!(output, input);

        Ok(())
    }
}
