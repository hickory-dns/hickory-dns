use core::array;
use core::result::Result as CoreResult;
use core::str::FromStr;
use std::net::Ipv4Addr;

use crate::container::Container;
use crate::{Domain, Error, Result};

pub struct Client {
    inner: Container,
}

impl Client {
    pub fn new() -> Result<Self> {
        Ok(Self {
            inner: Container::run()?,
        })
    }

    pub fn dig(
        &self,
        recurse: Recurse,
        server: Ipv4Addr,
        record_type: RecordType,
        domain: &Domain<'_>,
    ) -> Result<DigOutput> {
        let output = self.inner.stdout(&[
            "dig",
            recurse.as_str(),
            &format!("@{server}"),
            record_type.as_str(),
            domain.as_str(),
        ])?;

        output.parse()
    }
}

#[allow(clippy::upper_case_acronyms)]
pub enum RecordType {
    A,
    NS,
    SOA,
}

impl RecordType {
    fn as_str(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::SOA => "SOA",
            RecordType::NS => "NS",
        }
    }
}

#[derive(Clone, Copy)]
pub enum Recurse {
    Yes,
    No,
}

impl Recurse {
    fn as_str(&self) -> &'static str {
        match self {
            Recurse::Yes => "+recurse",
            Recurse::No => "+norecurse",
        }
    }
}

pub struct DigOutput {
    pub flags: DigFlags,
    pub status: DigStatus,
    pub answer: Vec<Record>,
    // TODO(if needed) other sections
}

impl FromStr for DigOutput {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        const FLAGS_PREFIX: &str = ";; flags: ";
        const STATUS_PREFIX: &str = ";; ->>HEADER<<- opcode: QUERY, status: ";
        const ANSWER_HEADER: &str = ";; ANSWER SECTION:";

        fn not_found(prefix: &str) -> String {
            format!("`{prefix}` line was not found")
        }

        fn more_than_once(prefix: &str) -> String {
            format!("`{prefix}` line was found more than once")
        }

        fn missing(prefix: &str, delimiter: &str) -> String {
            format!("`{prefix}` line is missing a {delimiter}")
        }

        let mut flags = None;
        let mut status = None;
        let mut answer = None;

        let mut lines = input.lines();
        while let Some(line) = lines.next() {
            if let Some(unprefixed) = line.strip_prefix(FLAGS_PREFIX) {
                let (flags_text, _rest) = unprefixed
                    .split_once(';')
                    .ok_or_else(|| missing(FLAGS_PREFIX, "semicolon (;)"))?;

                if flags.is_some() {
                    return Err(more_than_once(FLAGS_PREFIX).into());
                }

                flags = Some(flags_text.parse()?);
            } else if let Some(unprefixed) = line.strip_prefix(STATUS_PREFIX) {
                let (status_text, _rest) = unprefixed
                    .split_once(',')
                    .ok_or_else(|| missing(STATUS_PREFIX, "comma (,)"))?;

                if status.is_some() {
                    return Err(more_than_once(STATUS_PREFIX).into());
                }

                status = Some(status_text.parse()?);
            } else if line.starts_with(ANSWER_HEADER) {
                if answer.is_some() {
                    return Err(more_than_once(ANSWER_HEADER).into());
                }

                let mut records = vec![];
                for line in lines.by_ref() {
                    if line.is_empty() {
                        break;
                    }

                    records.push(line.parse()?);
                }

                answer = Some(records);
            }
        }

        Ok(Self {
            flags: flags.ok_or_else(|| not_found(FLAGS_PREFIX))?,
            status: status.ok_or_else(|| not_found(STATUS_PREFIX))?,
            answer: answer.unwrap_or_default(),
        })
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct DigFlags {
    pub qr: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authoritative_answer: bool,
}

impl FromStr for DigFlags {
    type Err = Error;

    fn from_str(input: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        let mut qr = false;
        let mut recursion_desired = false;
        let mut recursion_available = false;
        let mut authoritative_answer = false;

        for flag in input.split_whitespace() {
            match flag {
                "qr" => qr = true,
                "rd" => recursion_desired = true,
                "ra" => recursion_available = true,
                "aa" => authoritative_answer = true,
                _ => return Err(format!("unknown flag: {flag}").into()),
            }
        }

        Ok(Self {
            qr,
            recursion_desired,
            recursion_available,
            authoritative_answer,
        })
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DigStatus {
    NOERROR,
    NXDOMAIN,
    REFUSED,
}

impl DigStatus {
    #[must_use]
    pub fn is_noerror(&self) -> bool {
        matches!(self, Self::NOERROR)
    }
}

impl FromStr for DigStatus {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        let status = match input {
            "NXDOMAIN" => Self::NXDOMAIN,
            "NOERROR" => Self::NOERROR,
            "REFUSED" => Self::REFUSED,
            _ => return Err(format!("unknown status: {input}").into()),
        };

        Ok(status)
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
    pub domain: Domain<'static>,
    pub ttl: u32,
    pub ipv4_addr: Ipv4Addr,
}

impl FromStr for A {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        let mut columns = input.split_whitespace();

        let [Some(domain), Some(ttl), Some(class), Some(record_type), Some(ipv4_addr), None] =
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
            domain: domain.parse()?,
            ttl: ttl.parse()?,
            ipv4_addr: ipv4_addr.parse()?,
        })
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub struct SOA {
    pub domain: Domain<'static>,
    pub ttl: u32,
    pub nameserver: Domain<'static>,
    pub admin: Domain<'static>,
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

        let [Some(domain), Some(ttl), Some(class), Some(record_type), Some(nameserver), Some(admin), Some(serial), Some(refresh), Some(retry), Some(expire), Some(minimum), None] =
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
            domain: domain.parse()?,
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
    fn nxdomain() -> Result<()> {
        // $ dig nonexistent.domain.
        let input = "
; <<>> DiG 9.18.18-0ubuntu0.22.04.1-Ubuntu <<>> nonexistent.domain.
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 45583
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;nonexistent.domain.		IN	A

;; Query time: 3 msec
;; SERVER: 192.168.1.1#53(192.168.1.1) (UDP)
;; WHEN: Tue Feb 06 15:00:12 UTC 2024
;; MSG SIZE  rcvd: 47
";

        let output: DigOutput = input.parse()?;

        assert_eq!(DigStatus::NXDOMAIN, output.status);
        assert_eq!(
            DigFlags {
                qr: true,
                recursion_desired: true,
                recursion_available: true,
                ..DigFlags::default()
            },
            output.flags
        );
        assert!(output.answer.is_empty());

        Ok(())
    }

    #[test]
    fn can_parse_a_record() -> Result<()> {
        let input = "a.root-servers.net.	3600000	IN	A	198.41.0.4";
        let a: A = input.parse()?;

        assert_eq!("a.root-servers.net.", a.domain.as_str());
        assert_eq!(3600000, a.ttl);
        assert_eq!(Ipv4Addr::new(198, 41, 0, 4), a.ipv4_addr);

        Ok(())
    }

    #[test]
    fn can_parse_soa_record() -> Result<()> {
        let input = ".			15633	IN	SOA	a.root-servers.net. nstld.verisign-grs.com. 2024020501 1800 900 604800 86400";

        let soa: SOA = input.parse()?;

        assert_eq!(".", soa.domain.as_str());
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
