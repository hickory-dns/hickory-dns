use core::str::FromStr;
use std::net::Ipv4Addr;

use crate::container::{Container, Network};
use crate::record::{Record, RecordType};
use crate::trust_anchor::TrustAnchor;
use crate::{Error, Implementation, Result, FQDN};

pub struct Client {
    inner: Container,
}

impl Client {
    pub fn new(network: &Network) -> Result<Self> {
        Ok(Self {
            inner: Container::run(Implementation::Unbound, network)?,
        })
    }

    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.inner.ipv4_addr()
    }

    pub fn delv(
        &self,
        server: Ipv4Addr,
        record_type: RecordType,
        fqdn: &FQDN<'_>,
        trust_anchor: &TrustAnchor,
    ) -> Result<String> {
        const TRUST_ANCHOR_PATH: &str = "/etc/bind.keys";

        assert!(
            !trust_anchor.is_empty(),
            "`delv` cannot be used with an empty trust anchor"
        );

        self.inner.cp(TRUST_ANCHOR_PATH, &trust_anchor.delv())?;

        self.inner.stdout(&[
            "delv",
            &format!("@{server}"),
            "-a",
            TRUST_ANCHOR_PATH,
            fqdn.as_str(),
            record_type.as_str(),
        ])
    }

    pub fn dig(
        &self,
        recurse: Recurse,
        dnssec: Dnssec,
        server: Ipv4Addr,
        record_type: RecordType,
        fqdn: &FQDN<'_>,
    ) -> Result<DigOutput> {
        let output = self.inner.stdout(&[
            "dig",
            recurse.as_str(),
            dnssec.as_str(),
            &format!("@{server}"),
            record_type.as_str(),
            fqdn.as_str(),
        ])?;

        output.parse()
    }
}

#[derive(Clone, Copy)]
pub enum Dnssec {
    Yes,
    No,
}

impl Dnssec {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Yes => "+dnssec",
            Self::No => "+nodnssec",
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
            Self::Yes => "+recurse",
            Self::No => "+norecurse",
        }
    }
}

#[derive(Debug)]
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
    pub authenticated_data: bool,
}

impl FromStr for DigFlags {
    type Err = Error;

    fn from_str(input: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        let mut qr = false;
        let mut recursion_desired = false;
        let mut recursion_available = false;
        let mut authoritative_answer = false;
        let mut authenticated_data = false;

        for flag in input.split_whitespace() {
            match flag {
                "qr" => qr = true,
                "rd" => recursion_desired = true,
                "ra" => recursion_available = true,
                "aa" => authoritative_answer = true,
                "ad" => authenticated_data = true,
                _ => return Err(format!("unknown flag: {flag}").into()),
            }
        }

        Ok(Self {
            qr,
            recursion_desired,
            recursion_available,
            authoritative_answer,
            authenticated_data,
        })
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DigStatus {
    NOERROR,
    NXDOMAIN,
    REFUSED,
    SERVFAIL,
}

impl DigStatus {
    #[must_use]
    pub fn is_noerror(&self) -> bool {
        matches!(self, Self::NOERROR)
    }

    #[must_use]
    pub fn is_nxdomain(&self) -> bool {
        matches!(self, Self::NXDOMAIN)
    }
}

impl FromStr for DigStatus {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        let status = match input {
            "NXDOMAIN" => Self::NXDOMAIN,
            "NOERROR" => Self::NOERROR,
            "REFUSED" => Self::REFUSED,
            "SERVFAIL" => Self::SERVFAIL,
            _ => return Err(format!("unknown status: {input}").into()),
        };

        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dig_nxdomain() -> Result<()> {
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
}
