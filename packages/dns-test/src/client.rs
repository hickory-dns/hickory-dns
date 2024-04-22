use core::str::FromStr;
use std::net::Ipv4Addr;

use crate::container::{Container, Image, Network};
use crate::record::{Record, RecordType};
use crate::trust_anchor::TrustAnchor;
use crate::{Error, Result, FQDN};

pub struct Client {
    inner: Container,
}

impl Client {
    pub fn new(network: &Network) -> Result<Self> {
        Ok(Self {
            inner: Container::run(&Image::Client, network)?,
        })
    }

    pub fn container_id(&self) -> &str {
        self.inner.id()
    }

    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.inner.ipv4_addr()
    }

    pub fn delv(
        &self,
        server: Ipv4Addr,
        record_type: RecordType,
        fqdn: &FQDN,
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
        settings: DigSettings,
        server: Ipv4Addr,
        record_type: RecordType,
        fqdn: &FQDN,
    ) -> Result<DigOutput> {
        let output = self.inner.stdout(&[
            "dig",
            settings.rdflag(),
            settings.do_bit(),
            settings.adflag(),
            settings.cdflag(),
            &format!("@{server}"),
            record_type.as_str(),
            fqdn.as_str(),
        ])?;

        output.parse()
    }
}

#[derive(Clone, Copy, Default)]
pub struct DigSettings {
    adflag: bool,
    cdflag: bool,
    dnssec: bool,
    recurse: bool,
}

impl DigSettings {
    /// Sets the AD bit in the query
    pub fn authentic_data(&mut self) -> &mut Self {
        self.adflag = true;
        self
    }

    fn adflag(&self) -> &'static str {
        if self.adflag {
            "+adflag"
        } else {
            "+noadflag"
        }
    }

    /// Sets the CD bit in the query
    pub fn checking_disabled(&mut self) -> &mut Self {
        self.cdflag = true;
        self
    }

    fn cdflag(&self) -> &'static str {
        if self.cdflag {
            "+cdflag"
        } else {
            "+nocdflag"
        }
    }

    /// Sets the DO bit in the query
    pub fn dnssec(&mut self) -> &mut Self {
        self.dnssec = true;
        self
    }

    fn do_bit(&self) -> &'static str {
        if self.dnssec {
            "+dnssec"
        } else {
            "+nodnssec"
        }
    }

    /// Sets the RD bit in the query
    pub fn recurse(&mut self) -> &mut Self {
        self.recurse = true;
        self
    }

    fn rdflag(&self) -> &'static str {
        if self.recurse {
            "+recurse"
        } else {
            "+norecurse"
        }
    }
}

#[derive(Debug)]
pub struct DigOutput {
    pub ede: Option<ExtendedDnsError>,
    pub flags: DigFlags,
    pub status: DigStatus,
    pub answer: Vec<Record>,
    pub authority: Vec<Record>,
    // TODO(if needed) other sections
}

impl FromStr for DigOutput {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        const FLAGS_PREFIX: &str = ";; flags: ";
        const STATUS_PREFIX: &str = ";; ->>HEADER<<- opcode: QUERY, status: ";
        const EDE_PREFIX: &str = "; EDE: ";
        const ANSWER_HEADER: &str = ";; ANSWER SECTION:";
        const AUTHORITY_HEADER: &str = ";; AUTHORITY SECTION:";

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
        let mut authority = None;
        let mut ede = None;

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
            } else if let Some(unprefixed) = line.strip_prefix(EDE_PREFIX) {
                let code = unprefixed
                    .split_once(' ')
                    .map(|(code, _rest)| code)
                    .unwrap_or(unprefixed);

                if ede.is_some() {
                    return Err(more_than_once(EDE_PREFIX).into());
                }

                ede = Some(code.parse()?);
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
            } else if line.starts_with(AUTHORITY_HEADER) {
                if authority.is_some() {
                    return Err(more_than_once(AUTHORITY_HEADER).into());
                }

                let mut records = vec![];
                for line in lines.by_ref() {
                    if line.is_empty() {
                        break;
                    }

                    records.push(line.parse()?);
                }

                authority = Some(records);
            }
        }

        Ok(Self {
            answer: answer.unwrap_or_default(),
            authority: authority.unwrap_or_default(),
            ede,
            flags: flags.ok_or_else(|| not_found(FLAGS_PREFIX))?,
            status: status.ok_or_else(|| not_found(STATUS_PREFIX))?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum ExtendedDnsError {
    DnskeyMissing,
    DnssecBogus,
    RrsigsMissing,
    UnsupportedDnskeyAlgorithm,
}

impl FromStr for ExtendedDnsError {
    type Err = Error;

    fn from_str(input: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        let code: u16 = input.parse()?;

        let code = match code {
            1 => Self::UnsupportedDnskeyAlgorithm,
            6 => Self::DnssecBogus,
            9 => Self::DnskeyMissing,
            10 => Self::RrsigsMissing,
            _ => todo!("EDE {code} has not yet been implemented"),
        };

        Ok(code)
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct DigFlags {
    pub authenticated_data: bool,
    pub authoritative_answer: bool,
    pub checking_disabled: bool,
    pub qr: bool,
    pub recursion_available: bool,
    pub recursion_desired: bool,
}

impl FromStr for DigFlags {
    type Err = Error;

    fn from_str(input: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        let mut qr = false;
        let mut recursion_desired = false;
        let mut recursion_available = false;
        let mut authoritative_answer = false;
        let mut authenticated_data = false;
        let mut checking_disabled = false;

        for flag in input.split_whitespace() {
            match flag {
                "qr" => qr = true,
                "rd" => recursion_desired = true,
                "ra" => recursion_available = true,
                "aa" => authoritative_answer = true,
                "ad" => authenticated_data = true,
                "cd" => checking_disabled = true,
                _ => return Err(format!("unknown flag: {flag}").into()),
            }
        }

        Ok(Self {
            authenticated_data,
            authoritative_answer,
            checking_disabled,
            qr,
            recursion_available,
            recursion_desired,
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

    #[must_use]
    pub fn is_servfail(&self) -> bool {
        matches!(self, Self::SERVFAIL)
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

    #[test]
    fn authority_section() -> Result<()> {
        // $ dig A .
        let input = "
; <<>> DiG 9.18.24 <<>> A .
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 39670
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;.				IN	A

;; AUTHORITY SECTION:
.			2910	IN	SOA	a.root-servers.net. nstld.verisign-grs.com. 2024022600 1800 900 604800 86400

;; Query time: 43 msec
;; SERVER: 192.168.1.1#53(192.168.1.1) (UDP)
;; WHEN: Mon Feb 26 11:55:50 CET 2024
;; MSG SIZE  rcvd: 103
";

        let output: DigOutput = input.parse()?;

        let [record] = output.authority.try_into().expect("exactly one record");

        matches!(record, Record::SOA(..));

        Ok(())
    }

    #[test]
    fn ede() -> Result<()> {
        let input = "; <<>> DiG 9.18.24-1-Debian <<>> +recurse +nodnssec +adflag +nocdflag @192.168.176.5 A example.nameservers.com.
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 49801
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; EDE: 9 (DNSKEY Missing)
;; QUESTION SECTION:
;example.nameservers.com.	IN	A

;; Query time: 26 msec
;; SERVER: 192.168.176.5#53(192.168.176.5) (UDP)
;; WHEN: Tue Mar 05 17:45:29 UTC 2024
;; MSG SIZE  rcvd: 58
";

        let output: DigOutput = input.parse()?;

        assert_eq!(Some(ExtendedDnsError::DnskeyMissing), output.ede);

        Ok(())
    }
}
