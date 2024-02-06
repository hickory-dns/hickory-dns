use std::net::Ipv4Addr;
use std::process::Child;

use crate::container::Container;
use crate::record::{self, Referral, SoaSettings, ZoneFile};
use crate::{Domain, Result, CHMOD_RW_EVERYONE};

pub struct NameServer<'a, State> {
    container: Container,
    zone_file: ZoneFile<'a>,
    _state: State,
}

impl<'a> NameServer<'a, Stopped> {
    /// Spins up a primary name server that has authority over the given `zone`
    ///
    /// The initial state of the server is the "Stopped" state where it won't answer any query.
    ///
    /// The FQDN of the name server will have the form `primary{count}.nameservers.com.` where
    /// `{count}` is a (process-wide) unique, monotonically increasing integer
    ///
    /// The zone file will contain these records
    ///
    /// - one SOA record, with the primary name server set to the name server domain
    /// - one NS record, with the name server domain set as the only available name server for
    pub fn new(zone: Domain<'a>) -> Result<Self> {
        let ns_count = crate::nameserver_count();
        let nameserver = primary_ns(ns_count);

        let soa = record::Soa {
            domain: zone.clone(),
            ns: nameserver.clone(),
            admin: admin_ns(ns_count),
            settings: SoaSettings::default(),
        };
        let mut zone_file = ZoneFile::new(zone.clone(), soa);

        zone_file.record(record::Ns {
            domain: zone,
            ns: nameserver.clone(),
        });

        Ok(Self {
            container: Container::run()?,
            zone_file,
            _state: Stopped,
        })
    }

    /// Adds a NS + A record pair to the zone file
    pub fn referral(&mut self, referral: &Referral<'a>) -> &mut Self {
        self.zone_file.referral(referral);
        self
    }

    /// Adds an A record pair to the zone file
    pub fn a(&mut self, domain: Domain<'a>, ipv4_addr: Ipv4Addr) -> &mut Self {
        self.zone_file.record(record::A { domain, ipv4_addr });
        self
    }

    /// Moves the server to the "Start" state where it can answer client queries
    pub fn start(self) -> Result<NameServer<'a, Running>> {
        let Self {
            container,
            zone_file,
            _state: _,
        } = self;

        // for PID file
        container.status_ok(&["mkdir", "-p", "/run/nsd/"])?;

        container.cp(
            "/etc/nsd/nsd.conf",
            &nsd_conf(&zone_file.origin),
            CHMOD_RW_EVERYONE,
        )?;

        container.status_ok(&["mkdir", "-p", "/etc/nsd/zones"])?;
        container.cp(
            "/etc/nsd/zones/main.zone",
            &zone_file.to_string(),
            CHMOD_RW_EVERYONE,
        )?;

        let child = container.spawn(&["nsd", "-d"])?;

        Ok(NameServer {
            container,
            zone_file,
            _state: Running { child },
        })
    }
}

impl<'a, S> NameServer<'a, S> {
    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.container.ipv4_addr()
    }

    pub fn zone_file(&self) -> &ZoneFile<'a> {
        &self.zone_file
    }

    pub fn nameserver(&self) -> &Domain<'a> {
        &self.zone_file.soa.ns
    }
}

pub struct Stopped;

pub struct Running {
    child: Child,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn primary_ns(ns_count: usize) -> Domain<'static> {
    Domain(format!("primary{ns_count}.nameservers.com.")).unwrap()
}

fn admin_ns(ns_count: usize) -> Domain<'static> {
    Domain(format!("admin{ns_count}.nameservers.com.")).unwrap()
}

fn nsd_conf(domain: &Domain) -> String {
    minijinja::render!(
        include_str!("templates/nsd.conf.jinja"),
        domain => domain.as_str()
    )
}

#[cfg(test)]
mod tests {
    use crate::{
        client::{RecordType, Recurse},
        Client,
    };

    use super::*;

    #[test]
    fn simplest() -> Result<()> {
        let tld_ns = NameServer::new(Domain::COM)?.start()?;
        let ip_addr = tld_ns.ipv4_addr();

        let client = Client::new()?;
        let output = client.dig(Recurse::No, ip_addr, RecordType::SOA, &Domain::COM)?;

        assert!(output.status.is_noerror());

        Ok(())
    }

    #[test]
    fn with_referral() -> Result<()> {
        let expected_ip_addr = Ipv4Addr::new(172, 17, 200, 1);
        let mut root_ns = NameServer::new(Domain::ROOT)?;
        root_ns.referral(&Referral {
            domain: Domain::COM,
            ipv4_addr: expected_ip_addr,
            ns: Domain("primary.tld-server.com.")?,
        });
        let root_ns = root_ns.start()?;

        eprintln!("root.zone:\n{}", root_ns.zone_file());

        let ipv4_addr = root_ns.ipv4_addr();

        let client = Client::new()?;
        let output = client.dig(Recurse::No, ipv4_addr, RecordType::NS, &Domain::COM)?;

        assert!(output.status.is_noerror());

        Ok(())
    }
}
