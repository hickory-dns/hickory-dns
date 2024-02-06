use core::sync::atomic::{self, AtomicUsize};
use std::net::Ipv4Addr;
use std::process::Child;

use crate::container::Container;
use crate::zone_file::{self, SoaSettings, ZoneFile};
use crate::{Result, CHMOD_RW_EVERYONE, FQDN};

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
    /// - one SOA record, with the primary name server field set to this name server's FQDN
    /// - one NS record, with this name server's FQDN set as the only available name server for
    /// the zone
    pub fn new(zone: FQDN<'a>) -> Result<Self> {
        let ns_count = ns_count();
        let nameserver = primary_ns(ns_count);

        let soa = zone_file::SOA {
            zone: zone.clone(),
            nameserver: nameserver.clone(),
            admin: admin_ns(ns_count),
            settings: SoaSettings::default(),
        };
        let mut zone_file = ZoneFile::new(zone.clone(), soa);

        zone_file.entry(zone_file::NS {
            zone,
            nameserver: nameserver.clone(),
        });

        Ok(Self {
            container: Container::run()?,
            zone_file,
            _state: Stopped,
        })
    }

    /// Adds a NS + A record pair to the zone file
    pub fn referral(
        &mut self,
        zone: FQDN<'a>,
        nameserver: FQDN<'a>,
        ipv4_addr: Ipv4Addr,
    ) -> &mut Self {
        self.zone_file.referral(zone, nameserver, ipv4_addr);
        self
    }

    /// Adds an A record pair to the zone file
    pub fn a(&mut self, fqdn: FQDN<'a>, ipv4_addr: Ipv4Addr) -> &mut Self {
        self.zone_file.entry(zone_file::A { fqdn, ipv4_addr });
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

fn ns_count() -> usize {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    COUNT.fetch_add(1, atomic::Ordering::Relaxed)
}

impl<'a, S> NameServer<'a, S> {
    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.container.ipv4_addr()
    }

    pub fn zone_file(&self) -> &ZoneFile<'a> {
        &self.zone_file
    }

    pub fn zone(&self) -> &FQDN<'a> {
        &self.zone_file.origin
    }

    pub fn fqdn(&self) -> &FQDN<'a> {
        &self.zone_file.soa.nameserver
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

fn primary_ns(ns_count: usize) -> FQDN<'static> {
    FQDN(format!("primary{ns_count}.nameservers.com.")).unwrap()
}

fn admin_ns(ns_count: usize) -> FQDN<'static> {
    FQDN(format!("admin{ns_count}.nameservers.com.")).unwrap()
}

fn nsd_conf(fqdn: &FQDN) -> String {
    minijinja::render!(
        include_str!("templates/nsd.conf.jinja"),
        fqdn => fqdn.as_str()
    )
}

#[cfg(test)]
mod tests {
    use crate::client::{Client, Recurse};
    use crate::record::RecordType;

    use super::*;

    #[test]
    fn simplest() -> Result<()> {
        let tld_ns = NameServer::new(FQDN::COM)?.start()?;
        let ip_addr = tld_ns.ipv4_addr();

        let client = Client::new()?;
        let output = client.dig(Recurse::No, ip_addr, RecordType::SOA, &FQDN::COM)?;

        assert!(output.status.is_noerror());

        Ok(())
    }

    #[test]
    fn with_referral() -> Result<()> {
        let expected_ip_addr = Ipv4Addr::new(172, 17, 200, 1);
        let mut root_ns = NameServer::new(FQDN::ROOT)?;
        root_ns.referral(
            FQDN::COM,
            FQDN("primary.tld-server.com.")?,
            expected_ip_addr,
        );
        let root_ns = root_ns.start()?;

        eprintln!("root.zone:\n{}", root_ns.zone_file());

        let ipv4_addr = root_ns.ipv4_addr();

        let client = Client::new()?;
        let output = client.dig(Recurse::No, ipv4_addr, RecordType::NS, &FQDN::COM)?;

        assert!(output.status.is_noerror());

        Ok(())
    }
}
