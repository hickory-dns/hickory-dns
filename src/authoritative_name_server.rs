use std::net::Ipv4Addr;
use std::process::Child;

use crate::container::Container;
use crate::record::{self, Referral, SoaSettings, Zone};
use crate::{Domain, Result, CHMOD_RW_EVERYONE};

pub struct AuthoritativeNameServer<'a> {
    child: Child,
    container: Container,
    zone: Zone<'a>,
}

impl<'a> AuthoritativeNameServer<'a> {
    /// Spins up a container in a parked state where the name server is not running yet
    pub fn reserve() -> Result<StoppedAuthoritativeNameServer> {
        let ns_count = crate::nameserver_count();
        let nameserver = primary_ns(ns_count);

        Ok(StoppedAuthoritativeNameServer {
            container: Container::run()?,
            nameserver,
            ns_count,
        })
    }

    pub fn start(
        domain: Domain<'a>,
        referrals: &[Referral<'a>],
        a_records: &[record::A<'a>],
    ) -> Result<Self> {
        Self::reserve()?.start(domain, referrals, a_records)
    }

    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.container.ipv4_addr()
    }

    pub fn nameserver(&self) -> &Domain<'a> {
        &self.zone.soa.ns
    }

    pub fn zone(&self) -> &Zone<'a> {
        &self.zone
    }
}

impl Drop for AuthoritativeNameServer<'_> {
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

pub struct StoppedAuthoritativeNameServer {
    container: Container,
    nameserver: Domain<'static>,
    ns_count: usize,
}

impl StoppedAuthoritativeNameServer {
    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.container.ipv4_addr()
    }

    pub fn nameserver(&self) -> &Domain<'static> {
        &self.nameserver
    }

    pub fn start<'a>(
        self,
        domain: Domain<'a>,
        referrals: &[Referral<'a>],
        a_records: &[record::A<'a>],
    ) -> Result<AuthoritativeNameServer<'a>> {
        let Self {
            container,
            nameserver,
            ns_count,
        } = self;

        // for PID file
        container.status_ok(&["mkdir", "-p", "/run/nsd/"])?;

        container.status_ok(&["mkdir", "-p", "/etc/nsd/zones"])?;
        let zone_path = "/etc/nsd/zones/main.zone";
        container.cp("/etc/nsd/nsd.conf", &nsd_conf(&domain), CHMOD_RW_EVERYONE)?;

        let soa = record::Soa {
            domain: domain.clone(),
            ns: nameserver.clone(),
            admin: admin_ns(ns_count),
            settings: SoaSettings::default(),
        };
        let mut zone = Zone::new(domain.clone(), soa);

        zone.record(record::Ns {
            domain: domain.clone(),
            ns: nameserver,
        });
        zone.record(record::A {
            domain,
            ipv4_addr: container.ipv4_addr(),
        });

        for referral in referrals {
            zone.referral(referral)
        }

        for a in a_records {
            zone.record(a.clone())
        }

        container.cp(zone_path, &zone.to_string(), CHMOD_RW_EVERYONE)?;

        let child = container.spawn(&["nsd", "-d"])?;

        Ok(AuthoritativeNameServer {
            child,
            container,
            zone,
        })
    }
}

fn nsd_conf(domain: &Domain) -> String {
    minijinja::render!(
        include_str!("templates/nsd.conf.jinja"),
        domain => domain.as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tld_ns() -> Result<()> {
        let tld_ns = AuthoritativeNameServer::start(Domain("com.")?, &[], &[])?;
        let ip_addr = tld_ns.ipv4_addr();

        let client = Container::run()?;
        let output = client.output(&["dig", &format!("@{ip_addr}"), "SOA", "com."])?;

        assert!(output.status.success());
        eprintln!("{}", output.stdout);
        assert!(output.stdout.contains("status: NOERROR"));

        Ok(())
    }

    #[test]
    fn root_ns() -> Result<()> {
        let root_ns = AuthoritativeNameServer::start(Domain::ROOT, &[], &[])?;
        let ip_addr = root_ns.ipv4_addr();

        let client = Container::run()?;
        let output = client.output(&["dig", &format!("@{ip_addr}"), "SOA", "."])?;

        assert!(output.status.success());
        eprintln!("{}", output.stdout);
        assert!(output.stdout.contains("status: NOERROR"));

        Ok(())
    }

    #[test]
    fn root_ns_with_referral() -> Result<()> {
        let expected_ip_addr = Ipv4Addr::new(172, 17, 200, 1);
        let root_ns = AuthoritativeNameServer::start(
            Domain::ROOT,
            &[Referral {
                domain: Domain("com.")?,
                ipv4_addr: expected_ip_addr,
                ns: Domain("primary.tld-server.com.")?,
            }],
            &[],
        )?;
        let ip_addr = root_ns.ipv4_addr();

        let client = Container::run()?;
        let output = client.output(&["dig", &format!("@{ip_addr}"), "NS", "com."])?;

        assert!(output.status.success());
        eprintln!("{}", output.stdout);
        assert!(output.stdout.contains("status: NOERROR"));

        Ok(())
    }
}
