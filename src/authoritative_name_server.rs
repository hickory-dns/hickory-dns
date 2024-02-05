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
    pub fn start(domain: Domain<'a>, referrals: &[Referral<'a>]) -> Result<Self> {
        let container = Container::run()?;

        // for PID file
        container.status_ok(&["mkdir", "-p", "/run/nsd/"])?;

        container.status_ok(&["mkdir", "-p", "/etc/nsd/zones"])?;
        let zone_path = "/etc/nsd/zones/main.zone";
        container.cp("/etc/nsd/nsd.conf", &nsd_conf(&domain), CHMOD_RW_EVERYONE)?;

        let ns_count = crate::nameserver_count();
        let ns = Domain(format!("primary.ns{ns_count}.com."))?;
        let soa = record::Soa {
            domain: domain.clone(),
            ns,
            admin: Domain(format!("admin.ns{ns_count}.com."))?,
            settings: SoaSettings::default(),
        };
        let mut zone = Zone::new(domain, soa);
        for referral in referrals {
            zone.referral(referral)
        }

        container.cp(zone_path, &zone.to_string(), CHMOD_RW_EVERYONE)?;

        let child = container.spawn(&["nsd", "-d"])?;

        Ok(Self {
            child,
            container,
            zone,
        })
    }

    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.container.ipv4_addr()
    }

    pub fn nameserver(&self) -> &Domain<'a> {
        &self.zone.soa.ns
    }
}

impl Drop for AuthoritativeNameServer<'_> {
    fn drop(&mut self) {
        let _ = self.child.kill();
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
        let tld_ns = AuthoritativeNameServer::start(Domain("com.")?, &[])?;
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
        let root_ns = AuthoritativeNameServer::start(Domain::ROOT, &[])?;
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
