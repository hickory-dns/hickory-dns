use std::net::Ipv4Addr;
use std::process::Child;

use crate::container::Container;
use crate::record::{self, Referral, SoaSettings, ZoneFile};
use crate::{Domain, Result, CHMOD_RW_EVERYONE};

pub struct AuthoritativeNameServer<'a> {
    child: Child,
    container: Container,
    zone_file: ZoneFile<'a>,
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

    /// This is short-hand for `Self::reserve().start(/* .. */)`
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
        &self.zone_file.soa.ns
    }

    pub fn zone_file(&self) -> &ZoneFile<'a> {
        &self.zone_file
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

    /// Starts a primary name server that has authority over the given `zone`
    ///
    /// The domain of the name server will have the form `primary{count}.nameservers.com.` where
    /// `{count}` is a unique, monotonically increasing integer
    ///
    /// The zone will contain these records
    ///
    /// - one SOA record, with the primary name server set to the name server domain
    /// - one NS record, with the name server domain set as the only available name server for
    /// `zone`
    /// - one NS + A record pair, for each referral in the `referrals` list
    /// - the A records in the `a_records` list
    pub fn start<'a>(
        self,
        zone: Domain<'a>,
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
        let zone_file_path = "/etc/nsd/zones/main.zone";
        container.cp("/etc/nsd/nsd.conf", &nsd_conf(&zone), CHMOD_RW_EVERYONE)?;

        let soa = record::Soa {
            domain: zone.clone(),
            ns: nameserver.clone(),
            admin: admin_ns(ns_count),
            settings: SoaSettings::default(),
        };
        let mut zone_file = ZoneFile::new(zone.clone(), soa);

        zone_file.record(record::Ns {
            domain: zone.clone(),
            ns: nameserver.clone(),
        });

        for referral in referrals {
            zone_file.referral(referral)
        }

        for a in a_records {
            zone_file.record(a.clone())
        }

        container.cp(zone_file_path, &zone_file.to_string(), CHMOD_RW_EVERYONE)?;

        let child = container.spawn(&["nsd", "-d"])?;

        Ok(AuthoritativeNameServer {
            child,
            container,
            zone_file,
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
    use crate::{
        client::{RecordType, Recurse},
        Client,
    };

    use super::*;

    #[test]
    fn simplest() -> Result<()> {
        let com_domain = Domain("com.")?;
        let tld_ns = AuthoritativeNameServer::start(com_domain.clone(), &[], &[])?;
        let ip_addr = tld_ns.ipv4_addr();

        let client = Client::new()?;
        let output = client.dig(Recurse::No, ip_addr, RecordType::SOA, &com_domain)?;

        assert!(output.status.is_noerror());

        Ok(())
    }

    #[test]
    fn with_referral() -> Result<()> {
        let expected_ip_addr = Ipv4Addr::new(172, 17, 200, 1);
        let com_domain = Domain("com.")?;
        let root_ns = AuthoritativeNameServer::start(
            Domain::ROOT,
            &[Referral {
                domain: com_domain.clone(),
                ipv4_addr: expected_ip_addr,
                ns: Domain("primary.tld-server.com.")?,
            }],
            &[],
        )?;
        let ip_addr = root_ns.ipv4_addr();

        let client = Client::new()?;
        let output = client.dig(Recurse::No, ip_addr, RecordType::NS, &com_domain)?;

        assert!(output.status.is_noerror());

        Ok(())
    }
}
