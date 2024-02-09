use core::sync::atomic::{self, AtomicUsize};
use std::net::Ipv4Addr;

use crate::container::{Child, Container};
use crate::zone_file::{self, SoaSettings, ZoneFile, DNSKEY, DS};
use crate::{Implementation, Result, FQDN};

pub struct NameServer<'a, State> {
    container: Container,
    zone_file: ZoneFile<'a>,
    state: State,
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
            container: Container::run(Implementation::Unbound)?,
            zone_file,
            state: Stopped,
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

    /// Adds a DS record to the zone file
    pub fn ds(&mut self, ds: DS) -> &mut Self {
        self.zone_file.entry(ds);
        self
    }

    /// Freezes and signs the name server's zone file
    pub fn sign(self) -> Result<NameServer<'a, Signed>> {
        // TODO do we want to make these settings configurable?
        const ZSK_BITS: usize = 1024;
        const KSK_BITS: usize = 2048;
        const ALGORITHM: &str = "RSASHA1-NSEC3-SHA1";

        let Self {
            container,
            zone_file,
            state: _,
        } = self;

        container.status_ok(&["mkdir", "-p", ZONES_DIR])?;
        container.cp("/etc/nsd/zones/main.zone", &zone_file.to_string())?;

        let zone = &zone_file.origin;

        let zsk_keygen =
            format!("cd {ZONES_DIR} && ldns-keygen -a {ALGORITHM} -b {ZSK_BITS} {zone}");
        let zsk_filename = container.stdout(&["sh", "-c", &zsk_keygen])?;
        let zsk_path = format!("{ZONES_DIR}/{zsk_filename}.key");
        let zsk: DNSKEY = container.stdout(&["cat", &zsk_path])?.parse()?;

        let ksk_keygen =
            format!("cd {ZONES_DIR} && ldns-keygen -k -a {ALGORITHM} -b {KSK_BITS} {zone}");
        let ksk_filename = container.stdout(&["sh", "-c", &ksk_keygen])?;
        let ksk_path = format!("{ZONES_DIR}/{ksk_filename}.key");
        let ksk: DNSKEY = container.stdout(&["cat", &ksk_path])?.parse()?;

        // -n = use NSEC3 instead of NSEC
        // -p = set the opt-out flag on all nsec3 rrs
        let signzone = format!(
            "cd {ZONES_DIR} && ldns-signzone -n -p {ZONE_FILENAME} {zsk_filename} {ksk_filename}"
        );
        container.status_ok(&["sh", "-c", &signzone])?;

        // TODO do we want to make the hashing algorithm configurable?
        // -2 = use SHA256 for the DS hash
        let key2ds = format!("cd {ZONES_DIR} && ldns-key2ds -n -2 {ZONE_FILENAME}.signed");
        let ds: DS = container.stdout(&["sh", "-c", &key2ds])?.parse()?;

        // we have an in-memory representation of the zone file so we just delete the on-disk version
        let zone_file_path = zone_file_path();
        container.status_ok(&["mv", &format!("{zone_file_path}.signed"), &zone_file_path])?;

        let signed_zone_file = container.stdout(&["cat", &zone_file_path])?;

        Ok(NameServer {
            container,
            zone_file,
            state: Signed {
                ds,
                ksk,
                signed_zone_file,
                zsk,
            },
        })
    }

    /// Moves the server to the "Start" state where it can answer client queries
    pub fn start(self) -> Result<NameServer<'a, Running>> {
        let Self {
            container,
            zone_file,
            state: _,
        } = self;

        // for PID file
        container.status_ok(&["mkdir", "-p", "/run/nsd/"])?;

        container.cp("/etc/nsd/nsd.conf", &nsd_conf(&zone_file.origin))?;

        container.status_ok(&["mkdir", "-p", ZONES_DIR])?;
        container.cp(&zone_file_path(), &zone_file.to_string())?;

        let child = container.spawn(&["nsd", "-d"])?;

        Ok(NameServer {
            container,
            zone_file,
            state: Running { child },
        })
    }
}

const ZONES_DIR: &str = "/etc/nsd/zones";
const ZONE_FILENAME: &str = "main.zone";

fn zone_file_path() -> String {
    format!("{ZONES_DIR}/{ZONE_FILENAME}")
}

fn ns_count() -> usize {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    COUNT.fetch_add(1, atomic::Ordering::Relaxed)
}

impl<'a> NameServer<'a, Signed> {
    /// Moves the server to the "Start" state where it can answer client queries
    pub fn start(self) -> Result<NameServer<'a, Running>> {
        let Self {
            container,
            zone_file,
            state: _,
        } = self;

        // for PID file
        container.status_ok(&["mkdir", "-p", "/run/nsd/"])?;

        container.cp("/etc/nsd/nsd.conf", &nsd_conf(&zone_file.origin))?;

        let child = container.spawn(&["nsd", "-d"])?;

        Ok(NameServer {
            container,
            zone_file,
            state: Running { child },
        })
    }

    pub fn key_signing_key(&self) -> &DNSKEY {
        &self.state.ksk
    }

    pub fn zone_signing_key(&self) -> &DNSKEY {
        &self.state.zsk
    }

    pub fn signed_zone_file(&self) -> &str {
        &self.state.signed_zone_file
    }

    pub fn ds(&self) -> &DS {
        &self.state.ds
    }
}

impl<'a> NameServer<'a, Running> {
    /// gracefully terminates the name server collecting all logs
    pub fn terminate(self) -> Result<String> {
        let pidfile = "/run/nsd/nsd.pid";
        // if `terminate` is called right after `start` NSD may not have had the chance to create
        // the PID file so if it doesn't exist wait for a bit before invoking `kill`
        let kill = format!(
            "test -f {pidfile} || sleep 1
kill -TERM $(cat {pidfile})"
        );
        self.container.status_ok(&["sh", "-c", &kill])?;
        let output = self.state.child.wait()?;

        if !output.status.success() {
            return Err("could not terminate the `unbound` process".into());
        }

        assert!(
            output.stderr.is_empty(),
            "stderr should be returned if not empty"
        );
        Ok(output.stdout)
    }
}

impl<'a, S> NameServer<'a, S> {
    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.container.ipv4_addr()
    }

    /// Zone file BEFORE signing
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

pub struct Signed {
    ds: DS,
    zsk: DNSKEY,
    ksk: DNSKEY,
    signed_zone_file: String,
}

pub struct Running {
    child: Child,
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
    use crate::client::{Client, Dnssec, Recurse};
    use crate::record::RecordType;

    use super::*;

    #[test]
    fn simplest() -> Result<()> {
        let tld_ns = NameServer::new(FQDN::COM)?.start()?;
        let ip_addr = tld_ns.ipv4_addr();

        let client = Client::new()?;
        let output = client.dig(
            Recurse::No,
            Dnssec::No,
            ip_addr,
            RecordType::SOA,
            &FQDN::COM,
        )?;

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
        let output = client.dig(
            Recurse::No,
            Dnssec::No,
            ipv4_addr,
            RecordType::NS,
            &FQDN::COM,
        )?;

        assert!(output.status.is_noerror());

        Ok(())
    }

    #[test]
    fn signed() -> Result<()> {
        let ns = NameServer::new(FQDN::ROOT)?.sign()?;

        eprintln!("KSK:\n{}", ns.key_signing_key());
        eprintln!("ZSK:\n{}", ns.zone_signing_key());
        eprintln!("root.zone.signed:\n{}", ns.signed_zone_file());

        let tld_ns = ns.start()?;

        let ns_addr = tld_ns.ipv4_addr();

        let client = Client::new()?;
        let output = client.dig(
            Recurse::No,
            Dnssec::Yes,
            ns_addr,
            RecordType::SOA,
            &FQDN::ROOT,
        )?;

        assert!(output.status.is_noerror());

        let [soa, rrsig] = output
            .answer
            .try_into()
            .expect("two records in answer section");

        assert!(soa.is_soa());
        let rrsig = rrsig.try_into_rrsig().unwrap();
        assert_eq!(RecordType::SOA, rrsig.type_covered);

        Ok(())
    }

    #[test]
    fn terminate_works() -> Result<()> {
        let ns = NameServer::new(FQDN::ROOT)?.start()?;
        let logs = ns.terminate()?;

        assert!(logs.contains("nsd starting"));

        Ok(())
    }
}
