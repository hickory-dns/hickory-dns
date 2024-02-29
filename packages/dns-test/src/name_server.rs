use core::sync::atomic::{self, AtomicUsize};
use std::net::Ipv4Addr;

use crate::container::{Child, Container, Network};
use crate::record::{self, Record, SoaSettings, DS, SOA};
use crate::tshark::Tshark;
use crate::zone_file::{self, ZoneFile};
use crate::{Implementation, Result, DEFAULT_TTL, FQDN};

pub struct NameServer<State> {
    container: Container,
    implementation: Implementation,
    state: State,
    zone_file: ZoneFile,
}

impl NameServer<Stopped> {
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
    pub fn new(implementation: &Implementation, zone: FQDN, network: &Network) -> Result<Self> {
        assert!(
            matches!(
                implementation,
                Implementation::Unbound | Implementation::Bind
            ),
            "currently only `unbound` (`nsd`) and BIND can be used as a `NameServer`"
        );

        let ns_count = ns_count();
        let nameserver = primary_ns(ns_count);
        let image = implementation.clone().into();
        let container = Container::run(&image, network)?;

        let soa = SOA {
            zone: zone.clone(),
            ttl: DEFAULT_TTL,
            nameserver: nameserver.clone(),
            admin: admin_ns(ns_count),
            settings: SoaSettings::default(),
        };
        let mut zone_file = ZoneFile::new(soa);

        zone_file.add(Record::ns(zone, nameserver.clone()));
        // BIND requires that `nameserver` has an A record
        zone_file.add(Record::a(nameserver.clone(), container.ipv4_addr()));

        Ok(Self {
            container,
            implementation: implementation.clone(),
            zone_file,
            state: Stopped,
        })
    }

    /// Adds a NS + A record pair to the zone file
    pub fn referral(&mut self, zone: FQDN, nameserver: FQDN, ipv4_addr: Ipv4Addr) -> &mut Self {
        self.zone_file.referral(zone, nameserver, ipv4_addr);
        self
    }

    /// Adds a record to the name server's zone file
    pub fn add(&mut self, record: impl Into<Record>) -> &mut Self {
        self.zone_file.add(record);
        self
    }

    /// Freezes and signs the name server's zone file
    pub fn sign(self) -> Result<NameServer<Signed>> {
        // TODO do we want to make these settings configurable?
        const ZSK_BITS: usize = 1024;
        const KSK_BITS: usize = 2048;
        const ALGORITHM: &str = "RSASHA1-NSEC3-SHA1";

        let Self {
            container,
            zone_file,
            implementation,
            state: _,
        } = self;

        container.status_ok(&["mkdir", "-p", ZONES_DIR])?;
        let zone_file_path = zone_file_path();
        container.cp(&zone_file_path, &zone_file.to_string())?;

        let zone = zone_file.origin();

        let zsk_keygen =
            format!("cd {ZONES_DIR} && ldns-keygen -a {ALGORITHM} -b {ZSK_BITS} {zone}");
        let zsk_filename = container.stdout(&["sh", "-c", &zsk_keygen])?;
        let zsk_path = format!("{ZONES_DIR}/{zsk_filename}.key");
        let zsk: zone_file::DNSKEY = container.stdout(&["cat", &zsk_path])?.parse()?;

        let ksk_keygen =
            format!("cd {ZONES_DIR} && ldns-keygen -k -a {ALGORITHM} -b {KSK_BITS} {zone}");
        let ksk_filename = container.stdout(&["sh", "-c", &ksk_keygen])?;
        let ksk_path = format!("{ZONES_DIR}/{ksk_filename}.key");
        let ksk: zone_file::DNSKEY = container.stdout(&["cat", &ksk_path])?.parse()?;

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

        let signed: ZoneFile = container
            .stdout(&["cat", &format!("{zone_file_path}.signed")])?
            .parse()?;

        let ttl = zone_file.soa.ttl;

        Ok(NameServer {
            container,
            implementation,
            zone_file,
            state: Signed {
                ds,
                signed,
                // inherit SOA's TTL value
                ksk: ksk.with_ttl(ttl),
                zsk: zsk.with_ttl(ttl),
            },
        })
    }

    /// Moves the server to the "Start" state where it can answer client queries
    pub fn start(self) -> Result<NameServer<Running>> {
        let Self {
            container,
            zone_file,
            implementation,
            state: _,
        } = self;

        let origin = zone_file.origin();
        let (path, contents, cmd_args) = match &implementation {
            Implementation::Bind => (
                "/etc/bind/named.conf",
                named_conf(origin),
                &["named", "-g", "-d5"][..],
            ),

            Implementation::Unbound => {
                // for PID file
                container.status_ok(&["mkdir", "-p", "/run/nsd/"])?;

                ("/etc/nsd/nsd.conf", nsd_conf(origin), &["nsd", "-d"][..])
            }

            Implementation::Hickory(_) => unreachable!(),
        };

        container.cp(path, &contents)?;

        container.status_ok(&["mkdir", "-p", ZONES_DIR])?;
        container.cp(&zone_file_path(), &zone_file.to_string())?;

        let child = container.spawn(cmd_args)?;

        Ok(NameServer {
            container,
            implementation,
            zone_file,
            state: Running { child },
        })
    }
}

const ZONES_DIR: &str = "/etc/zones";
const ZONE_FILENAME: &str = "main.zone";

fn zone_file_path() -> String {
    format!("{ZONES_DIR}/{ZONE_FILENAME}")
}

fn ns_count() -> usize {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    COUNT.fetch_add(1, atomic::Ordering::Relaxed)
}

impl NameServer<Signed> {
    /// Moves the server to the "Start" state where it can answer client queries
    pub fn start(self) -> Result<NameServer<Running>> {
        let Self {
            container,
            zone_file,
            implementation,
            state,
        } = self;

        let (conf_path, conf_contents, cmd_args) = match implementation {
            Implementation::Bind => (
                "/etc/bind/named.conf",
                named_conf(zone_file.origin()),
                &["named", "-g", "-d5"][..],
            ),

            Implementation::Unbound => {
                // for PID file
                container.status_ok(&["mkdir", "-p", "/run/nsd/"])?;

                (
                    "/etc/nsd/nsd.conf",
                    nsd_conf(zone_file.origin()),
                    &["nsd", "-d"][..],
                )
            }

            Implementation::Hickory(..) => unreachable!(),
        };

        container.cp(conf_path, &conf_contents)?;

        container.cp(&zone_file_path(), &state.signed.to_string())?;

        let child = container.spawn(cmd_args)?;

        Ok(NameServer {
            container,
            implementation,
            zone_file,
            state: Running { child },
        })
    }

    pub fn key_signing_key(&self) -> &record::DNSKEY {
        &self.state.ksk
    }

    pub fn zone_signing_key(&self) -> &record::DNSKEY {
        &self.state.zsk
    }

    pub fn signed_zone_file(&self) -> &ZoneFile {
        &self.state.signed
    }

    pub fn signed_zone_file_mut(&mut self) -> &mut ZoneFile {
        &mut self.state.signed
    }

    pub fn ds(&self) -> &DS {
        &self.state.ds
    }
}

impl NameServer<Running> {
    /// Starts a `tshark` instance that captures DNS messages flowing through this network node
    pub fn eavesdrop(&self) -> Result<Tshark> {
        self.container.eavesdrop()
    }

    /// gracefully terminates the name server collecting all logs
    pub fn terminate(self) -> Result<String> {
        let pidfile = match &self.implementation {
            Implementation::Bind => "/tmp/named.pid",

            Implementation::Unbound => "/run/nsd/nsd.pid",

            Implementation::Hickory(_) => unreachable!(),
        };
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

impl<S> NameServer<S> {
    pub fn container_id(&self) -> &str {
        self.container.id()
    }

    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.container.ipv4_addr()
    }

    /// Zone file BEFORE signing
    pub fn zone_file(&self) -> &ZoneFile {
        &self.zone_file
    }

    pub fn zone(&self) -> &FQDN {
        self.zone_file.origin()
    }

    pub fn fqdn(&self) -> &FQDN {
        &self.zone_file.soa.nameserver
    }
}

pub struct Stopped;

pub struct Signed {
    ds: DS,
    zsk: record::DNSKEY,
    ksk: record::DNSKEY,
    signed: ZoneFile,
}

pub struct Running {
    child: Child,
}

fn primary_ns(ns_count: usize) -> FQDN {
    FQDN(format!("primary{ns_count}.nameservers.com.")).unwrap()
}

fn admin_ns(ns_count: usize) -> FQDN {
    FQDN(format!("admin{ns_count}.nameservers.com.")).unwrap()
}

fn named_conf(fqdn: &FQDN) -> String {
    minijinja::render!(
        include_str!("templates/named.name-server.conf.jinja"),
        fqdn => fqdn.as_str()
    )
}

fn nsd_conf(fqdn: &FQDN) -> String {
    minijinja::render!(
        include_str!("templates/nsd.conf.jinja"),
        fqdn => fqdn.as_str()
    )
}

#[cfg(test)]
mod tests {
    use crate::client::{Client, DigSettings};
    use crate::record::RecordType;

    use super::*;

    #[test]
    fn simplest() -> Result<()> {
        let network = Network::new()?;
        let tld_ns = NameServer::new(&Implementation::Unbound, FQDN::COM, &network)?.start()?;
        let ip_addr = tld_ns.ipv4_addr();

        let client = Client::new(&network)?;
        let output = client.dig(DigSettings::default(), ip_addr, RecordType::SOA, &FQDN::COM)?;

        assert!(output.status.is_noerror());

        Ok(())
    }

    #[test]
    fn with_referral() -> Result<()> {
        let network = Network::new()?;
        let expected_ip_addr = Ipv4Addr::new(172, 17, 200, 1);
        let mut root_ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, &network)?;
        root_ns.referral(
            FQDN::COM,
            FQDN("primary.tld-server.com.")?,
            expected_ip_addr,
        );
        let root_ns = root_ns.start()?;

        eprintln!("root.zone:\n{}", root_ns.zone_file());

        let ipv4_addr = root_ns.ipv4_addr();

        let client = Client::new(&network)?;
        let output = client.dig(
            DigSettings::default(),
            ipv4_addr,
            RecordType::NS,
            &FQDN::COM,
        )?;

        assert!(output.status.is_noerror());

        Ok(())
    }

    #[test]
    fn signed() -> Result<()> {
        let network = Network::new()?;
        let ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, &network)?.sign()?;

        eprintln!("KSK:\n{}", ns.key_signing_key());
        eprintln!("ZSK:\n{}", ns.zone_signing_key());
        eprintln!("root.zone.signed:\n{}", ns.signed_zone_file());

        let tld_ns = ns.start()?;

        let ns_addr = tld_ns.ipv4_addr();

        let client = Client::new(&network)?;
        let settings = *DigSettings::default().dnssec();
        let output = client.dig(settings, ns_addr, RecordType::SOA, &FQDN::ROOT)?;

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
    fn terminate_nsd_works() -> Result<()> {
        let network = Network::new()?;
        let ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, &network)?.start()?;
        let logs = ns.terminate()?;

        assert!(logs.contains("nsd starting"));

        Ok(())
    }

    #[test]
    fn terminate_named_works() -> Result<()> {
        let network = Network::new()?;
        let ns = NameServer::new(&Implementation::Bind, FQDN::ROOT, &network)?.start()?;
        let logs = ns.terminate()?;

        eprintln!("{logs}");
        assert!(logs.contains("starting BIND"));

        Ok(())
    }
}
