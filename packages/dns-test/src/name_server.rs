use core::sync::atomic::{self, AtomicUsize};
use std::net::Ipv4Addr;

use crate::container::{Child, Container, Network};
use crate::implementation::{Config, Role};
use crate::record::{self, Record, SoaSettings, DS, SOA};
use crate::tshark::Tshark;
use crate::zone_file::{self, Root, ZoneFile};
use crate::{Implementation, Result, TrustAnchor, DEFAULT_TTL, FQDN};

pub struct Graph {
    pub nameservers: Vec<NameServer<Running>>,
    pub root: Root,
    pub trust_anchor: Option<TrustAnchor>,
}

/// Whether to sign the zone files
pub enum Sign<'a> {
    No,
    Yes,
    /// Signs the zone files and then modifies the records produced by the signing process
    // XXX if captures are needed use `&dyn Fn(..)` instead of a function pointer
    AndAmend(&'a dyn Fn(&FQDN, &mut Vec<Record>)),
}

impl Graph {
    /// Builds up a minimal DNS graph from `leaf` up to a root name server and returns all the
    /// name servers in the graph
    ///
    /// All new name servers will share the `Implementation` of `leaf`.
    ///
    /// The returned name servers are sorted from leaf zone to root zone.
    ///
    /// both `Sign::Yes` and `Sign::AndAmend` will add a DS record with the hash of the child's
    /// key to the parent's zone file
    ///
    /// a non-empty `TrustAnchor` is returned only when `Sign::Yes` or `Sign::AndAmend` is used
    pub fn build(leaf: NameServer<Stopped>, sign: Sign) -> Result<Self> {
        // TODO if `leaf` is not authoritative over `nameservers.com.`, we would need two "lines" to
        // root. for example, if `leaf` is authoritative over `example.net.` we would need these two
        // lines:
        // - `nameservers.com.`, `com.`, `.` to cover the `primaryNNN.nameservers.com.` domains that
        // `NameServer` implicitly uses
        // - `example.net.`, `net.`, `.` to cover the requested `leaf` name server
        assert_eq!(&FQDN::NAMESERVERS, leaf.zone(), "not yet implemented");

        // first pass: create nameservers for parent zones
        let mut zone = leaf.zone().clone();
        let mut nameservers = vec![leaf];
        while let Some(parent) = zone.parent() {
            let leaf = &mut nameservers[0];
            let nameserver = NameServer::new(
                &leaf.implementation,
                parent.clone(),
                leaf.container.network(),
            )?;

            leaf.add(Record::a(nameserver.fqdn().clone(), nameserver.ipv4_addr()));
            nameservers.push(nameserver);

            zone = parent;
        }

        // XXX will not hold when `leaf` is not authoritative over `nameservers.com.`
        assert_eq!(3, nameservers.len());

        // second pass: add referrals from parent to child
        // `windows_mut` is not a thing in `core::iter` so use indexing as a workaround
        for index in 0..nameservers.len() - 1 {
            let [child, parent] = &mut nameservers[index..][..2] else {
                unreachable!()
            };

            parent.referral(
                child.zone().clone(),
                child.fqdn().clone(),
                child.ipv4_addr(),
            );
        }

        let root = nameservers.last().unwrap();
        let root = Root::new(root.fqdn().clone(), root.ipv4_addr());

        // start name servers
        let (nameservers, trust_anchor) = match sign {
            Sign::No => (
                nameservers
                    .into_iter()
                    .map(|nameserver| nameserver.start())
                    .collect::<Result<_>>()?,
                None,
            ),

            _ => {
                let mut trust_anchor = TrustAnchor::empty();
                let maybe_mutate = match sign {
                    Sign::No => unreachable!(),
                    Sign::Yes => None,
                    Sign::AndAmend(f) => Some(f),
                };

                let mut running = vec![];
                let mut child_ds = None;
                let len = nameservers.len();
                for (index, mut nameserver) in nameservers.into_iter().enumerate() {
                    if let Some(ds) = child_ds.take() {
                        nameserver.add(ds);
                    }

                    let mut nameserver = nameserver.sign()?;
                    child_ds = Some(nameserver.ds().clone());
                    if let Some(mutate) = maybe_mutate {
                        let zone = nameserver.zone().clone();
                        mutate(&zone, &mut nameserver.signed_zone_file_mut().records);
                    }

                    if index == len - 1 {
                        // the last nameserver covers `.`
                        trust_anchor.add(nameserver.key_signing_key().clone());
                        trust_anchor.add(nameserver.zone_signing_key().clone());
                    }

                    running.push(nameserver.start()?);
                }

                (running, Some(trust_anchor))
            }
        };

        Ok(Graph {
            nameservers,
            root,
            trust_anchor,
        })
    }
}

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

        let config = Config::NameServer {
            origin: zone_file.origin(),
        };

        container.cp(
            implementation.conf_file_path(config.role()),
            &implementation.format_config(config),
        )?;

        container.status_ok(&["mkdir", "-p", ZONES_DIR])?;
        container.cp(&zone_file_path(), &zone_file.to_string())?;

        let child = container.spawn(implementation.cmd_args(config.role()))?;

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

        let config = Config::NameServer {
            origin: zone_file.origin(),
        };
        container.cp(
            implementation.conf_file_path(config.role()),
            &implementation.format_config(config),
        )?;
        container.cp(&zone_file_path(), &state.signed.to_string())?;

        let child = container.spawn(implementation.cmd_args(config.role()))?;

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
        let pidfile = self.implementation.pidfile(Role::NameServer);

        // if `terminate` is called right after `start` NSD may not have had the chance to create
        // the PID file so if it doesn't exist wait for a bit before invoking `kill`
        let kill = format!(
            "test -f {pidfile} || sleep 1
kill -TERM $(cat {pidfile})"
        );
        self.container.status_ok(&["sh", "-c", &kill])?;
        let output = self.state.child.wait()?;

        // the hickory-dns binary does not do signal handling so it won't shut down gracefully; we
        // will still get some logs so we'll ignore the fact that it fails to shut down ...
        let is_hickory = matches!(self.implementation, Implementation::Hickory(_));
        if !is_hickory && !output.status.success() {
            return Err(
                format!("could not terminate the `{}` process", self.implementation).into(),
            );
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

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use crate::client::{Client, DigSettings};
    use crate::record::RecordType;
    use crate::Repository;

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

    #[test]
    fn terminate_hickory_works() -> Result<()> {
        let network = Network::new()?;
        let ns = NameServer::new(
            &Implementation::Hickory(Repository("https://github.com/hickory-dns/hickory-dns")),
            FQDN::ROOT,
            &network,
        )?
        .start()?;

        // hickory-dns does not do signal handling so we need to wait until it prints something to
        // the console
        thread::sleep(Duration::from_millis(500));

        let logs = ns.terminate()?;

        eprintln!("{logs}");
        let mut found = false;
        for line in logs.lines() {
            if line.contains("Hickory DNS") && line.contains("starting") {
                found = true;
            }
        }
        assert!(found);

        Ok(())
    }
}
