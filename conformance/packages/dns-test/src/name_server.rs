use core::sync::atomic::{self, AtomicUsize};
use std::net::Ipv4Addr;

use crate::container::{Child, Container, Network};
use crate::implementation::{Config, Role};
use crate::record::{self, Record, SoaSettings, DS, SOA};
use crate::tshark::Tshark;
use crate::zone_file::{Root, ZoneFile};
use crate::zone_file::{SignSettings, Signer};
use crate::{Implementation, Result, TrustAnchor, DEFAULT_TTL, FQDN};

pub struct Graph {
    pub nameservers: Vec<NameServer<Running>>,
    pub root: Root,
    pub trust_anchor: Option<TrustAnchor>,
}

/// Whether to sign the zone files
pub enum Sign<'a> {
    No,
    Yes {
        settings: SignSettings,
    },
    /// Signs the zone files and then modifies the records produced by the signing process
    AndAmend {
        settings: SignSettings,
        mutate: &'a dyn Fn(&FQDN, &mut Vec<Record>),
    },
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
        assert_eq!(2, leaf.zone().num_labels(), "not yet implemented");
        assert_eq!(Some(FQDN::COM), leaf.zone().parent(), "not yet implemented");

        // first pass: create nameservers for parent zones
        let mut zone = leaf.zone().clone();
        let network = leaf.container.network().clone();
        let implementation = leaf.implementation.clone();

        let (mut nameservers_ns, leaf) = if leaf.zone() != &FQDN::NAMESERVERS {
            let nameservers_ns = NameServer::new(&implementation, FQDN::NAMESERVERS, &network)?;
            (nameservers_ns, Some(leaf))
        } else {
            (leaf, None)
        };

        // the nameserver covering `FQDN::NAMESERVERS` needs A records about all the nameservers in the graph
        let mut nameservers = vec![];
        while let Some(parent) = zone.parent() {
            let nameserver = NameServer::new(&implementation, parent.clone(), &network)?;

            nameservers_ns.add(nameserver.a());
            nameservers.push(nameserver);

            zone = parent;
        }
        drop((network, implementation));

        if let Some(leaf) = leaf {
            nameservers.insert(0, leaf);
        }
        nameservers.insert(0, nameservers_ns);

        // second pass: add referrals from parent to child
        // the nameservers are sorted leaf-most zone first but siblings may be next to each other
        // for each child (e.g. `nameservers.com.`), do a linear search for its parent (`com.`)
        for index in 1..nameservers.len() {
            let (left, right) = nameservers.split_at_mut(index);
            let child = left.last_mut().unwrap();
            for maybe_parent in right {
                if Some(maybe_parent.zone()) == child.zone().parent().as_ref() {
                    let parent = maybe_parent;
                    parent.referral_nameserver(child);
                    break;
                }
            }
        }

        let root = nameservers.last().unwrap().root_hint();

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
                let (settings, maybe_mutate) = match sign {
                    Sign::No => unreachable!(),
                    Sign::Yes { settings } => (settings, None),
                    Sign::AndAmend { settings, mutate } => (settings, Some(mutate)),
                };

                let mut running = vec![];
                let mut children_ds = vec![];
                let mut children_num_labels = 0;
                let len = nameservers.len();
                for (index, mut nameserver) in nameservers.into_iter().enumerate() {
                    if !children_ds.is_empty() {
                        let is_parent = nameserver.zone().num_labels() + 1 == children_num_labels;
                        if is_parent {
                            for ds in children_ds.drain(..) {
                                nameserver.add(ds);
                            }
                        }
                    }

                    let mut nameserver = nameserver.sign(settings.clone())?;
                    children_ds.push(nameserver.ds().clone());
                    children_num_labels = nameserver.zone().num_labels();
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
        let nameserver = primary_ns(ns_count, &zone);
        let image = implementation.clone().into();
        let container = Container::run(&image, network)?;

        let soa = SOA {
            zone: zone.clone(),
            ttl: DEFAULT_TTL,
            nameserver: nameserver.clone(),
            admin: admin_ns(ns_count, &zone),
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

    /// Adds a NS + A record pair to the zone file from another NameServer
    pub fn referral_nameserver<T>(&mut self, nameserver: &NameServer<T>) -> &mut Self {
        self.referral(
            nameserver.zone().clone(),
            nameserver.fqdn().clone(),
            nameserver.ipv4_addr(),
        )
    }

    /// Adds a record to the name server's zone file
    pub fn add(&mut self, record: impl Into<Record>) -> &mut Self {
        self.zone_file.add(record);
        self
    }

    /// Freezes and signs the name server's zone file
    pub fn sign(self, settings: SignSettings) -> Result<NameServer<Signed>> {
        let Self {
            container,
            zone_file,
            implementation,
            state: _,
        } = self;

        let state = Signer::new(&container, settings)?.sign_zone(&zone_file)?;

        Ok(NameServer {
            container,
            implementation,
            zone_file,
            state,
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
            state: Running {
                child,
                trust_anchor: None,
            },
        })
    }
}

const ZONES_DIR: &str = "/etc/zones";
const ZONE_FILENAME: &str = "main.zone";

fn zone_file_path() -> String {
    format!("{ZONES_DIR}/{ZONE_FILENAME}")
}

fn ns_count() -> usize {
    thread_local! {
        static COUNT: AtomicUsize = const { AtomicUsize::new(0) };
    }
    COUNT.with(|count| count.fetch_add(1, atomic::Ordering::Relaxed))
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
            state: Running {
                child,
                trust_anchor: Some(state.trust_anchor()),
            },
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

    pub fn trust_anchor(&self) -> TrustAnchor {
        self.state.trust_anchor()
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

    pub fn trust_anchor(&self) -> Option<&TrustAnchor> {
        self.state.trust_anchor.as_ref()
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

    /// Returns the [`Record::A`] record for this server.
    pub fn a(&self) -> Record {
        Record::a(self.fqdn().clone(), self.ipv4_addr())
    }

    /// Returns the [`Root`] hint for this server.
    pub fn root_hint(&self) -> Root {
        Root::new(self.fqdn().clone(), self.ipv4_addr())
    }
}

pub struct Stopped;

pub struct Signed {
    pub(crate) ds: DS,
    pub(crate) zsk: record::DNSKEY,
    pub(crate) ksk: record::DNSKEY,
    pub(crate) signed: ZoneFile,
}

impl Signed {
    /// Return a [`TrustAnchor`] active on this NameServer.
    pub fn trust_anchor(&self) -> TrustAnchor {
        let mut trust_anchor = TrustAnchor::empty();
        trust_anchor.add(self.ksk.clone());
        trust_anchor.add(self.zsk.clone());
        trust_anchor
    }
}

pub struct Running {
    child: Child,
    trust_anchor: Option<TrustAnchor>,
}

fn primary_ns(ns_count: usize, zone: &FQDN) -> FQDN {
    FQDN(format!("primary{ns_count}.{}", expand_zone(zone))).unwrap()
}

fn admin_ns(ns_count: usize, zone: &FQDN) -> FQDN {
    FQDN(format!("admin{ns_count}.{}", expand_zone(zone))).unwrap()
}

fn expand_zone(zone: &FQDN) -> String {
    if zone == &FQDN::ROOT {
        "nameservers.com.".to_string()
    } else if zone.num_labels() == 1 {
        format!("nameservers.{}", zone.as_str())
    } else {
        zone.to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

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
        let ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, &network)?
            .sign(SignSettings::default())?;

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
        let ns = NameServer::new(&Implementation::hickory(), FQDN::ROOT, &network)?.start()?;

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
