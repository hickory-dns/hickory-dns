use core::sync::atomic::{self, AtomicUsize};
use std::{collections::HashMap, net::Ipv4Addr, path::PathBuf, rc::Rc, thread, time::Duration};

use crate::container::{Child, Container, Network};
use crate::implementation::{Config, Role, TlsServerConfig};
use crate::record::{self, DS, Record, SOA, SoaSettings};
use crate::tshark::Tshark;
use crate::zone_file::{self, Root, SigningKeys, ZoneFile};
use crate::zone_file::{SignSettings, Signer};
use crate::{DEFAULT_TTL, FQDN, Implementation, Pki, Result, TrustAnchor};

use rcgen::CertifiedKey;

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
        assert_eq!(
            Some(FQDN::TEST_TLD),
            leaf.zone().parent(),
            "not yet implemented"
        );

        // first pass: create nameservers for parent zones
        let mut zone = leaf.zone().clone();
        let network = leaf.container.network().clone();
        let implementation = leaf.implementation.clone();
        let pki = leaf.pki.clone();

        let (mut nameservers_ns, leaf) = if leaf.zone() != &FQDN::TEST_DOMAIN {
            let mut nameserver =
                NameServer::builder(implementation.clone(), FQDN::TEST_DOMAIN, network.clone());
            if let Some(pki) = &pki {
                nameserver = nameserver.pki(pki.clone());
            }
            (nameserver.build()?, Some(leaf))
        } else {
            (leaf, None)
        };

        // the nameserver covering `FQDN::NAMESERVERS` needs A records about all the nameservers in the graph
        let mut nameservers = vec![];
        while let Some(parent) = zone.parent() {
            let mut nameserver =
                NameServer::builder(implementation.clone(), parent.clone(), network.clone());
            if let Some(pki) = &pki {
                nameserver = nameserver.pki(pki.clone());
            }
            let nameserver = nameserver.build()?;

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
                    children_ds.push(nameserver.ds().ksk.clone());
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

/// Builder for [`NameServer`].
pub struct NameServerBuilder {
    zone: FQDN,
    nameserver_fqdn: Option<FQDN>,
    implementation: Implementation,
    network: Network,
    pki: Option<Rc<Pki>>,
}

impl NameServerBuilder {
    /// Constructs a [`NameServer`].
    ///
    /// The name server will initially be in the "Stopped" state, and won't respond to queries until
    /// it is started.
    ///
    /// The zone file will initially contain an SOA record, an NS record pointing to this name
    /// server, and an A record with the address of this server.
    pub fn build(self) -> Result<NameServer<Stopped>> {
        let Self {
            zone,
            nameserver_fqdn,
            implementation,
            network,
            pki,
        } = self;

        let ns_count = ns_count();
        let nameserver = nameserver_fqdn.unwrap_or_else(|| primary_ns(ns_count, &zone));
        let admin = admin_ns(ns_count, &zone);

        let image = implementation.clone().into();
        let container = Container::run(&image, &network)?;

        let soa = SOA {
            zone: zone.clone(),
            ttl: DEFAULT_TTL,
            nameserver: nameserver.clone(),
            admin,
            settings: SoaSettings::default(),
        };
        let mut zone_file = ZoneFile::new(soa);

        zone_file.add(Record::ns(zone, nameserver.clone()));
        // BIND requires that `nameserver` has an A record
        zone_file.add(Record::a(nameserver.clone(), container.ipv4_addr()));

        Ok(NameServer {
            container,
            implementation,
            state: Stopped,
            zone_file,
            additional_zones: HashMap::new(),
            pki,
        })
    }

    /// Override the FQDN of the name server.
    pub fn nameserver_fqdn(mut self, nameserver_fqdn: FQDN) -> Self {
        self.nameserver_fqdn = Some(nameserver_fqdn);
        self
    }

    /// Override the PKI to use for the name server.
    pub fn pki(mut self, pki: Rc<Pki>) -> Self {
        self.pki = Some(pki);
        self
    }
}

pub struct NameServer<State> {
    container: Container,
    implementation: Implementation,
    state: State,
    zone_file: ZoneFile,
    additional_zones: HashMap<FQDN, ZoneFile>,
    pki: Option<Rc<Pki>>,
}

impl<State> NameServer<State> {
    fn dot_config(&self) -> Result<Option<TlsServerConfig>> {
        let Some(pki) = &self.pki else {
            return Ok(None);
        };

        let cert_chain_path = "/tmp/dot.fullchain.pem";
        let private_key_path = "/tmp/dot.privkey.pem";
        let config = TlsServerConfig {
            cert_chain: PathBuf::from(cert_chain_path),
            private_key: PathBuf::from(private_key_path),
        };

        let CertifiedKey { cert, signing_key } =
            pki.certified_key_for_container(&self.container)?;

        self.container.cp(cert_chain_path, &cert.pem())?;
        // NOTE: cp() sets insecure permissions on the private key. Testing use only!
        self.container
            .cp(private_key_path, &signing_key.serialize_pem())?;

        Ok(Some(config))
    }
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
    ///   the zone
    /// - one A record, with this name server's IP address
    pub fn new(implementation: &Implementation, zone: FQDN, network: &Network) -> Result<Self> {
        Self::builder(implementation.clone(), zone, network.clone()).build()
    }

    pub fn builder(
        implementation: Implementation,
        zone: FQDN,
        network: Network,
    ) -> NameServerBuilder {
        NameServerBuilder {
            zone,
            nameserver_fqdn: None,
            implementation,
            network,
            pki: None,
        }
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

    /// Copy a file to the name server's filesystem
    pub fn cp(&self, path: &str, contents: &str) -> Result<()> {
        self.container.cp(path, contents)?;
        Ok(())
    }

    /// Adds an additional zone to the nameserver
    pub fn add_zone(&mut self, name: FQDN, zone: ZoneFile) {
        self.additional_zones.insert(name, zone);
    }

    /// Freezes and signs the name server's zone file
    pub fn sign(self, settings: SignSettings) -> Result<NameServer<Signed>> {
        let Self {
            container,
            zone_file,
            implementation,
            additional_zones,
            state: _,
            pki,
        } = self;

        let signer = Signer::new(&container, settings)?;
        let keys = signer.generate_keys(zone_file.origin())?;
        let state = signer.sign_zone(&zone_file, &keys)?;

        Ok(NameServer {
            container,
            implementation,
            zone_file,
            state,
            additional_zones,
            pki,
        })
    }

    /// Freezes and signs the name server's zone file, using the provided keys
    pub fn sign_with_keys(
        self,
        settings: SignSettings,
        keys: &SigningKeys,
    ) -> Result<NameServer<Signed>> {
        let Self {
            container,
            zone_file,
            implementation,
            additional_zones,
            state: _,
            pki,
        } = self;

        let signer = Signer::new(&container, settings)?;
        let state = signer.sign_zone(&zone_file, keys)?;

        Ok(NameServer {
            container,
            implementation,
            zone_file,
            state,
            additional_zones,
            pki,
        })
    }

    /// Moves the server to the "Start" state where it can answer client queries
    pub fn start(self) -> Result<NameServer<Running>> {
        let dot_config = self.dot_config()?;
        let Self {
            container,
            zone_file,
            implementation,
            additional_zones,
            state: _,
            pki,
        } = self;

        let config = Config::NameServer {
            origin: zone_file.origin(),
            use_dnssec: false,
            additional_zones: additional_zones.clone(),
            dot: dot_config,
        };

        if let Some(conf_file_path) = implementation.conf_file_path(config.role()) {
            container.cp(
                conf_file_path,
                &implementation.format_config(config.clone()),
            )?;
        }

        // PowerDNS auth server needs an additional zones configuration file
        if implementation.is_pdns() && matches!(config.role(), Role::NameServer) {
            let zones_config = minijinja::render!(
                include_str!("templates/pdns-zones.conf.jinja"),
                fqdn => zone_file.origin().as_str(),
                additional_zones => additional_zones.keys().map(FQDN::as_str).collect::<Vec<_>>(),
            );
            container.cp("/etc/powerdns/zones.conf", &zones_config)?;
            container.status_ok(&["pdnsutil", "set-presigned", "main"])?;
        }

        container.status_ok(&["mkdir", "-p", ZONES_DIR])?;
        container.cp(&zone_file_path(), &zone_file.to_string())?;

        for (key, zone_file) in &additional_zones {
            container.cp(&format!("{ZONES_DIR}/{key}zone"), &zone_file.to_string())?;
        }

        let mut child = container.spawn(&implementation.cmd_args(config.role()))?;

        // For Dnslib, make sure the python interpreter is still running after two seconds
        if let Implementation::Dnslib = implementation {
            thread::sleep(Duration::from_secs(2));

            match child.try_wait() {
                Ok(None) => {} // the process is still running
                Ok(Some(status)) => {
                    return Err(format!(
                        "unable to start dnslib server: {status:?}; logs: {:?}",
                        container
                            .stdout(&["cat", &implementation.stderr_logfile(Role::NameServer)]),
                    )
                    .into());
                }
                Err(e) => println!("unable to determine if dnslib started: {e}"),
            }
        }

        Ok(NameServer {
            container,
            implementation,
            zone_file,
            additional_zones,
            state: Running {
                _child: child,
                trust_anchor: None,
            },
            pki,
        })
    }
}

const ZONES_DIR: &str = "/etc/zones";
const ZONE_FILENAME: &str = "main.zone";
const ZSK_PRIVATE_FILENAME: &str = "zsk.key";
const ZSK_PKCS8_FILENAME: &str = "zsk.pk8";

fn zone_file_path() -> String {
    format!("{ZONES_DIR}/{ZONE_FILENAME}")
}
fn zsk_private_path() -> String {
    format!("{ZONES_DIR}/{ZSK_PRIVATE_FILENAME}")
}

fn zsk_pkcs8_path() -> String {
    format!("{ZONES_DIR}/{ZSK_PKCS8_FILENAME}")
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
        let dot_config = self.dot_config()?;
        let Self {
            container,
            zone_file,
            implementation,
            additional_zones,
            state,
            pki,
        } = self;

        let config = Config::NameServer {
            origin: zone_file.origin(),
            use_dnssec: state.use_dnssec,
            additional_zones: additional_zones.clone(),
            dot: dot_config,
        };

        if let Some(conf_file_path) = implementation.conf_file_path(config.role()) {
            container.cp(
                conf_file_path,
                &implementation.format_config(config.clone()),
            )?;
        }

        // PowerDNS auth server needs an additional zones configuration file
        if implementation.is_pdns() && matches!(config.role(), Role::NameServer) {
            let zones_config = minijinja::render!(
                include_str!("templates/pdns-zones.conf.jinja"),
                fqdn => zone_file.origin().as_str(),
                additional_zones => additional_zones.keys().map(FQDN::as_str).collect::<Vec<_>>(),
            );
            container.cp("/etc/powerdns/zones.conf", &zones_config)?;
            container.status_ok(&["pdnsutil", "set-presigned", "main"])?;
        }

        if implementation.is_hickory() && state.use_dnssec {
            // FIXME: Hickory does not support pre-signed zonefiles. We copy the unsigned
            // zonefile so hickory can sign the zonefile itself.
            container.cp(&zone_file_path(), &zone_file.to_string())?;
            // FIXME: Given that hickory doesn't support the key format produced by
            // `ldns-keygen` we generate a new zsk from scratch. This is fine as long as we
            // don't compare signatures in any of the conformance tests.
            let zsk = container.stdout(&["openssl", "genpkey", "-algorithm", "RSA"])?;
            container.cp(&zsk_private_path(), &zsk)?;
            container.status_ok(&[
                "openssl",
                "pkcs8",
                "-topk8",
                "-nocrypt",
                "-inform",
                "pem",
                "-in",
                &zsk_private_path(),
                "-outform",
                "der",
                "-out",
                &zsk_pkcs8_path(),
            ])?;
        } else {
            container.cp(&zone_file_path(), &state.signed.to_string())?;
        }

        let child = container.spawn(&implementation.cmd_args(config.role()))?;

        Ok(NameServer {
            container,
            implementation,
            zone_file,
            additional_zones,
            state: Running {
                _child: child,
                trust_anchor: Some(state.trust_anchor()),
            },
            pki,
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

    pub fn ds(&self) -> &DS2 {
        &self.state.ds
    }
}

impl NameServer<Running> {
    pub fn eavesdrop(&self) -> Result<Tshark> {
        Tshark::new(&self.container)
    }

    pub fn trust_anchor(&self) -> Option<&TrustAnchor> {
        self.state.trust_anchor.as_ref()
    }

    /// Returns the logs collected so far
    pub fn logs(&self) -> Result<String> {
        if self.implementation.is_hickory() || self.implementation.is_dnslib() {
            Ok(format!(
                "STDOUT:\n{}\nSTDERR:\n{}",
                self.stdout()?,
                self.stderr()?,
            ))
        } else {
            self.stderr()
        }
    }

    fn stdout(&self) -> Result<String> {
        self.container
            .stdout(&["cat", &self.implementation.stdout_logfile(Role::NameServer)])
    }

    fn stderr(&self) -> Result<String> {
        self.container
            .stdout(&["cat", &self.implementation.stderr_logfile(Role::NameServer)])
    }
}

impl<S> NameServer<S> {
    pub fn container_id(&self) -> &str {
        self.container.id()
    }

    pub fn container_name(&self) -> &str {
        self.container.name()
    }

    pub fn container(&self) -> &Container {
        &self.container
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

/// DS records for both the KSK and the ZSK
#[derive(Debug)]
pub struct DS2 {
    pub ksk: DS,
    pub zsk: DS,
}

impl DS2 {
    pub(crate) fn classify(dses: Vec<DS>, zsk: &zone_file::DNSKEY, ksk: &zone_file::DNSKEY) -> DS2 {
        let mut ksk_ds = None;
        let mut zsk_ds = None;

        let zsk_tag = zsk.rdata().calculate_key_tag();
        let ksk_tag = ksk.rdata().calculate_key_tag();
        for ds in dses {
            if ds.key_tag == zsk_tag {
                assert!(zsk_ds.is_none());
                zsk_ds = Some(ds);
            } else if ds.key_tag == ksk_tag {
                assert!(ksk_ds.is_none());
                ksk_ds = Some(ds);
            }
        }

        DS2 {
            ksk: ksk_ds.expect("DS for KSK not found"),
            zsk: zsk_ds.expect("DS for ZSK not found"),
        }
    }
}

pub struct Signed {
    pub(crate) ds: DS2,
    pub(crate) zsk: record::DNSKEY,
    pub(crate) ksk: record::DNSKEY,
    pub(crate) signed: ZoneFile,
    pub(crate) use_dnssec: bool,
}

impl Signed {
    /// Return a [`TrustAnchor`] active on this NameServer.
    pub fn trust_anchor(&self) -> TrustAnchor {
        let mut trust_anchor = TrustAnchor::empty();
        trust_anchor.add(self.ksk.clone());
        trust_anchor.add(self.zsk.clone());
        trust_anchor
    }

    /// Return the DS records for this zone's keys.
    pub fn ds(&self) -> &DS2 {
        &self.ds
    }
}

pub struct Running {
    _child: Child,
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
        FQDN::TEST_DOMAIN.as_str().to_string()
    } else if zone.num_labels() == 1 {
        if *zone == FQDN::TEST_TLD {
            FQDN::TEST_DOMAIN.as_str().to_string()
        } else if *zone == FQDN::COM_TLD {
            "nameservers.com.".to_string()
        } else {
            unimplemented!()
        }
    } else {
        zone.to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use crate::client::{Client, DigSettings};
    use crate::record::{A, NS, RecordType};

    use super::*;

    #[test]
    fn simplest() -> Result<()> {
        let network = Network::new()?;
        let tld_ns =
            NameServer::new(&Implementation::Unbound, FQDN::TEST_TLD, &network)?.start()?;
        let ip_addr = tld_ns.ipv4_addr();

        let client = Client::new(&network)?;
        let output = client.dig(
            DigSettings::default(),
            ip_addr,
            RecordType::SOA,
            &FQDN::TEST_TLD,
        )?;

        assert!(output.status.is_noerror());

        Ok(())
    }

    #[test]
    fn with_referral() -> Result<()> {
        let network = Network::new()?;
        let expected_ip_addr = Ipv4Addr::new(172, 17, 200, 1);
        let mut root_ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, &network)?;
        root_ns.referral(
            FQDN::TEST_TLD,
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
            &FQDN::TEST_TLD,
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
    fn nsd_logs_works() -> Result<()> {
        let network = Network::new()?;
        let ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, &network)?.start()?;
        // no way to block until the server has finished starting up so we just give it some
        // arbitrary amount of time
        thread::sleep(Duration::from_secs(1));
        let logs = ns.logs()?;

        assert!(logs.contains("nsd starting"));

        Ok(())
    }

    #[test]
    fn named_logs_works() -> Result<()> {
        let network = Network::new()?;
        let ns = NameServer::new(&Implementation::Bind, FQDN::ROOT, &network)?.start()?;
        // no way to block until the server has finished starting up so we just give it some
        // arbitrary amount of time
        thread::sleep(Duration::from_secs(1));
        let logs = ns.logs()?;

        eprintln!("{logs}");
        assert!(logs.contains("starting BIND"));

        Ok(())
    }

    #[test]
    fn hickory_logs_works() -> Result<()> {
        let network = Network::new()?;
        let ns = NameServer::new(&Implementation::hickory(), FQDN::ROOT, &network)?.start()?;

        // no way to block until the server has finished starting up so we just give it some
        // arbitrary amount of time
        thread::sleep(Duration::from_secs(1));

        let logs = ns.logs()?;

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

    #[test]
    fn bind_multizone_works() -> Result<()> {
        multizone_test(&Implementation::Bind)?;
        Ok(())
    }

    #[test]
    fn hickory_multizone_works() -> Result<()> {
        multizone_test(&Implementation::hickory())?;
        Ok(())
    }

    #[test]
    fn unbound_multizone_works() -> Result<()> {
        multizone_test(&Implementation::Unbound)?;
        Ok(())
    }

    #[cfg(test)]
    fn multizone_test(implementation: &Implementation) -> Result<()> {
        let network = Network::new()?;
        let mut ns = NameServer::new(implementation, FQDN::ROOT, &network)?;
        let mut zone_file = ZoneFile::new(SOA {
            zone: FQDN("domain.testing.")?,
            ttl: 86400,
            nameserver: FQDN("ns.domain.testing.")?,
            admin: FQDN("admin.domain.testing.")?,
            settings: SoaSettings::default(),
        });
        zone_file.add(Record::NS(NS {
            zone: FQDN("domain.testing.")?,
            ttl: 86400,
            nameserver: FQDN("ns.domain.testing.")?,
        }));
        zone_file.add(Record::A(A {
            fqdn: FQDN("ns.domain.testing.")?,
            ipv4_addr: Ipv4Addr::new(192, 0, 2, 1),
            ttl: 86400,
        }));

        zone_file.add(Record::A(A {
            fqdn: FQDN("host.domain.testing.")?,
            ipv4_addr: Ipv4Addr::new(192, 0, 2, 1),
            ttl: 86400,
        }));

        ns.add_zone(FQDN("domain.testing.")?, zone_file);

        let ns = ns.start()?;
        thread::sleep(Duration::from_secs(2));

        let client = Client::new(&network)?;
        let dig_settings = DigSettings::default();
        let res = client.dig(
            dig_settings,
            ns.ipv4_addr(),
            RecordType::A,
            &FQDN("host.domain.testing.")?,
        );

        if let Ok(res) = &res {
            assert!(res.status.is_noerror());
            assert_eq!(res.answer.len(), 1);
            if let Record::A(rec) = res.answer.first().unwrap() {
                assert_eq!(rec.fqdn, FQDN("host.domain.testing.")?);
                assert_eq!(rec.ipv4_addr, Ipv4Addr::new(192, 0, 2, 1));
            } else {
                panic!("error");
            }
        } else {
            panic!("error");
        }

        Ok(())
    }
}
