use core::fmt::Write;
use std::net::Ipv4Addr;

use crate::container::{Child, Container, Network};
use crate::implementation::{Config, Role};
use crate::record::DNSKEY;
use crate::trust_anchor::TrustAnchor;
use crate::tshark::Tshark;
use crate::zone_file::Root;
use crate::{Implementation, Result};

pub struct Resolver {
    container: Container,
    _child: Child,
    implementation: Implementation,
}

impl Resolver {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(network: &Network, root: Root) -> ResolverSettings {
        ResolverSettings {
            ede: false,
            network: network.clone(),
            roots: vec![root],
            trust_anchor: TrustAnchor::empty(),
            custom_config: None,
            case_randomization: false,
        }
    }

    pub fn eavesdrop(&self) -> Result<Tshark> {
        Tshark::new(&self.container)
    }

    pub fn network(&self) -> &Network {
        self.container.network()
    }

    pub fn container_id(&self) -> &str {
        self.container.id()
    }

    pub fn container_name(&self) -> &str {
        self.container.name()
    }

    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.container.ipv4_addr()
    }

    /// Returns the logs collected so far
    pub fn logs(&self) -> Result<String> {
        if self.implementation.is_hickory() {
            self.stdout()
        } else {
            self.stderr()
        }
    }

    fn stdout(&self) -> Result<String> {
        self.container
            .stdout(&["cat", &self.implementation.stdout_logfile(Role::Resolver)])
    }

    fn stderr(&self) -> Result<String> {
        self.container
            .stdout(&["cat", &self.implementation.stderr_logfile(Role::Resolver)])
    }
}

pub struct ResolverSettings {
    /// Extended DNS Errors (RFC8914)
    ede: bool,
    network: Network,
    roots: Vec<Root>,
    trust_anchor: TrustAnchor,
    custom_config: Option<String>,
    case_randomization: bool,
}

impl ResolverSettings {
    /// Starts a DNS server in the recursive resolver role
    ///
    /// The server uses the implementation based on `$DNS_TEST_SUBJECT` env var.
    pub fn start(&self) -> Result<Resolver> {
        self.start_with_subject(&crate::SUBJECT)
    }

    /// Starts a DNS server in the recursive resolver role
    ///
    /// This server is not an authoritative name server; it does not serve a zone file to clients
    pub fn start_with_subject(&self, implementation: &Implementation) -> Result<Resolver> {
        let image = implementation.clone().into();
        let container = Container::run(&image, &self.network)?;

        let mut hints = String::new();
        for root in &self.roots {
            writeln!(hints, "{root}").unwrap();
        }

        container.cp("/etc/root.hints", &hints)?;

        let use_dnssec = !self.trust_anchor.is_empty();
        let config_contents = if let Some(custom_config) = &self.custom_config {
            custom_config
        } else {
            let config = Config::Resolver {
                use_dnssec,
                netmask: self.network.netmask(),
                ede: self.ede,
                case_randomization: self.case_randomization,
            };
            &implementation.format_config(config)
        };
        if let Some(conf_file_path) = implementation.conf_file_path(Role::Resolver) {
            container.cp(conf_file_path, config_contents)?;
        }

        if use_dnssec {
            let path = if implementation.is_bind() {
                "/etc/bind/bind.keys"
            } else {
                "/etc/trusted-key.key"
            };

            let contents = if implementation.is_bind() {
                self.trust_anchor.delv()
            } else {
                self.trust_anchor.to_string()
            };

            container.cp(path, &contents)?;
        }

        let child = container.spawn(&implementation.cmd_args(Role::Resolver))?;

        Ok(Resolver {
            _child: child,
            container,
            implementation: implementation.clone(),
        })
    }

    /// Enables the Extended DNS Errors (RFC8914) feature
    pub fn extended_dns_errors(&mut self) -> &mut Self {
        self.ede = true;
        self
    }
    /// Adds a root hint
    pub fn root(&mut self, root: Root) -> &mut Self {
        self.roots.push(root);
        self
    }

    /// Adds a DNSKEY record to the trust anchor
    pub fn trust_anchor_key(&mut self, key: DNSKEY) -> &mut Self {
        self.trust_anchor.add(key.clone());
        self
    }

    /// Adds all the keys in the `other` trust anchor to ours
    pub fn trust_anchor(&mut self, other: &TrustAnchor) -> &mut Self {
        for key in other.keys() {
            self.trust_anchor.add(key.clone());
        }
        self
    }

    /// Overrides the automatically-generated configuration file.
    pub fn custom_config(&mut self, config: String) -> &mut Self {
        self.custom_config = Some(config);
        self
    }

    /// Enables case randomization in outgoing query names.
    pub fn case_randomization(&mut self) -> &mut Self {
        self.case_randomization = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use crate::{FQDN, name_server::NameServer};

    use super::*;

    #[test]
    fn unbound_logs_works() -> Result<()> {
        let network = Network::new()?;
        let ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, &network)?.start()?;
        let resolver =
            Resolver::new(&network, ns.root_hint()).start_with_subject(&Implementation::Unbound)?;
        // no way to block until the server has finished starting up so we just give it some
        // arbitrary amount of time
        thread::sleep(Duration::from_secs(1));
        let logs = resolver.logs()?;

        eprintln!("{logs}");
        assert!(logs.contains("start of service"));

        Ok(())
    }

    #[test]
    fn bind_logs_works() -> Result<()> {
        let network = Network::new()?;
        let ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, &network)?.start()?;
        let resolver =
            Resolver::new(&network, ns.root_hint()).start_with_subject(&Implementation::Bind)?;
        // no way to block until the server has finished starting up so we just give it some
        // arbitrary amount of time
        thread::sleep(Duration::from_secs(1));
        let logs = resolver.logs()?;

        eprintln!("{logs}");
        assert!(logs.contains("starting BIND"));

        Ok(())
    }

    #[test]
    fn hickory_logs_works() -> Result<()> {
        let network = Network::new()?;
        let ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, &network)?.start()?;
        let resolver = Resolver::new(&network, ns.root_hint())
            .start_with_subject(&Implementation::hickory())?;
        // no way to block until the server has finished starting up so we just give it some
        // arbitrary amount of time
        thread::sleep(Duration::from_secs(1));
        let logs = resolver.logs()?;

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
    fn pdns_logs_works() -> Result<()> {
        let network = Network::new()?;
        let ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, &network)?.start()?;
        let resolver =
            Resolver::new(&network, ns.root_hint()).start_with_subject(&Implementation::Pdns)?;
        // no way to block until the server has finished starting up so we just give it some
        // arbitrary amount of time
        thread::sleep(Duration::from_secs(1));
        let logs = resolver.logs()?;

        eprintln!("{logs}");
        assert!(logs.contains("Listening for queries"));

        Ok(())
    }
}
