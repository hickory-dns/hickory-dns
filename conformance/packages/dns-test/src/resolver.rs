use core::fmt::Write;
use std::io::{BufRead, BufReader};
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
    child: Child,
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
        }
    }

    pub fn eavesdrop(&self) -> Result<Tshark> {
        self.container.eavesdrop()
    }

    pub fn network(&self) -> &Network {
        self.container.network()
    }

    pub fn container_id(&self) -> &str {
        self.container.id()
    }

    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.container.ipv4_addr()
    }

    /// Gracefully terminates the name server collecting all logs
    pub fn terminate(self) -> Result<String> {
        let Resolver {
            implementation,
            container,
            child,
        } = self;

        let pidfile = implementation.pidfile(Role::Resolver);
        let kill = format!(
            "test -f {pidfile} || sleep 1
kill -TERM $(cat {pidfile})"
        );
        container.status_ok(&["sh", "-c", &kill])?;
        let output = child.wait()?;

        // the hickory-dns binary does not do signal handling so it won't shut down gracefully; we
        // will still get some logs so we'll ignore the fact that it fails to shut down ...
        if !implementation.is_hickory() && !output.status.success() {
            return Err(format!("could not terminate the `{}` process", implementation).into());
        }

        assert!(
            output.stderr.is_empty(),
            "stderr should be returned if not empty"
        );
        Ok(output.stdout)
    }
}

pub struct ResolverSettings {
    /// Extended DNS Errors (RFC8914)
    ede: bool,
    network: Network,
    roots: Vec<Root>,
    trust_anchor: TrustAnchor,
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
        let config = Config::Resolver {
            use_dnssec,
            netmask: self.network.netmask(),
            ede: self.ede,
        };
        container.cp(
            implementation.conf_file_path(config.role()),
            &implementation.format_config(config),
        )?;

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

        let mut child = container.spawn(implementation.cmd_args(config.role()))?;

        // For HickoryDNS we need to wait until its start sequence finished. Only then the server is able
        // to accept connections. The start sequence logs are consumed here.
        if implementation.is_hickory() {
            let stdout = child.stdout()?;
            let lines = BufReader::new(stdout).lines();

            for line in lines {
                let line = line?;
                if line.contains("server starting up") {
                    break;
                }
            }
        }

        Ok(Resolver {
            child,
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
}

#[cfg(test)]
mod tests {
    use crate::{name_server::NameServer, FQDN};

    use super::*;

    #[test]
    fn terminate_unbound_works() -> Result<()> {
        let network = Network::new()?;
        let ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, &network)?.start()?;
        let resolver =
            Resolver::new(&network, ns.root_hint()).start_with_subject(&Implementation::Unbound)?;
        let logs = resolver.terminate()?;

        eprintln!("{logs}");
        assert!(logs.contains("start of service"));

        Ok(())
    }

    #[test]
    fn terminate_bind_works() -> Result<()> {
        let network = Network::new()?;
        let ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, &network)?.start()?;
        let resolver =
            Resolver::new(&network, ns.root_hint()).start_with_subject(&Implementation::Bind)?;
        let logs = resolver.terminate()?;

        eprintln!("{logs}");
        assert!(logs.contains("starting BIND"));

        Ok(())
    }

    #[test]
    fn terminate_hickory_works() -> Result<()> {
        let network = Network::new()?;
        let ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, &network)?.start()?;
        let resolver = Resolver::new(&network, ns.root_hint())
            .start_with_subject(&Implementation::hickory())?;
        let logs = resolver.terminate()?;

        // Hickory-DNS start sequence log has been consumed in `ResolverSettings.start`.
        assert!(logs.is_empty());

        Ok(())
    }
}
