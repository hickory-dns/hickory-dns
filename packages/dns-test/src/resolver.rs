use core::fmt::Write;
use std::net::Ipv4Addr;

use crate::container::{Child, Container, Network};
use crate::implementation::{Config, Role};
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
    /// Starts a DNS server in the recursive resolver role
    ///
    /// This server is not an authoritative name server; it does not server a zone file to clients
    ///
    /// # Panics
    ///
    /// This constructor panics if `roots` is an empty slice
    pub fn start(
        implementation: &Implementation,
        roots: &[Root],
        trust_anchor: &TrustAnchor,
        network: &Network,
    ) -> Result<Self> {
        assert!(
            !roots.is_empty(),
            "must configure at least one local root server"
        );

        let image = implementation.clone().into();
        let container = Container::run(&image, network)?;

        let mut hints = String::new();
        for root in roots {
            writeln!(hints, "{root}").unwrap();
        }

        container.cp("/etc/root.hints", &hints)?;

        let use_dnssec = !trust_anchor.is_empty();
        let config = Config::Resolver {
            use_dnssec,
            netmask: network.netmask(),
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
                trust_anchor.delv()
            } else {
                trust_anchor.to_string()
            };

            container.cp(path, &contents)?;
        }

        let child = container.spawn(implementation.cmd_args(config.role()))?;

        Ok(Self {
            child,
            container,
            implementation: implementation.clone(),
        })
    }

    pub fn eavesdrop(&self) -> Result<Tshark> {
        self.container.eavesdrop()
    }

    pub fn container_id(&self) -> &str {
        self.container.id()
    }

    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.container.ipv4_addr()
    }

    /// gracefully terminates the name server collecting all logs
    pub fn terminate(self) -> Result<String> {
        let pidfile = self.implementation.pidfile(Role::Resolver);
        let kill = format!(
            "test -f {pidfile} || sleep 1
kill -TERM $(cat {pidfile})"
        );
        self.container.status_ok(&["sh", "-c", &kill])?;
        let output = self.child.wait()?;

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

#[cfg(test)]
mod tests {
    use crate::{name_server::NameServer, FQDN};

    use super::*;

    #[test]
    fn terminate_unbound_works() -> Result<()> {
        let network = Network::new()?;
        let ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, &network)?.start()?;
        let resolver = Resolver::start(
            &Implementation::Unbound,
            &[Root::new(ns.fqdn().clone(), ns.ipv4_addr())],
            &TrustAnchor::empty(),
            &network,
        )?;
        let logs = resolver.terminate()?;

        eprintln!("{logs}");
        assert!(logs.contains("start of service"));

        Ok(())
    }

    #[test]
    fn terminate_bind_works() -> Result<()> {
        let network = Network::new()?;
        let ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, &network)?.start()?;
        let resolver = Resolver::start(
            &Implementation::Bind,
            &[Root::new(ns.fqdn().clone(), ns.ipv4_addr())],
            &TrustAnchor::empty(),
            &network,
        )?;
        let logs = resolver.terminate()?;

        eprintln!("{logs}");
        assert!(logs.contains("starting BIND"));

        Ok(())
    }
}
