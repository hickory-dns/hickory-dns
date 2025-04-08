use std::net::Ipv4Addr;

use crate::{
    Implementation, Network, Resolver, Result, TrustAnchor,
    container::{Child, Container},
    implementation::{Config, Role},
    record::DNSKEY,
};

pub struct Forwarder {
    container: Container,
    _child: Child,
    implementation: Implementation,
}

impl Forwarder {
    #[allow(clippy::new_ret_no_self)]
    pub fn new<'a>(network: &Network, resolver: &'a Resolver) -> ForwarderSettings<'a> {
        ForwarderSettings {
            network: network.clone(),
            resolver,
            trust_anchor: TrustAnchor::empty(),
        }
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
            .stdout(&["cat", &self.implementation.stdout_logfile(Role::Forwarder)])
    }

    fn stderr(&self) -> Result<String> {
        self.container
            .stdout(&["cat", &self.implementation.stderr_logfile(Role::Forwarder)])
    }
}

pub struct ForwarderSettings<'a> {
    network: Network,
    resolver: &'a Resolver,
    trust_anchor: TrustAnchor,
}

impl ForwarderSettings<'_> {
    /// Starts a DNS server in the forwarder role.
    ///
    /// The server uses the implementation chosen by the `$DNS_TEST_SUBJECT` environment variable.
    pub fn start(&self) -> Result<Forwarder> {
        self.start_with_subject(&crate::SUBJECT)
    }

    /// Starts a DNS server in the forwarder role.
    pub fn start_with_subject(&self, implementation: &Implementation) -> Result<Forwarder> {
        let image = implementation.clone().into();
        let container = Container::run(&image, &self.network)?;

        let use_dnssec = !self.trust_anchor.is_empty();
        let config = Config::Forwarder {
            use_dnssec,
            resolver_ip: self.resolver.ipv4_addr(),
        };
        let config_contents = implementation.format_config(config);
        if let Some(conf_file_path) = implementation.conf_file_path(Role::Forwarder) {
            container.cp(conf_file_path, &config_contents)?;
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

        let child = container.spawn(&implementation.cmd_args(Role::Forwarder))?;

        Ok(Forwarder {
            container,
            _child: child,
            implementation: implementation.clone(),
        })
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
