use core::fmt;
use std::borrow::Cow;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::Serialize;
use url::Url;

use crate::zone_file::ZoneFile;
use crate::{Error, FQDN};

#[derive(Clone)]
pub enum Config<'a> {
    NameServer {
        origin: &'a FQDN,
        use_dnssec: bool,
        additional_zones: HashMap<FQDN, ZoneFile>,
        /// Optional DNS over TLS (DoT) configuration.
        dot: Option<TlsServerConfig>,
    },
    Resolver {
        use_dnssec: bool,
        netmask: &'a str,
        /// Extended DNS error (RFC8914)
        ede: bool,
        case_randomization: bool,
    },
    Forwarder {
        resolver_ip: Ipv4Addr,
        use_dnssec: bool,
    },
}

impl Config<'_> {
    pub fn role(&self) -> Role {
        match self {
            Config::NameServer { .. } => Role::NameServer,
            Config::Resolver { .. } => Role::Resolver,
            Config::Forwarder { .. } => Role::Forwarder,
        }
    }
}

/// Configuration for a TLS server
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct TlsServerConfig {
    /// Path to a PEM encoded certificate chain for the server.
    pub cert_chain: PathBuf,
    /// Path to the PEM encoded private key associated with the leaf cert of `cert_chain`.
    pub private_key: PathBuf,
}

#[derive(Clone, Copy)]
pub enum Role {
    NameServer,
    Resolver,
    Forwarder,
}

#[derive(Clone, Debug)]
pub enum Implementation {
    Bind,
    Dnslib,
    Hickory {
        repo: Repository<'static>,
        crypto_provider: HickoryCryptoProvider,
    },
    Pdns,
    Unbound,
    EdeDotCom,
}

impl Implementation {
    pub fn supports_ede(&self) -> bool {
        match self {
            Implementation::Bind => false,
            Implementation::Dnslib => true,
            Implementation::Hickory { .. } => true,
            Implementation::Pdns => true,
            Implementation::Unbound => true,
            Implementation::EdeDotCom => false, // does not support running a resolver
        }
    }

    /// Returns the latest hickory-dns local revision
    pub fn hickory() -> Self {
        Self::Hickory {
            repo: Repository(crate::repo_root()),
            crypto_provider: HickoryCryptoProvider::AwsLcRs,
        }
    }

    /// A test peer that cannot be changed using the `DNS_TEST_PEER` env variable.
    ///
    /// This is intended for use within `e2e-tests`, not `conformance-tests`.
    pub const fn test_peer() -> Implementation {
        Implementation::Unbound
    }

    #[must_use]
    pub fn is_bind(&self) -> bool {
        matches!(self, Self::Bind)
    }

    #[must_use]
    pub fn is_dnslib(&self) -> bool {
        matches!(self, Self::Dnslib)
    }

    #[must_use]
    pub fn is_hickory(&self) -> bool {
        matches!(self, Self::Hickory { .. })
    }

    #[must_use]
    pub fn is_pdns(&self) -> bool {
        matches!(self, Self::Pdns)
    }

    #[must_use]
    pub fn is_unbound(&self) -> bool {
        matches!(self, Self::Unbound)
    }

    pub(crate) fn format_config(&self, config: Config) -> String {
        match config {
            Config::Resolver {
                use_dnssec,
                netmask,
                ede,
                case_randomization,
            } => match self {
                Self::Bind => {
                    assert!(!ede, "the BIND resolver does not support EDE (RFC8914)");

                    minijinja::render!(
                        include_str!("templates/named.resolver.conf.jinja"),
                        use_dnssec => use_dnssec,
                        netmask => netmask,
                    )
                }

                Self::Dnslib => {
                    // Dnslib resolvers don't have a config
                    "".into()
                }

                Self::Hickory { .. } => {
                    // TODO enable EDE in Hickory when supported
                    minijinja::render!(
                        include_str!("templates/hickory.resolver.toml.jinja"),
                        use_dnssec => use_dnssec,
                        case_randomization => case_randomization,
                    )
                }

                Self::Pdns => {
                    minijinja::render!(
                        include_str!("templates/pdns.resolver.conf.jinja"),
                        use_dnssec => use_dnssec,
                        netmask => netmask,
                        ede => ede,
                        case_randomization => case_randomization,
                    )
                }

                Self::Unbound => {
                    minijinja::render!(
                        include_str!("templates/unbound.conf.jinja"),
                        use_dnssec => use_dnssec,
                        netmask => netmask,
                        ede => ede,
                        case_randomization => case_randomization,
                    )
                }

                Self::EdeDotCom => {
                    // Does not support running a resolver
                    "".into()
                }
            },

            Config::NameServer {
                origin,
                use_dnssec,
                additional_zones,
                dot,
            } => match self {
                Self::Bind => {
                    minijinja::render!(
                        include_str!("templates/named.name-server.conf.jinja"),
                        fqdn => origin.as_str(),
                        additional_zones => additional_zones.keys().map(|x| x.as_str()).collect::<Vec<&str>>(),
                        dot => dot,
                    )
                }

                Self::Dnslib => {
                    // Dnslib name servers don't have a config
                    "".into()
                }

                Self::Unbound => {
                    minijinja::render!(
                        include_str!("templates/nsd.conf.jinja"),
                        fqdn => origin.as_str(),
                        additional_zones => additional_zones.keys().map(|x| x.as_str()).collect::<Vec<&str>>(),
                        dot => dot,
                    )
                }

                Self::Hickory {
                    crypto_provider, ..
                } => {
                    let use_pkcs8 = matches!(crypto_provider, HickoryCryptoProvider::Ring);
                    minijinja::render!(
                        include_str!("templates/hickory.name-server.toml.jinja"),
                        fqdn => origin.as_str(),
                        use_dnssec => use_dnssec,
                        additional_zones => additional_zones.keys().map(|x| x.as_str()).collect::<Vec<&str>>(),
                        use_pkcs8 => use_pkcs8,
                        dot => dot,
                    )
                }

                Self::Pdns => minijinja::render!(
                    include_str!("templates/pdns-auth.conf.jinja"),
                    use_dnssec => use_dnssec,
                ),

                Self::EdeDotCom => include_str!("templates/named.ede-dot-com.conf").into(),
            },

            Config::Forwarder {
                resolver_ip,
                use_dnssec,
            } => match self {
                Self::Bind => minijinja::render!(
                    include_str!("templates/named.forwarder.conf.jinja"),
                    resolver_ip => resolver_ip,
                    use_dnssec => use_dnssec,
                ),

                Self::Dnslib => {
                    // Dnslib servers don't have a config
                    "".into()
                }

                Self::Hickory { .. } => minijinja::render!(
                    include_str!("templates/hickory.forwarder.toml.jinja"),
                    resolver_ip => resolver_ip,
                    use_dnssec => use_dnssec,
                ),

                Self::Pdns => minijinja::render!(
                    include_str!("templates/pdns.forwarder.conf.jinja"),
                    resolver_ip => resolver_ip,
                    use_dnssec => use_dnssec,
                ),

                Self::Unbound => minijinja::render!(
                    include_str!("templates/unbound.forwarder.conf.jinja"),
                    resolver_ip => resolver_ip,
                    use_dnssec => use_dnssec,
                ),

                Self::EdeDotCom => {
                    // Does not support running a forwarder
                    "".into()
                }
            },
        }
    }

    pub(crate) fn conf_file_path(&self, role: Role) -> Option<&'static str> {
        match self {
            Self::Bind => Some("/etc/bind/named.conf"),

            Self::Dnslib => None,

            Self::Hickory { .. } => Some("/etc/named.toml"),

            Self::Pdns => match role {
                Role::Resolver | Role::Forwarder => Some("/etc/powerdns/recursor.yml"),
                Role::NameServer => Some("/etc/powerdns/pdns.conf"),
            },

            Self::Unbound => match role {
                Role::NameServer => Some("/etc/nsd/nsd.conf"),
                Role::Resolver | Role::Forwarder => Some("/etc/unbound/unbound.conf"),
            },

            Self::EdeDotCom => Some("/etc/named.conf"),
        }
    }

    pub(crate) fn cmd_args(&self, role: Role) -> Vec<String> {
        let base = match self {
            Implementation::Bind | Implementation::EdeDotCom => "named -g -d5",
            Implementation::Dnslib => "python3 /script.py",
            Implementation::Hickory { .. } => "hickory-dns -d",
            Implementation::Pdns => match role {
                Role::Resolver | Role::Forwarder => "pdns_recursor",
                Role::NameServer => "pdns_server",
            },
            Implementation::Unbound => match role {
                Role::NameServer => "nsd -d",
                Role::Resolver | Role::Forwarder => "unbound -d",
            },
        };

        vec![
            "sh".into(),
            "-c".into(),
            format!(
                "{base} >{} 2>{}",
                self.stdout_logfile(role),
                self.stderr_logfile(role)
            ),
        ]
    }

    pub(crate) fn stdout_logfile(&self, role: Role) -> String {
        self.logfile(role, Stream::Stdout)
    }

    pub(crate) fn stderr_logfile(&self, role: Role) -> String {
        self.logfile(role, Stream::Stderr)
    }

    fn logfile(&self, role: Role, stream: Stream) -> String {
        let suffix = stream.as_str();

        let path = match self {
            Implementation::Bind | Implementation::EdeDotCom => "/tmp/named",

            Implementation::Dnslib => "/tmp/dnslib",

            Implementation::Hickory { .. } => "/tmp/hickory",

            Implementation::Pdns => "/tmp/pdns",

            Implementation::Unbound => match role {
                Role::NameServer => "/tmp/nsd",
                Role::Resolver | Role::Forwarder => "/tmp/unbound",
            },
        };

        format!("{path}.{suffix}")
    }
}

/// A cryptography provider used to enable HickoryDNS Cargo features that depend on cryptography.
///
/// For example, one of `dnssec-aws-lc-rs` or `dnssec-ring`.
#[derive(Debug, Clone, Copy)]
pub enum HickoryCryptoProvider {
    AwsLcRs,
    Ring,
}

impl fmt::Display for HickoryCryptoProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AwsLcRs => "aws-lc-rs",
            Self::Ring => "ring",
        })
    }
}

impl FromStr for HickoryCryptoProvider {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "aws-lc-rs" => Ok(Self::AwsLcRs),
            "ring" => Ok(Self::Ring),
            _ => Err(
                format!("invalid value for DNSSEC_FEATURE: {s}, expected aws-lc-rs or ring").into(),
            ),
        }
    }
}

#[derive(Clone, Copy)]
enum Stream {
    Stdout,
    Stderr,
}

impl Stream {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Repository<'a> {
    inner: Cow<'a, str>,
}

impl Repository<'_> {
    pub(crate) fn as_str(&self) -> &str {
        &self.inner
    }
}

/// checks that `input` looks like a valid repository which can be either local or remote
///
/// # Panics
///
/// this function panics if `input` is not a local `Path` that exists or a well-formed URL
#[allow(non_snake_case)]
pub fn Repository(input: impl Into<Cow<'static, str>>) -> Repository<'static> {
    let input = input.into();
    assert!(
        Path::new(&*input).exists() || Url::parse(&input).is_ok(),
        "{input} is not a valid repository"
    );
    Repository { inner: input }
}

impl Default for Implementation {
    fn default() -> Self {
        Self::Unbound
    }
}
