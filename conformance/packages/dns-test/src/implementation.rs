use core::fmt;
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;

use url::Url;

use crate::zone_file::ZoneFile;
use crate::{Error, FQDN};

#[derive(Clone)]
pub enum Config<'a> {
    NameServer {
        origin: &'a FQDN,
        use_dnssec: bool,
        additional_zones: HashMap<FQDN, ZoneFile>,
    },
    Resolver {
        use_dnssec: bool,
        netmask: &'a str,
        /// Extended DNS error (RFC8914)
        ede: bool,
        case_randomization: bool,
    },
}

impl Config<'_> {
    pub fn role(&self) -> Role {
        match self {
            Config::NameServer { .. } => Role::NameServer,
            Config::Resolver { .. } => Role::Resolver,
        }
    }
}

#[derive(Clone, Copy)]
pub enum Role {
    NameServer,
    Resolver,
}

#[derive(Clone, Debug)]
pub enum Implementation {
    Bind,
    Dnslib,
    Hickory {
        repo: Repository<'static>,
        dnssec_feature: Option<HickoryDnssecFeature>,
    },
    Unbound,
    EdeDotCom,
}

impl Implementation {
    pub fn supports_ede(&self) -> bool {
        match self {
            Implementation::Bind => false,
            Implementation::Dnslib => true,
            Implementation::Hickory { .. } => true,
            Implementation::Unbound => true,
            Implementation::EdeDotCom => false, // does not support running a resolver
        }
    }

    /// Returns the latest hickory-dns local revision
    pub fn hickory() -> Self {
        Self::Hickory {
            repo: Repository(crate::repo_root()),
            dnssec_feature: None,
        }
    }

    /// A test peer that cannot be changed using the `DNS_TEST_PEER` env variable
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
            } => match self {
                Self::Bind => {
                    minijinja::render!(
                        include_str!("templates/named.name-server.conf.jinja"),
                        fqdn => origin.as_str(),
                        additional_zones => additional_zones.keys().map(|x| x.as_str()).collect::<Vec<&str>>(),
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
                    )
                }

                Self::Hickory { dnssec_feature, .. } => {
                    let use_pkcs8 =
                        matches!(dnssec_feature, None | Some(HickoryDnssecFeature::Ring));
                    minijinja::render!(
                        include_str!("templates/hickory.name-server.toml.jinja"),
                        fqdn => origin.as_str(),
                        use_dnssec => use_dnssec,
                        additional_zones => additional_zones.keys().map(|x| x.as_str()).collect::<Vec<&str>>(),
                        use_pkcs8 => use_pkcs8,
                    )
                }

                Self::EdeDotCom => include_str!("templates/named.ede-dot-com.conf").into(),
            },
        }
    }

    pub(crate) fn conf_file_path(&self, role: Role) -> Option<&'static str> {
        match self {
            Self::Bind => Some("/etc/bind/named.conf"),

            Self::Dnslib => None,

            Self::Hickory { .. } => Some("/etc/named.toml"),

            Self::Unbound => match role {
                Role::NameServer => Some("/etc/nsd/nsd.conf"),
                Role::Resolver => Some("/etc/unbound/unbound.conf"),
            },

            Self::EdeDotCom => Some("/etc/named.conf"),
        }
    }

    pub(crate) fn cmd_args(&self, role: Role) -> Vec<String> {
        let base = match self {
            Implementation::Bind | Implementation::EdeDotCom => "named -g -d5",
            Implementation::Dnslib => "python3 /script.py",
            Implementation::Hickory { .. } => "hickory-dns -d",
            Implementation::Unbound => match role {
                Role::NameServer => "nsd -d",
                Role::Resolver => "unbound -d",
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

            Implementation::Unbound => match role {
                Role::NameServer => "/tmp/nsd",
                Role::Resolver => "/tmp/unbound",
            },
        };

        format!("{path}.{suffix}")
    }
}

/// A Hickory DNS Cargo feature used to enable DNSSEC with a particular cryptography library.
#[derive(Debug, Clone, Copy)]
pub enum HickoryDnssecFeature {
    AwsLcRs,
    Ring,
}

impl fmt::Display for HickoryDnssecFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AwsLcRs => "dnssec-aws-lc-rs",
            Self::Ring => "dnssec-ring",
        })
    }
}

impl FromStr for HickoryDnssecFeature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dnssec-aws-lc-rs" => Ok(Self::AwsLcRs),
            "dnssec-ring" => Ok(Self::Ring),
            _ => {
                Err(format!("invalid value for DNSSEC_FEATURE: {s}, expected  dnssec-ring").into())
            }
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
