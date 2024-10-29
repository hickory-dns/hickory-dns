use core::fmt;
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::Path;

use url::Url;

use crate::zone_file::ZoneFile;
use crate::FQDN;

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
    Hickory(Repository<'static>),
    Unbound,
}

impl Implementation {
    pub fn supports_ede(&self) -> bool {
        match self {
            Implementation::Bind => false,
            Implementation::Dnslib => true,
            Implementation::Hickory(_) => true,
            Implementation::Unbound => true,
        }
    }

    /// Returns the latest hickory-dns local revision
    pub fn hickory() -> Self {
        Self::Hickory(Repository(crate::repo_root()))
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
        matches!(self, Self::Hickory(_))
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

                Self::Hickory(_) => {
                    // TODO enable EDE in Hickory when supported
                    minijinja::render!(
                        include_str!("templates/hickory.resolver.toml.jinja"),
                        use_dnssec => use_dnssec,
                    )
                }

                Self::Unbound => {
                    minijinja::render!(
                        include_str!("templates/unbound.conf.jinja"),
                        use_dnssec => use_dnssec,
                        netmask => netmask,
                        ede => ede,
                    )
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

                Self::Hickory(_) => {
                    minijinja::render!(
                        include_str!("templates/hickory.name-server.toml.jinja"),
                        fqdn => origin.as_str(),
                        use_dnssec => use_dnssec,
                        additional_zones => additional_zones.keys().map(|x| x.as_str()).collect::<Vec<&str>>(),
                    )
                }
            },
        }
    }

    pub(crate) fn conf_file_path(&self, role: Role) -> Option<&'static str> {
        match self {
            Self::Bind => Some("/etc/bind/named.conf"),

            Self::Dnslib => None,

            Self::Hickory(_) => Some("/etc/named.toml"),

            Self::Unbound => match role {
                Role::NameServer => Some("/etc/nsd/nsd.conf"),
                Role::Resolver => Some("/etc/unbound/unbound.conf"),
            },
        }
    }

    pub(crate) fn cmd_args(&self, role: Role) -> Vec<String> {
        let base = match self {
            Implementation::Bind => "named -g -d5",
            Implementation::Dnslib => "python3 /script.py",
            Implementation::Hickory(_) => "hickory-dns -d",
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
            Implementation::Bind => "/tmp/named",

            Implementation::Dnslib => "/tmp/dnslib",

            Implementation::Hickory(_) => "/tmp/hickory",

            Implementation::Unbound => match role {
                Role::NameServer => "/tmp/nsd",
                Role::Resolver => "/tmp/unbound",
            },
        };

        format!("{path}.{suffix}")
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

impl fmt::Display for Implementation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Implementation::Bind => "bind",
            Implementation::Dnslib => "dnslib",
            Implementation::Hickory(_) => "hickory",
            Implementation::Unbound => "unbound",
        };

        f.write_str(s)
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
