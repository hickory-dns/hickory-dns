use core::fmt;
use std::borrow::Cow;
use std::path::Path;

use url::Url;

use crate::FQDN;

#[derive(Clone, Copy)]
pub enum Config<'a> {
    NameServer {
        origin: &'a FQDN,
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
    Hickory(Repository<'static>),
    Unbound,
}

impl Implementation {
    pub fn supports_ede(&self) -> bool {
        match self {
            Implementation::Bind => false,
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

            Config::NameServer { origin } => match self {
                Self::Bind => {
                    minijinja::render!(
                        include_str!("templates/named.name-server.conf.jinja"),
                        fqdn => origin.as_str()
                    )
                }

                Self::Unbound => {
                    minijinja::render!(
                        include_str!("templates/nsd.conf.jinja"),
                        fqdn => origin.as_str()
                    )
                }

                Self::Hickory(_) => {
                    minijinja::render!(
                        include_str!("templates/hickory.name-server.toml.jinja"),
                        fqdn => origin.as_str()
                    )
                }
            },
        }
    }

    pub(crate) fn conf_file_path(&self, role: Role) -> &'static str {
        match self {
            Self::Bind => "/etc/bind/named.conf",

            Self::Hickory(_) => "/etc/named.toml",

            Self::Unbound => match role {
                Role::NameServer => "/etc/nsd/nsd.conf",
                Role::Resolver => "/etc/unbound/unbound.conf",
            },
        }
    }

    pub(crate) fn cmd_args(&self, role: Role) -> &[&'static str] {
        match self {
            Implementation::Bind => &["named", "-g", "-d5"],

            Implementation::Hickory(_) => &[
                "sh",
                "-c",
                "echo $$ > /tmp/hickory.pid
exec hickory-dns -d",
            ],

            Implementation::Unbound => match role {
                Role::NameServer => &["nsd", "-d"],

                Role::Resolver => &["unbound", "-d"],
            },
        }
    }

    pub(crate) fn pidfile(&self, role: Role) -> &'static str {
        match self {
            Implementation::Bind => "/tmp/named.pid",

            Implementation::Hickory(_) => "/tmp/hickory.pid",

            Implementation::Unbound => match role {
                Role::NameServer => "/tmp/nsd.pid",
                Role::Resolver => "/tmp/unbound.pid",
            },
        }
    }
}

impl fmt::Display for Implementation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Implementation::Bind => "bind",
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
