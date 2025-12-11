//! A test framework for all things DNS

use std::io::{Read as _, Write as _};
use std::sync::LazyLock;
use std::{env, io};

use client::Client;
use name_server::{NameServer, Running};

pub use crate::container::Network;
pub use crate::forwarder::{Forwarder, ForwarderSettings};
pub use crate::fqdn::FQDN;
pub use crate::implementation::{HickoryCryptoProvider, Implementation, Repository, Role};
pub use crate::pki::Pki;
pub use crate::resolver::{Resolver, ResolverSettings};
pub use crate::trust_anchor::TrustAnchor;

pub mod client;
pub mod container;
mod forwarder;
mod fqdn;
mod implementation;
pub mod name_server;
pub mod nsec3;
pub mod pki;
pub mod record;
mod resolver;
mod trust_anchor;
pub mod tshark;
pub mod zone_file;

pub type Error = Box<dyn std::error::Error>;

// TODO maybe this should be a TLS variable that each unit test (thread) can override
const DEFAULT_TTL: u32 = 24 * 60 * 60; // 1 day

pub static SUBJECT: LazyLock<Implementation> = LazyLock::new(parse_subject);
pub static PEER: LazyLock<Implementation> = LazyLock::new(parse_peer);

/// Helper to prevent a unit test from immediately terminating so its associated containers can be
/// manually inspected
pub fn inspect(
    clients: &[Client],
    resolvers: &[Resolver],
    nameservers: &[NameServer<Running>],
    forwarders: &[Forwarder],
) {
    use core::fmt::Write as _;

    let mut output = String::new();

    if !clients.is_empty() {
        output.push_str("\n\nCLIENTS");
    }

    for client in clients {
        write!(output, "\n{} {}", client.container_id(), client.ipv4_addr()).unwrap();
    }

    if !resolvers.is_empty() {
        output.push_str("\n\nRESOLVERS");
    }

    for resolver in resolvers {
        write!(
            output,
            "\n{} {}",
            resolver.container_id(),
            resolver.ipv4_addr()
        )
        .unwrap();
    }

    if !nameservers.is_empty() {
        output.push_str("\n\nNAME SERVERS");
    }

    for nameserver in nameservers {
        write!(
            output,
            "\n{} {} {}",
            nameserver.container_id(),
            nameserver.ipv4_addr(),
            nameserver.zone(),
        )
        .unwrap();
    }

    if !forwarders.is_empty() {
        output.push_str("\n\nFORWARDERS");
    }

    for forwarder in forwarders {
        write!(
            output,
            "\n{} {}",
            forwarder.container_id(),
            forwarder.ipv4_addr()
        )
        .unwrap();
    }

    output.push_str("\n\ntest paused. press ENTER to continue\n\n");

    // try to write everything in a single system call to avoid this output interleaving with the
    // output of other tests (when `--nocapture` is used)
    io::stdout().write_all(output.as_bytes()).unwrap();

    // block this thread until user provides some input
    let mut buf = [0];
    let _ = io::stdin().read(&mut buf).unwrap();
}

fn parse_subject() -> Implementation {
    parse_implementation("DNS_TEST_SUBJECT")
}

fn parse_peer() -> Implementation {
    parse_implementation("DNS_TEST_PEER")
}

fn parse_implementation(env_var: &str) -> Implementation {
    if let Ok(subject) = env::var(env_var) {
        if subject == "unbound" {
            return Implementation::Unbound;
        }

        if subject == "bind" {
            return Implementation::Bind;
        }

        if subject == "pdns" {
            return Implementation::Pdns;
        }

        if subject.starts_with("hickory ") {
            let tokens = subject.split_ascii_whitespace().collect::<Vec<_>>();
            let Ok([_, url, crypto_provider]) = <[&str; 3]>::try_from(tokens) else {
                panic!(
                    "the syntax of {env_var} is 'hickory $URL $CRYPTO_PROVIDER', e.g. \
                    'hickory /tmp/hickory aws-lc-rs' or \
                    'hickory https://github.com/owner/repo ring'"
                )
            };
            Implementation::Hickory {
                repo: Repository(url.to_string()),
                crypto_provider: crypto_provider.parse().unwrap(),
            }
        } else {
            panic!("unknown implementation: {subject}")
        }
    } else {
        Implementation::default()
    }
}

fn repo_root() -> String {
    use std::path::PathBuf;

    let mut repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")); // /conformance/dns-test
    repo_root.pop(); // /conformance
    repo_root.pop(); // /
    repo_root.display().to_string()
}
