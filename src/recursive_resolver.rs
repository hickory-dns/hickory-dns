use core::fmt::Write;
use std::net::Ipv4Addr;
use std::process::Child;

use crate::container::Container;
use crate::record::Root;
use crate::{Result, CHMOD_RW_EVERYONE};

pub struct RecursiveResolver {
    container: Container,
    child: Child,
}

impl RecursiveResolver {
    pub fn start(roots: &[Root]) -> Result<Self> {
        let container = Container::run()?;

        let mut hints = String::new();
        for root in roots {
            writeln!(hints, "{root}").unwrap();
        }

        container.cp("/etc/unbound/root.hints", &hints, CHMOD_RW_EVERYONE)?;

        let child = container.spawn(&["unbound", "-d"])?;

        Ok(Self { child, container })
    }

    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.container.ipv4_addr()
    }
}

impl Drop for RecursiveResolver {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        record::{self, Referral},
        AuthoritativeNameServer, Domain,
    };

    use super::*;

    #[test]
    fn can_resolve() -> Result<()> {
        let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
        let needle = Domain("example.nameservers.com.")?;
        let root_ns = AuthoritativeNameServer::reserve()?;
        let com_ns = AuthoritativeNameServer::reserve()?;

        let nameservers_domain = Domain("nameservers.com.")?;
        let nameservers_ns = AuthoritativeNameServer::start(
            nameservers_domain.clone(),
            &[],
            &[
                record::A {
                    domain: root_ns.nameserver().clone(),
                    ipv4_addr: root_ns.ipv4_addr(),
                },
                record::A {
                    domain: com_ns.nameserver().clone(),
                    ipv4_addr: com_ns.ipv4_addr(),
                },
                record::A {
                    domain: needle.clone(),
                    ipv4_addr: expected_ipv4_addr,
                },
            ],
        )?;

        eprintln!("nameservers.com.zone:\n{}", nameservers_ns.zone());

        let com_domain = Domain("com.")?;
        let com_ns = com_ns.start(
            com_domain.clone(),
            &[Referral {
                domain: nameservers_domain,
                ipv4_addr: nameservers_ns.ipv4_addr(),
                ns: nameservers_ns.nameserver().clone(),
            }],
            &[],
        )?;

        eprintln!("com.zone:\n{}", com_ns.zone());

        let root_ns = root_ns.start(
            Domain::ROOT,
            &[Referral {
                domain: com_domain,
                ipv4_addr: com_ns.ipv4_addr(),
                ns: com_ns.nameserver().clone(),
            }],
            &[],
        )?;

        eprintln!("root.zone:\n{}", root_ns.zone());

        let roots = &[Root::new(root_ns.nameserver().clone(), root_ns.ipv4_addr())];
        let resolver = RecursiveResolver::start(roots)?;
        let resolver_ip_addr = resolver.ipv4_addr();

        let container = Container::run()?;
        let output = container.output(&[
            "dig",
            &format!("@{}", resolver_ip_addr),
            &needle.to_string(),
        ])?;

        eprintln!("{}", output.stdout);

        assert!(output.status.success());
        assert!(output.stdout.contains("status: NOERROR"));

        let mut found = false;
        let needle = needle.to_string();
        for line in output.stdout.lines() {
            if line.starts_with(&needle) {
                found = true;
                assert!(line.ends_with(&expected_ipv4_addr.to_string()));
            }
        }

        assert!(found);

        Ok(())
    }
}
