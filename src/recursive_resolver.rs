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
    use crate::{record::Referral, AuthoritativeNameServer, Domain};

    use super::*;

    #[test]
    fn can_resolve() -> Result<()> {
        let tld_ns = AuthoritativeNameServer::start(Domain("com.")?, &[])?;

        let root_ns = AuthoritativeNameServer::start(
            Domain::ROOT,
            &[Referral {
                domain: Domain("com.")?,
                ipv4_addr: tld_ns.ipv4_addr(),
                ns: tld_ns.nameserver().clone(),
            }],
        )?;

        let roots = &[Root::new(root_ns.nameserver().clone(), root_ns.ipv4_addr())];
        let resolver = RecursiveResolver::start(roots)?;
        let resolver_ip_addr = resolver.ipv4_addr();

        let container = Container::run()?;
        let output =
            container.output(&["dig", &format!("@{}", resolver_ip_addr), "example.com"])?;

        eprintln!("{}", output.stdout);

        assert!(output.status.success());
        assert!(output.stdout.contains("status: NOERROR"));

        Ok(())
    }
}
