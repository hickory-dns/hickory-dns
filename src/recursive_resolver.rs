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
        client::{RecordType, Recurse},
        record::Referral,
        Client, Domain, NameServer,
    };

    use super::*;

    #[test]
    fn can_resolve() -> Result<()> {
        let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
        let needle = Domain("example.nameservers.com.")?;

        let mut root_ns = NameServer::new(Domain::ROOT)?;
        let mut com_ns = NameServer::new(Domain::COM)?;

        let nameservers_domain = Domain("nameservers.com.")?;
        let mut nameservers_ns = NameServer::new(nameservers_domain.clone())?;
        nameservers_ns
            .a(root_ns.nameserver().clone(), root_ns.ipv4_addr())
            .a(com_ns.nameserver().clone(), com_ns.ipv4_addr())
            .a(needle.clone(), expected_ipv4_addr);
        let nameservers_ns = nameservers_ns.start()?;

        eprintln!("nameservers.com.zone:\n{}", nameservers_ns.zone_file());

        com_ns.referral(&Referral {
            domain: nameservers_domain,
            ipv4_addr: nameservers_ns.ipv4_addr(),
            ns: nameservers_ns.nameserver().clone(),
        });
        let com_ns = com_ns.start()?;

        eprintln!("com.zone:\n{}", com_ns.zone_file());

        root_ns.referral(&Referral {
            domain: Domain::COM,
            ipv4_addr: com_ns.ipv4_addr(),
            ns: com_ns.nameserver().clone(),
        });
        let root_ns = root_ns.start()?;

        eprintln!("root.zone:\n{}", root_ns.zone_file());

        let roots = &[Root::new(root_ns.nameserver().clone(), root_ns.ipv4_addr())];
        let resolver = RecursiveResolver::start(roots)?;
        let resolver_ip_addr = resolver.ipv4_addr();

        let client = Client::new()?;
        let output = client.dig(Recurse::Yes, resolver_ip_addr, RecordType::A, &needle)?;

        assert!(output.status.is_noerror());

        let [answer] = output.answer.try_into().unwrap();
        let a = answer.try_into_a().unwrap();

        assert_eq!(needle, a.domain);
        assert_eq!(expected_ipv4_addr, a.ipv4_addr);

        Ok(())
    }
}
