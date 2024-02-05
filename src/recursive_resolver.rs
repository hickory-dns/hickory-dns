use std::net::Ipv4Addr;
use std::process::Child;

use serde::Serialize;

use crate::container::Container;
use crate::{Result, CHMOD_RW_EVERYONE};

pub struct RecursiveResolver {
    container: Container,
    child: Child,
}

#[derive(Serialize)]
pub struct RootServer {
    name: String,
    ip_addr: Ipv4Addr,
}

fn root_hints(roots: &[RootServer]) -> String {
    minijinja::render!(
        include_str!("templates/root.hints.jinja"),
        roots => roots
    )
}

impl RecursiveResolver {
    pub fn start(root_servers: &[RootServer]) -> Result<Self> {
        let container = Container::run()?;

        container.cp(
            "/etc/unbound/root.hints",
            &root_hints(root_servers),
            CHMOD_RW_EVERYONE,
        )?;

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
    use crate::AuthoritativeNameServer;

    use super::*;

    #[test]
    #[ignore = "FIXME"]
    fn can_resolve() -> Result<()> {
        let root_ns = AuthoritativeNameServer::start(crate::Domain::Root)?;
        let roots = &[RootServer {
            name: "my.root-server.com".to_string(),
            ip_addr: root_ns.ipv4_addr(),
        }];
        let resolver = RecursiveResolver::start(roots)?;
        let resolver_ip_addr = resolver.ipv4_addr();

        let container = Container::run()?;
        let output =
            container.output(&["dig", &format!("@{}", resolver_ip_addr), "example.com"])?;

        assert!(output.status.success());
        assert!(output.stdout.contains("status: NOERROR"));

        Ok(())
    }

    #[test]
    fn root_hints_template_works() {
        let expected = [
            ("a.root-server.com", Ipv4Addr::new(172, 17, 0, 1)),
            ("b.root-server.com", Ipv4Addr::new(172, 17, 0, 2)),
        ];

        let roots = expected
            .iter()
            .map(|(ns_name, ip_addr)| RootServer {
                name: ns_name.to_string(),
                ip_addr: *ip_addr,
            })
            .collect::<Vec<_>>();

        let hints = root_hints(&roots);

        eprintln!("{hints}");
        let lines = hints.lines().collect::<Vec<_>>();

        for (lines, (expected_ns_name, expected_ip_addr)) in lines.chunks(2).zip(expected) {
            let [ns_record, a_record] = lines.try_into().unwrap();

            // block to avoid shadowing
            {
                let [domain, _ttl, record_type, ns_name] = ns_record
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();

                assert_eq!(".", domain);
                assert_eq!("NS", record_type);
                assert_eq!(expected_ns_name, ns_name);
            }

            let [ns_name, _ttl, record_type, ip_addr] = a_record
                .split_whitespace()
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            assert_eq!(expected_ns_name, ns_name);
            assert_eq!("A", record_type);
            assert_eq!(expected_ip_addr.to_string(), ip_addr);
        }
    }
}
