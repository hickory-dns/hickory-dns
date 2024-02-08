use core::fmt::Write;
use std::net::Ipv4Addr;

use crate::container::{Child, Container};
use crate::zone_file::{Root, DNSKEY};
use crate::Result;

pub struct RecursiveResolver {
    container: Container,
    child: Child,
}

impl RecursiveResolver {
    pub fn start(roots: &[Root], trust_anchors: &[DNSKEY]) -> Result<Self> {
        const TRUST_ANCHOR_FILE: &str = "/etc/trusted-key.key";

        let container = Container::run()?;

        let mut hints = String::new();
        for root in roots {
            writeln!(hints, "{root}").unwrap();
        }

        container.cp("/etc/unbound/root.hints", &hints)?;

        let use_dnssec = !trust_anchors.is_empty();
        container.cp("/etc/unbound/unbound.conf", &unbound_conf(use_dnssec))?;

        if use_dnssec {
            let trust_anchor = trust_anchors.iter().fold(String::new(), |mut buf, ds| {
                writeln!(buf, "{ds}").expect("infallible");
                buf
            });

            container.cp(TRUST_ANCHOR_FILE, &trust_anchor)?;
        }

        let child = container.spawn(&["unbound", "-d"])?;

        Ok(Self { child, container })
    }

    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.container.ipv4_addr()
    }

    /// gracefully terminates the name server collecting all logs
    pub fn terminate(self) -> Result<String> {
        let pidfile = "/run/unbound.pid";
        let kill = format!(
            "test -f {pidfile} || sleep 1
kill -TERM $(cat {pidfile})"
        );
        self.container.status_ok(&["sh", "-c", &kill])?;
        let output = self.child.wait()?;

        if !output.status.success() {
            return Err("could not terminate the `unbound` process".into());
        }

        assert!(
            output.stderr.is_empty(),
            "stderr should be returned if not empty"
        );
        Ok(output.stdout)
    }
}

fn unbound_conf(use_dnssec: bool) -> String {
    minijinja::render!(include_str!("templates/unbound.conf.jinja"), use_dnssec => use_dnssec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminate_works() -> Result<()> {
        let resolver = RecursiveResolver::start(&[], &[])?;
        let logs = resolver.terminate()?;

        eprintln!("{logs}");
        assert!(logs.contains("start of service"));

        Ok(())
    }
}
