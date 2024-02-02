use std::process::Child;

use minijinja::{context, Environment};

use crate::{container::Container, Domain, Result, CHMOD_RW_EVERYONE};

pub struct AuthoritativeNameServer {
    child: Child,
    container: Container,
}

impl AuthoritativeNameServer {
    pub fn start(domain: Domain) -> Result<Self> {
        let container = Container::run()?;

        container.exec(&["mkdir", "-p", "/etc/nsd/zones"])?;
        let zone_path = "/etc/nsd/zones/main.zone";

        container.cp(
            "/etc/nsd/nsd.conf",
            &nsd_conf(domain.fqdn()),
            CHMOD_RW_EVERYONE,
        )?;

        let zone_file_contents = match domain {
            Domain::Root => root_zone(),
            Domain::Tld { domain } => tld_zone(domain),
        };

        container.cp(zone_path, &zone_file_contents, CHMOD_RW_EVERYONE)?;

        let child = container.spawn(&["nsd", "-d"])?;

        Ok(Self { child, container })
    }

    pub fn ip_addr(&self) -> Result<String> {
        self.container.ip_addr()
    }
}

impl Drop for AuthoritativeNameServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn tld_zone(domain: &str) -> String {
    assert!(domain.ends_with("."));
    assert!(!domain.starts_with("."));

    let mut env = Environment::new();
    let name = "main.zone";
    env.add_template(name, include_str!("templates/tld.zone.jinja"))
        .unwrap();
    let template = env.get_template(name).unwrap();
    template.render(context! { tld => domain }).unwrap()
}

fn root_zone() -> String {
    let mut env = Environment::new();
    let name = "main.zone";
    env.add_template(name, include_str!("templates/root.zone.jinja"))
        .unwrap();
    let template = env.get_template(name).unwrap();
    template.render(context! {}).unwrap()
}

fn nsd_conf(domain: &str) -> String {
    assert!(domain.ends_with("."));

    let mut env = Environment::new();
    let name = "nsd.conf";
    env.add_template(name, include_str!("templates/nsd.conf.jinja"))
        .unwrap();
    let template = env.get_template(name).unwrap();
    template.render(context! { domain => domain }).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tld_setup() -> Result<()> {
        let tld_ns = AuthoritativeNameServer::start(Domain::Tld { domain: "com." })?;
        let ip_addr = tld_ns.ip_addr()?;

        let client = Container::run()?;
        let output = client.exec(&["dig", &format!("@{ip_addr}"), "SOA", "com."])?;

        assert!(output.status.success());
        let stdout = core::str::from_utf8(&output.stdout)?;
        println!("{stdout}");
        assert!(stdout.contains("status: NOERROR"));

        Ok(())
    }

    #[test]
    fn root_setup() -> Result<()> {
        let root_ns = AuthoritativeNameServer::start(Domain::Root)?;
        let ip_addr = root_ns.ip_addr()?;

        let client = Container::run()?;
        let output = client.exec(&["dig", &format!("@{ip_addr}"), "SOA", "."])?;

        assert!(output.status.success());
        let stdout = core::str::from_utf8(&output.stdout)?;
        println!("{stdout}");
        assert!(stdout.contains("status: NOERROR"));

        Ok(())
    }
}
