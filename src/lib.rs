use core::fmt;
use std::process::Child;

use container::Container;
use minijinja::{context, Environment};

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = core::result::Result<T, Error>;

const CHMOD_RW_EVERYONE: &str = "666";

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

pub enum Domain<'a> {
    Root,
    Tld { domain: &'a str },
}

impl Domain<'_> {
    fn fqdn(&self) -> &str {
        match self {
            Domain::Root => ".",
            Domain::Tld { domain } => domain,
        }
    }
}

pub struct NsdContainer {
    child: Child,
    container: Container,
}

impl NsdContainer {
    pub fn start(domain: Domain) -> Result<Self> {
        let container = Container::run(Image::Nsd)?;

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

impl Drop for NsdContainer {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

mod container;

pub enum Image {
    Nsd, // for ROOT, TLD, DOMAIN
    Unbound,
    Client,
}

impl fmt::Display for Image {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Image::Nsd => "nsd",
            Image::Unbound => "unbound",
            Image::Client => "client",
        };
        f.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tld_setup() -> Result<()> {
        let tld_ns = NsdContainer::start(Domain::Tld { domain: "com." })?;
        let ip_addr = tld_ns.ip_addr()?;

        let client = Container::run(Image::Client)?;
        let output = client.exec(&["dig", &format!("@{ip_addr}"), "SOA", "com."])?;

        assert!(output.status.success());
        let stdout = core::str::from_utf8(&output.stdout)?;
        println!("{stdout}");
        assert!(stdout.contains("status: NOERROR"));

        Ok(())
    }

    #[test]
    fn root_setup() -> Result<()> {
        let root_ns = NsdContainer::start(Domain::Root)?;
        let ip_addr = root_ns.ip_addr()?;

        let client = Container::run(Image::Client)?;
        let output = client.exec(&["dig", &format!("@{ip_addr}"), "SOA", "."])?;

        assert!(output.status.success());
        let stdout = core::str::from_utf8(&output.stdout)?;
        println!("{stdout}");
        assert!(stdout.contains("status: NOERROR"));

        Ok(())
    }
}
