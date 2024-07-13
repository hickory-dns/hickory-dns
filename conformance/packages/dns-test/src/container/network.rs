use std::{
    process::{self, Command, Stdio},
    sync::{
        atomic::{self, AtomicUsize},
        Arc, Mutex,
    },
};

use crate::Result;

/// Represents a network in which to put containers into.
#[derive(Clone)]
pub struct Network(Arc<NetworkInner>);

impl Network {
    /// Returns the name of the network.
    pub fn name(&self) -> &str {
        self.0.name.as_str()
    }

    /// Returns the subnet mask
    pub fn netmask(&self) -> &str {
        &self.0.config.subnet
    }
}

struct NetworkInner {
    name: String,
    config: NetworkConfig,
}

impl Network {
    pub fn new() -> Result<Self> {
        let pid = process::id();
        let network_name = env!("CARGO_PKG_NAME");
        Ok(Self(Arc::new(NetworkInner::new(pid, network_name)?)))
    }
}

/// This ensure the Docker network is deleted after the test runner process ends.
impl Drop for NetworkInner {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["network", "rm", "--force", self.name.as_str()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

impl NetworkInner {
    pub fn new(pid: u32, network_name: &str) -> Result<Self> {
        static CRITICAL_SECTION: Mutex<()> = Mutex::new(());

        let count = network_count();
        let network_name = format!("{network_name}-{pid}-{count}");

        let mut command = Command::new("docker");
        command
            .args(["network", "create"])
            .args(["--internal", "--attachable"])
            .arg(&network_name);

        // create network
        let output = {
            // `docker network create` is racy in some versions of Docker. this `Mutex` ensure that
            // multiple test threads do not run the command in parallel
            let _guard = CRITICAL_SECTION.lock()?;

            command.output()?
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() {
            return Err(format!("--- STDOUT ---\n{stdout}\n--- STDERR ---\n{stderr}").into());
        }

        // inspect & parse network details
        let config = get_network_config(&network_name)?;

        Ok(Self {
            name: network_name,
            config,
        })
    }
}

/// Collects all important configs.
pub struct NetworkConfig {
    /// The CIDR subnet mask, e.g. "172.21.0.0/16"
    subnet: String,
}

/// Return network config
fn get_network_config(network_name: &str) -> Result<NetworkConfig> {
    let mut command = Command::new("docker");
    command
        .args([
            "network",
            "inspect",
            "-f",
            "{{range .IPAM.Config}}{{.Subnet}}{{end}}",
        ])
        .arg(network_name);

    let output = command.output()?;
    if !output.status.success() {
        return Err(format!("{command:?} failed").into());
    }

    let subnet = std::str::from_utf8(&output.stdout)?.trim().to_string();
    Ok(NetworkConfig { subnet })
}

fn network_count() -> usize {
    static COUNT: AtomicUsize = AtomicUsize::new(1);

    COUNT.fetch_add(1, atomic::Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use crate::container::{Container, Image};

    use super::*;

    fn exists_network(network_name: &str) -> bool {
        let mut command = Command::new("docker");
        command.args(["network", "ls", "--format={{ .Name }}"]);

        let output = command.output().expect("Failed to get output");
        let stdout = String::from_utf8_lossy(&output.stdout);

        stdout.trim().lines().any(|line| line == network_name)
    }

    #[test]
    fn create_works() -> Result<()> {
        let network = Network::new();
        assert!(network.is_ok());

        let network = network.expect("Failed to construct network");
        assert!(exists_network(network.name()));
        Ok(())
    }

    #[test]
    fn remove_network_works() -> Result<()> {
        let network = Network::new().expect("Failed to create network");
        let network_name = network.name().to_string();
        let container =
            Container::run(&Image::Client, &network).expect("Failed to start container");

        assert!(exists_network(&network_name));
        drop(network);
        assert!(exists_network(&network_name));

        drop(container);
        assert!(!exists_network(&network_name));

        Ok(())
    }
}
