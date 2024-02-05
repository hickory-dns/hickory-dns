use core::str;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{self, Child, Output};
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicUsize;
use std::sync::{atomic, Once};

use tempfile::NamedTempFile;

use crate::Result;

pub struct Container {
    _name: String,
    id: String,
    // TODO probably also want the IPv6 address
    ipv4_addr: Ipv4Addr,
}

impl Container {
    /// Starts the container in a "parked" state
    pub fn run() -> Result<Self> {
        static ONCE: Once = Once::new();
        static COUNT: AtomicUsize = AtomicUsize::new(0);

        // TODO configurable: hickory; bind
        let binary = "unbound";
        let image_tag = format!("dnssec-tests-{binary}");

        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let dockerfile_path = manifest_dir
            .join("docker")
            .join(format!("{binary}.Dockerfile"));
        let docker_dir_path = manifest_dir.join("docker");
        dbg!(&image_tag);

        let mut command = Command::new("docker");
        command
            .args(["build", "-t"])
            .arg(&image_tag)
            .arg("-f")
            .arg(dockerfile_path)
            .arg(docker_dir_path);

        ONCE.call_once(|| {
            let status = command.status().unwrap();
            assert!(status.success());
        });

        let mut command = Command::new("docker");
        let pid = process::id();
        let container_name = format!(
            "{binary}-{pid}-{}",
            COUNT.fetch_add(1, atomic::Ordering::Relaxed)
        );
        command.args(["run", "--rm", "--detach", "--name", &container_name]);
        let output = command
            .arg("-it")
            .arg(image_tag)
            .args(["sleep", "infinity"])
            .output()?;

        if !output.status.success() {
            return Err(format!("`{command:?}` failed").into());
        }

        let id = str::from_utf8(&output.stdout)?.trim().to_string();
        dbg!(&id);

        let ipv4_addr = get_ipv4_addr(&id)?;

        Ok(Self {
            id,
            _name: container_name,
            ipv4_addr,
        })
    }

    pub fn cp(&self, path_in_container: &str, file_contents: &str, chmod: &str) -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        fs::write(&mut temp_file, file_contents)?;

        let src_path = temp_file.path().display().to_string();
        let dest_path = format!("{}:{path_in_container}", self.id);

        let mut command = Command::new("docker");
        command.args(["cp", &src_path, &dest_path]);

        let status = command.status()?;
        if !status.success() {
            return Err(format!("`{command:?}` failed").into());
        }

        let command = &["chmod", chmod, path_in_container];
        let output = self.exec(command)?;
        if !output.status.success() {
            return Err(format!("`{command:?}` failed").into());
        }

        Ok(())
    }

    pub fn exec(&self, cmd: &[&str]) -> Result<Output> {
        let mut command = Command::new("docker");
        command.args(["exec", "-t", &self.id]).args(cmd);

        let output = command.output()?;

        Ok(output)
    }

    pub fn spawn(&self, cmd: &[&str]) -> Result<Child> {
        let mut command = Command::new("docker");
        command.args(["exec", "-t", &self.id]).args(cmd);

        let child = command.spawn()?;

        Ok(child)
    }

    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.ipv4_addr
    }
}

// TODO cache this to avoid calling `docker inspect` every time
fn get_ipv4_addr(container_id: &str) -> Result<Ipv4Addr> {
    let mut command = Command::new("docker");
    command
        .args([
            "inspect",
            "-f",
            "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        ])
        .arg(container_id);

    let output = command.output()?;
    if !output.status.success() {
        return Err(format!("`{command:?}` failed").into());
    }

    let ipv4_addr = str::from_utf8(&output.stdout)?.trim().to_string();
    dbg!(&ipv4_addr);

    Ok(ipv4_addr.parse()?)
}

// ensure the container gets deleted
impl Drop for Container {
    fn drop(&mut self) {
        // running this to completion would block the current thread for several seconds so just
        // fire and forget
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[cfg(test)]
mod tests {
    use crate::CHMOD_RW_EVERYONE;

    use super::*;

    #[test]
    fn run_works() -> Result<()> {
        let container = Container::run()?;

        let output = container.exec(&["true"])?;
        assert!(output.status.success());

        Ok(())
    }

    #[test]
    fn ipv4_addr_works() -> Result<()> {
        let container = Container::run()?;
        let ipv4_addr = container.ipv4_addr();

        let output = container.exec(&["ping", "-c1", &format!("{ipv4_addr}")])?;
        assert!(output.status.success());

        Ok(())
    }

    #[test]
    fn cp_works() -> Result<()> {
        let container = Container::run()?;

        let path = "/tmp/somefile";
        let contents = "hello";
        container.cp(path, contents, CHMOD_RW_EVERYONE)?;

        let output = container.exec(&["cat", path])?;
        dbg!(&output);

        assert!(output.status.success());

        assert_eq!(contents, core::str::from_utf8(&output.stdout)?);

        Ok(())
    }
}
