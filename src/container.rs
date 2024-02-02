use std::fs;
use std::path::Path;
use std::process::{self, Child, Output};
use std::process::{Command, Stdio};
use std::sync::atomic;
use std::sync::atomic::AtomicUsize;

use tempfile::NamedTempFile;

use crate::Result;

pub struct Container {
    id: String,
    name: String,
}

impl Container {
    /// Starts the container in a "parked" state
    pub fn run() -> Result<Self> {
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
            .args(&["build", "-t"])
            .arg(&image_tag)
            .arg("-f")
            .arg(dockerfile_path)
            .arg(docker_dir_path);
        let status = command.status()?;

        if !status.success() {
            return Err(format!("`{command:?}` failed").into());
        }

        let mut command = Command::new("docker");
        let pid = process::id();
        let container_name = format!(
            "{binary}-{pid}-{}",
            COUNT.fetch_add(1, atomic::Ordering::Relaxed)
        );
        command.args(&["run", "--rm", "--detach", "--name", &container_name]);
        let output = command
            .arg("-it")
            .arg(image_tag)
            .args(["sleep", "infinity"])
            .output()?;

        if !output.status.success() {
            return Err(format!("`{command:?}` failed").into());
        }

        let id = core::str::from_utf8(&output.stdout)?.trim().to_string();
        dbg!(&id);
        let container = Self {
            id,
            name: container_name,
        };
        dbg!(container.ip_addr()?);

        Ok(container)
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
        command.args(&["exec", "-t", &self.id]).args(cmd);

        let output = command.output()?;

        Ok(output)
    }

    pub fn spawn(&self, cmd: &[&str]) -> Result<Child> {
        let mut command = Command::new("docker");
        command.args(&["exec", "-t", &self.id]).args(cmd);

        let child = command.spawn()?;

        Ok(child)
    }

    pub fn ip_addr(&self) -> Result<String> {
        let mut command = Command::new("docker");
        command
            .args(&[
                "inspect",
                "-f",
                "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            ])
            .arg(&self.id);

        let output = command.output()?;
        if !output.status.success() {
            return Err(format!("`{command:?}` failed").into());
        }

        let ip_addr = core::str::from_utf8(&output.stdout)?.trim().to_string();
        dbg!(&ip_addr);

        Ok(ip_addr)
    }
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
    use std::net::Ipv4Addr;

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
    fn ip_addr_works() -> Result<()> {
        let container = Container::run()?;

        let ip_addr = container.ip_addr()?;
        assert!(ip_addr.parse::<Ipv4Addr>().is_ok());

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
