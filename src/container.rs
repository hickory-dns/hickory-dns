use core::str;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{self, Child, ExitStatus};
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicUsize;
use std::sync::{atomic, Once};

use tempfile::NamedTempFile;

use crate::{Error, Result};

pub struct Container {
    name: String,
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
        let count = COUNT.fetch_add(1, atomic::Ordering::Relaxed);
        let name = format!("{binary}-{pid}-{count}");
        command
            .args(["run", "--rm", "--detach", "--name", &name])
            .arg("-it")
            .arg(image_tag)
            .args(["sleep", "infinity"]);

        let output: Output = checked_output(&mut command)?.try_into()?;
        let id = output.stdout;

        let ipv4_addr = get_ipv4_addr(&id)?;

        Ok(Self {
            id,
            name,
            ipv4_addr,
        })
    }

    pub fn cp(&self, path_in_container: &str, file_contents: &str) -> Result<()> {
        const CHMOD_RW_EVERYONE: &str = "666";

        let mut temp_file = NamedTempFile::new()?;
        fs::write(&mut temp_file, file_contents)?;

        let src_path = temp_file.path().display().to_string();
        let dest_path = format!("{}:{path_in_container}", self.id);

        let mut command = Command::new("docker");
        command.args(["cp", &src_path, &dest_path]);
        checked_output(&mut command)?;

        self.status_ok(&["chmod", CHMOD_RW_EVERYONE, path_in_container])?;

        Ok(())
    }

    /// Similar to `std::process::Command::output` but runs `command_and_args` in the container
    pub fn output(&self, command_and_args: &[&str]) -> Result<Output> {
        let mut command = Command::new("docker");
        command
            .args(["exec", "-t", &self.id])
            .args(command_and_args);

        command.output()?.try_into()
    }

    /// Similar to `Self::output` but checks `command_and_args` ran successfully and only
    /// returns the stdout
    pub fn stdout(&self, command_and_args: &[&str]) -> Result<String> {
        let output = self.output(command_and_args)?;

        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(format!("[{}] `{command_and_args:?}` failed", self.name).into())
        }
    }

    /// Similar to `std::process::Command::status` but runs `command_and_args` in the container
    pub fn status(&self, command_and_args: &[&str]) -> Result<ExitStatus> {
        let mut command = Command::new("docker");
        command
            .args(["exec", "-t", &self.id])
            .args(command_and_args);

        Ok(command.status()?)
    }

    /// Like `Self::status` but checks that `command_and_args` executed successfully
    pub fn status_ok(&self, command_and_args: &[&str]) -> Result<()> {
        let status = self.status(command_and_args)?;

        if status.success() {
            Ok(())
        } else {
            Err(format!("[{}] `{command_and_args:?}` failed", self.name).into())
        }
    }

    pub fn spawn(&self, cmd: &[&str]) -> Result<Child> {
        let mut command = Command::new("docker");
        command.args(["exec", "-t", &self.id]).args(cmd);

        Ok(command.spawn()?)
    }

    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.ipv4_addr
    }
}

#[derive(Debug)]
pub struct Output {
    pub status: ExitStatus,
    pub stderr: String,
    pub stdout: String,
}

impl TryFrom<process::Output> for Output {
    type Error = Error;

    fn try_from(output: process::Output) -> Result<Self> {
        let mut stderr = String::from_utf8(output.stderr)?;
        while stderr.ends_with(|c| matches!(c, '\n' | '\r')) {
            stderr.pop();
        }

        let mut stdout = String::from_utf8(output.stdout)?;
        while stdout.ends_with(|c| matches!(c, '\n' | '\r')) {
            stdout.pop();
        }

        Ok(Self {
            status: output.status,
            stderr,
            stdout,
        })
    }
}

fn checked_output(command: &mut Command) -> Result<process::Output> {
    let output = command.output()?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(format!("`{command:?}` failed").into())
    }
}

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
    use super::*;

    #[test]
    fn run_works() -> Result<()> {
        let container = Container::run()?;

        let output = container.output(&["true"])?;
        assert!(output.status.success());

        Ok(())
    }

    #[test]
    fn ipv4_addr_works() -> Result<()> {
        let container = Container::run()?;
        let ipv4_addr = container.ipv4_addr();

        let output = container.output(&["ping", "-c1", &format!("{ipv4_addr}")])?;
        assert!(output.status.success());

        Ok(())
    }

    #[test]
    fn cp_works() -> Result<()> {
        let container = Container::run()?;

        let path = "/tmp/somefile";
        let contents = "hello";
        container.cp(path, contents)?;

        let output = container.output(&["cat", path])?;
        dbg!(&output);

        assert!(output.status.success());
        assert_eq!(contents, output.stdout);

        Ok(())
    }
}
