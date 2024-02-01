use core::fmt;
use std::process::Output;
use std::sync::atomic;
use std::{
    fs,
    path::Path,
    process::{Command, ExitStatus, Stdio},
    sync::atomic::AtomicUsize,
};

use tempfile::NamedTempFile;

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = core::result::Result<T, Error>;

pub struct Container {
    id: String,
    name: String,
}

impl Container {
    /// Starts the container in a "parked" state
    pub fn run(image: Image) -> Result<Self> {
        static COUNT: AtomicUsize = AtomicUsize::new(0);

        let image_tag = format!("dnssec-tests-{image}");

        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let dockerfile_path = manifest_dir
            .join("docker")
            .join(format!("{image}.Dockerfile"));
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

        // run container based on image
        // `docker run --rm -it $IMAGE sleep infinity`

        let mut command = Command::new("docker");
        let container_name = format!("{image}-{}", COUNT.fetch_add(1, atomic::Ordering::Relaxed));
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

        Ok(Self {
            id,
            name: container_name,
        })
    }

    pub fn cp(&self, path_in_container: &str, file_contents: &str) -> Result<()> {
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

        Ok(())
    }

    pub fn exec(&self, cmd: &[&str]) -> Result<Output> {
        let mut command = Command::new("docker");
        command.args(&["exec", "-t", &self.id]).args(cmd);

        let output = command.output()?;

        Ok(output)
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
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn run_works() -> Result<()> {
        let container = Container::run(Image::Client)?;

        let output = container.exec(&["true"])?;
        assert!(output.status.success());

        Ok(())
    }

    #[test]
    fn ip_addr_works() -> Result<()> {
        let container = Container::run(Image::Client)?;

        let ip_addr = container.ip_addr()?;
        assert!(ip_addr.parse::<Ipv4Addr>().is_ok());

        Ok(())
    }

    #[test]
    fn cp_works() -> Result<()> {
        let container = Container::run(Image::Client)?;

        let path = "/tmp/somefile";
        let contents = "hello";
        container.cp(path, contents)?;

        let output = container.exec(&["cat", path])?;
        dbg!(&output);

        assert!(output.status.success());

        assert_eq!(contents, core::str::from_utf8(&output.stdout)?);

        Ok(())
    }

    #[ignore = "TODO"]
    #[test]
    fn tld_setup() -> Result<()> {
        let container = Container::run(Image::Nsd)?;

        container.cp("/etc/nsd/zones/main.zone", "TODO")?;

        container.exec(&["nsd", "-d"])?;

        Ok(())
    }
}
