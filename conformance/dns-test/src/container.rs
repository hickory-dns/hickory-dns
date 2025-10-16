mod network;

use core::{fmt, str};
use std::{
    env,
    ffi::OsStr,
    fs,
    net::Ipv4Addr,
    process::{self, ChildStderr, ChildStdout, Command, ExitStatus, Stdio},
    sync::{Arc, Once, atomic, atomic::AtomicUsize},
    thread::sleep,
    time::{Duration, Instant},
};

use tempfile::{NamedTempFile, TempDir};

pub use crate::container::network::Network;
use crate::{Error, HickoryCryptoProvider, Implementation, Repository, implementation::Role};

#[derive(Clone)]
pub struct Container {
    inner: Arc<Inner>,
}

const PACKAGE_NAME: &str = env!("CARGO_PKG_NAME");

#[derive(Clone)]
pub enum Image {
    Bind,
    Client,
    Hickory {
        repo: Repository<'static>,
        crypto_provider: HickoryCryptoProvider,
    },
    Pdns,
    Unbound,
    EdeDotCom,
    TestServer {
        handler: String,
        repo: Repository<'static>,
        transport: String,
    },
}

impl Image {
    pub fn hickory() -> Self {
        Self::Hickory {
            repo: Repository(crate::repo_root()),
            crypto_provider: HickoryCryptoProvider::AwsLcRs,
        }
    }

    fn dockerfile(&self) -> &'static str {
        match self {
            Self::Bind => include_str!("docker/bind.Dockerfile"),
            Self::Client => include_str!("docker/client.Dockerfile"),
            Self::Hickory { .. } => include_str!("docker/hickory.Dockerfile"),
            Self::Pdns => include_str!("docker/pdns.Dockerfile"),
            Self::Unbound => include_str!("docker/unbound.Dockerfile"),
            Self::EdeDotCom => include_str!("docker/ede-dot-com/Dockerfile"),
            Self::TestServer { .. } => include_str!("docker/test-server.Dockerfile"),
        }
    }

    fn once(&self) -> &'static Once {
        match self {
            Self::Bind => {
                static BIND_ONCE: Once = Once::new();
                &BIND_ONCE
            }

            Self::Client => {
                static CLIENT_ONCE: Once = Once::new();
                &CLIENT_ONCE
            }

            Self::Hickory { .. } => {
                static HICKORY_ONCE: Once = Once::new();
                &HICKORY_ONCE
            }

            Self::Pdns => {
                static PDNS_ONCE: Once = Once::new();
                &PDNS_ONCE
            }

            Self::Unbound => {
                static UNBOUND_ONCE: Once = Once::new();
                &UNBOUND_ONCE
            }

            Self::EdeDotCom => {
                static EDE_ONCE: Once = Once::new();
                &EDE_ONCE
            }

            Self::TestServer { .. } => {
                static TESTSERVER_ONCE: Once = Once::new();
                &TESTSERVER_ONCE
            }
        }
    }
}

impl From<Implementation> for Image {
    fn from(implementation: Implementation) -> Self {
        match implementation {
            Implementation::Bind => Self::Bind,
            Implementation::Unbound => Self::Unbound,
            Implementation::Hickory {
                repo,
                crypto_provider,
            } => Self::Hickory {
                repo,
                crypto_provider,
            },
            Implementation::EdeDotCom => Self::EdeDotCom,
            Implementation::Pdns => Self::Pdns,
            Implementation::TestServer {
                handler,
                repo,
                transport,
            } => Self::TestServer {
                handler,
                repo,
                transport,
            },
        }
    }
}

impl fmt::Display for Image {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client => f.write_str("client"),
            Self::Bind => f.write_str("bind"),
            Self::Hickory {
                crypto_provider, ..
            } => write!(f, "hickory-{crypto_provider}"),
            Self::Pdns => f.write_str("pdns"),
            Self::Unbound => f.write_str("unbound"),
            Self::EdeDotCom => f.write_str("ede-dot-com"),
            Self::TestServer { .. } => f.write_str("test-server"),
        }
    }
}

impl Container {
    /// Starts the container in a "parked" state
    pub fn run(image: &Image, network: &Network) -> Result<Self, Error> {
        let image_tag = format!("{PACKAGE_NAME}-{image}");

        if !skip_docker_build() {
            image.once().call_once(|| {
                let dockerfile = image.dockerfile();
                let docker_build_dir =
                    TempDir::new().expect("failed to create temporary directory");
                let docker_build_dir = docker_build_dir.path();
                fs::write(docker_build_dir.join("Dockerfile"), dockerfile)
                    .expect("failed to write Dockerfile");

                let mut command = Command::new("docker");
                command
                    .args(["build", "--load", "-t"])
                    .arg(&image_tag)
                    .arg(docker_build_dir);
                // Use BuildKit instead of the legacy builder. We need to choose this in order to
                // pass the `--load` flag above. Depending on which BuildKit build driver is in use,
                // the `--load` flag may be necessary, in order to load the resulting image as a
                // local Docker image.
                command.env("DOCKER_BUILDKIT", "1");

                if let Image::Hickory {
                    crypto_provider, ..
                } = image
                {
                    command.arg(format!("--build-arg=CRYPTO_PROVIDER={crypto_provider}"));
                };

                if docker_build_gha_cache() {
                    let scope = match image {
                        Image::Bind => "bind",
                        Image::Client => "client",
                        Image::Hickory {
                            crypto_provider: HickoryCryptoProvider::AwsLcRs,
                            ..
                        } => "hickory-aws-lc-rs",
                        Image::Hickory {
                            crypto_provider: HickoryCryptoProvider::Ring,
                            ..
                        } => "hickory-ring",
                        Image::Pdns => "pdns",
                        Image::Unbound => "unbound",
                        Image::EdeDotCom => "ede-dot-com",
                        Image::TestServer { .. } => "test-server",
                    };

                    command.arg(format!("--cache-from=type=gha,scope=${scope}"));
                    if let Image::Hickory { .. } = image {
                        command.arg(format!(
                            "--cache-to=type=gha,scope=${scope},mode=max,ignore-error=true"
                        ));
                    } else {
                        command.arg(format!(
                            "--cache-to=type=gha,scope=${scope},ignore-error=true"
                        ));
                    }
                }

                if let Image::Hickory { repo, .. } = image {
                    let mut cp_r = Command::new("git");
                    cp_r.args([
                        "clone",
                        "--depth",
                        "1",
                        repo.as_str(),
                        &docker_build_dir.join("src").display().to_string(),
                    ]);

                    exec_or_panic(&mut cp_r, false);
                }

                if let Image::EdeDotCom = image {
                    fs::write(
                        docker_build_dir.join("configure_child.sh"),
                        include_str!("docker/ede-dot-com/configure_child.sh"),
                    )
                    .expect("could not copy configure_child.sh");
                    fs::write(
                        docker_build_dir.join("configure_parent.sh"),
                        include_str!("docker/ede-dot-com/configure_parent.sh"),
                    )
                    .expect("could not copy configure_parent.sh");
                }

                if let Image::TestServer { repo, .. } = image {
                    let mut cp_r = Command::new("git");
                    cp_r.args([
                        "clone",
                        "--depth",
                        "1",
                        repo.as_str(),
                        &docker_build_dir.join("src").display().to_string(),
                    ]);

                    exec_or_panic(&mut cp_r, false);
                }

                fs::write(docker_build_dir.join(".dockerignore"), "src/.git")
                    .expect("could not create .dockerignore file");

                exec_or_panic(&mut command, verbose_docker_build());
            });
        }

        let mut command = Command::new("docker");
        let pid = process::id();
        let count = container_count();
        let name = format!("{PACKAGE_NAME}-{image}-{pid}-{count}");
        command
            .args([
                "run",
                "--rm",
                "--detach",
                "--cap-add=NET_RAW",
                "--cap-add=NET_ADMIN",
                "--network",
                network.name(),
                "--name",
                &name,
            ])
            .arg(image_tag)
            .args(["sleep", "infinity"]);

        let output: Output = checked_output(&mut command)?.try_into()?;
        let id = output.stdout;

        let ipv4_addr = get_ipv4_addr(&id)?;

        let inner = Inner {
            id,
            name,
            ipv4_addr,
            network: network.clone(),
        };
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    pub fn cp(&self, path_in_container: &str, file_contents: &str) -> Result<(), Error> {
        const CHMOD_RW_EVERYONE: &str = "666";

        let mut temp_file = NamedTempFile::new()?;
        fs::write(&mut temp_file, file_contents)?;

        let src_path = temp_file.path().display().to_string();
        let dest_path = format!("{}:{path_in_container}", self.inner.id);

        let mut command = Command::new("docker");
        command.args(["cp", &src_path, &dest_path]);
        checked_output(&mut command)?;

        self.status_ok(&["chmod", CHMOD_RW_EVERYONE, path_in_container])?;

        Ok(())
    }

    /// Similar to `std::process::Command::output` but runs `command_and_args` in the container
    pub fn output(&self, command_and_args: &[&str]) -> Result<Output, Error> {
        let mut command = Command::new("docker");
        command
            .args(["exec", &self.inner.id])
            .args(command_and_args);

        command.output()?.try_into()
    }

    /// Similar to `Self::output` but checks `command_and_args` ran successfully and only
    /// returns the stdout
    pub fn stdout(&self, command_and_args: &[&str]) -> Result<String, Error> {
        let Output {
            status,
            stderr,
            stdout,
        } = self.output(command_and_args)?;

        if status.success() {
            Ok(stdout)
        } else {
            Err(format!(
                "[{}] `{command_and_args:?}` failed\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
                self.inner.name
            )
            .into())
        }
    }

    /// Similar to `std::process::Command::status` but runs `command_and_args` in the container
    pub fn status(&self, command_and_args: &[&str]) -> Result<ExitStatus, Error> {
        let mut command = Command::new("docker");
        command
            .args(["exec", &self.inner.id])
            .args(command_and_args)
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        Ok(command.status()?)
    }

    /// Like `Self::status` but checks that `command_and_args` executed successfully
    pub fn status_ok(&self, command_and_args: &[&str]) -> Result<(), Error> {
        let status = self.status(command_and_args)?;

        if status.success() {
            Ok(())
        } else {
            Err(format!("[{}] `{command_and_args:?}` failed", self.inner.name).into())
        }
    }

    pub fn spawn(&self, cmd: &[impl AsRef<OsStr>]) -> Result<Child, Error> {
        let mut command = Command::new("docker");
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        command.args(["exec", &self.inner.id]).args(cmd);

        let inner = command.spawn()?;

        Ok(Child {
            inner: Some(inner),
            _container: self.inner.clone(),
        })
    }

    /// Wait up to 10 seconds for a nameserver/resolver to start to avoid test failures
    pub fn wait(&self, implementation: &Implementation, role: Role) -> Result<(), Error> {
        let start = Instant::now();
        let timeout = Duration::from_secs(10);
        loop {
            if start.elapsed() >= timeout {
                return Err("unable to start name server: timeout expired".into());
            }

            let Ok(logs) = self.stdout(&[
                "cat",
                &implementation.stdout_logfile(role),
                &implementation.stderr_logfile(role),
            ]) else {
                continue;
            };

            let match_str = match implementation {
                Implementation::EdeDotCom if role == Role::Resolver => {
                    panic!("EdeDotCom unsupported as resolver")
                }
                Implementation::Bind | Implementation::EdeDotCom => "running",
                Implementation::Hickory { .. } => "server starting up, awaiting connections...",
                Implementation::Pdns if role == Role::Resolver => "Enabled multiplexer",
                Implementation::Pdns => panic!("Pdns unsupported as name server"),
                Implementation::TestServer { .. } if role == Role::Resolver => {
                    panic!("TestServer unsupported as resolver")
                }
                Implementation::TestServer { .. } => "TEST SERVER STARTED",
                Implementation::Unbound if role == Role::Resolver => "start of service",
                Implementation::Unbound => "nsd started",
            };

            if logs.contains(match_str) {
                break;
            }
            sleep(Duration::from_millis(500));
        }

        Ok(())
    }
    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.inner.ipv4_addr
    }

    pub fn id(&self) -> &str {
        &self.inner.id
    }

    pub(crate) fn network(&self) -> &Network {
        &self.inner.network
    }

    pub fn name(&self) -> &str {
        &self.inner.name
    }
}

fn verbose_docker_build() -> bool {
    env::var("DNS_TEST_VERBOSE_DOCKER_BUILD").as_deref().is_ok()
}

fn skip_docker_build() -> bool {
    env::var("DNS_TEST_SKIP_DOCKER_BUILD").is_ok()
}

fn docker_build_gha_cache() -> bool {
    env::var("DNS_TEST_DOCKER_CACHE_GHA").is_ok()
}

fn exec_or_panic(command: &mut Command, verbose: bool) {
    if verbose {
        let status = command.status().unwrap();
        assert!(status.success());
    } else {
        let output = command.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "--- STDOUT ---\n{stdout}\n--- STDERR ---\n{stderr}"
        );
    }
}

fn container_count() -> usize {
    static COUNT: AtomicUsize = AtomicUsize::new(0);

    COUNT.fetch_add(1, atomic::Ordering::Relaxed)
}

struct Inner {
    name: String,
    id: String,
    // TODO probably also want the IPv6 address
    ipv4_addr: Ipv4Addr,
    network: Network,
}

/// NOTE unlike `std::process::Child`, the drop implementation of this type will `kill` the
/// child process
// this wrapper over `std::process::Child` stores a reference to the container the child process
// runs inside of, to prevent the scenario of the container being destroyed _before_
// the child is killed
pub struct Child {
    inner: Option<process::Child>,
    _container: Arc<Inner>,
}

impl Child {
    /// Returns a handle to the child's stdout
    ///
    /// This method will succeed at most once
    pub fn stdout(&mut self) -> Result<ChildStdout, Error> {
        Ok(self
            .inner
            .as_mut()
            .and_then(|child| child.stdout.take())
            .ok_or("could not retrieve child's stdout")?)
    }

    /// Returns a handle to the child's stderr
    ///
    /// This method will succeed at most once
    pub fn stderr(&mut self) -> Result<ChildStderr, Error> {
        Ok(self
            .inner
            .as_mut()
            .and_then(|child| child.stderr.take())
            .ok_or("could not retrieve child's stderr")?)
    }

    /// Returns the child's exit status, if the child process has exited. try_wait will not block
    /// on a running process.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, Error> {
        match self.inner.as_mut() {
            Some(child) => Ok(child.try_wait()?),
            _ => Err("can't borrow child as mut for try_wait".into()),
        }
    }

    pub fn wait(mut self) -> Result<Output, Error> {
        let output = self.inner.take().expect("unreachable").wait_with_output()?;
        output.try_into()
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if let Some(mut inner) = self.inner.take() {
            let _ = inner.kill();
        }
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

    fn try_from(output: process::Output) -> Result<Self, Error> {
        let mut stderr = String::from_utf8(output.stderr)?;
        while stderr.ends_with(['\n', '\r']) {
            stderr.pop();
        }

        let mut stdout = String::from_utf8(output.stdout)?;
        while stdout.ends_with(['\n', '\r']) {
            stdout.pop();
        }

        Ok(Self {
            status: output.status,
            stderr,
            stdout,
        })
    }
}

fn checked_output(command: &mut Command) -> Result<process::Output, Error> {
    let output = command.output()?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(format!("`{command:?}` failed").into())
    }
}

fn get_ipv4_addr(container_id: &str) -> Result<Ipv4Addr, Error> {
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

// this ensures the container gets deleted and does not linger after the test runner process ends
impl Drop for Inner {
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
    fn run_works() -> Result<(), Error> {
        let network = Network::new()?;
        let container = Container::run(&Image::Client, &network)?;

        let output = container.output(&["true"])?;
        assert!(output.status.success());

        Ok(())
    }

    #[test]
    fn ipv4_addr_works() -> Result<(), Error> {
        let network = Network::new()?;
        let container = Container::run(&Image::Client, &network)?;
        let ipv4_addr = container.ipv4_addr();

        let output = container.output(&["ping", "-c1", &format!("{ipv4_addr}")])?;
        assert!(output.status.success());

        Ok(())
    }

    #[test]
    fn cp_works() -> Result<(), Error> {
        let network = Network::new()?;
        let container = Container::run(&Image::Client, &network)?;

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
