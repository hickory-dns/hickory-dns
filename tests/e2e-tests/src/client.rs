use core::time::Duration;
use std::thread;

use dns_test::container::{Container, Image};
use dns_test::{Network, Result};

#[test]
fn tls_handshake_timeout_dns_over_https() -> Result<()> {
    tls_handshake_timeout("https")
}

#[test]
fn tls_handshake_timeout_dns_over_tls() -> Result<()> {
    tls_handshake_timeout("tls")
}

#[test]
fn tls_handshake_timeout_dns_over_quic() -> Result<()> {
    tls_handshake_timeout("quic")
}

#[test]
fn tls_handshake_timeout_dns_over_h3() -> Result<()> {
    tls_handshake_timeout("h3")
}

fn tls_handshake_timeout(protocol: &str) -> Result<()> {
    const PORT: u16 = 8443;

    let network = Network::new().unwrap();

    let server_container = Container::run(&Image::Client, &network)?;
    let _server_process = server_container.spawn(&["nc", "-l", "-p", &PORT.to_string()])?;

    let client_container = Container::run(&Image::hickory(), &network)?;

    let server_addr = server_container.ipv4_addr();
    let mut client_process = client_container.spawn(&[
        "dns",
        "-p",
        protocol,
        "-n",
        &format!("{server_addr}:{PORT}"),
        "--tls-dns-name",
        "dont-care",
        "query",
        "dont.care",
        "A",
    ])?;

    for _ in 0..10 {
        if client_process.try_wait()?.is_some() {
            let output = client_process.wait()?;

            assert!(!output.status.success());
            println!("stdout:\n {}", output.stdout);
            assert!(output.stdout.contains("timed out"));

            return Ok(());
        } else {
            thread::sleep(Duration::from_secs(1))
        }
    }

    panic!("`dns` client is unresponsive")
}
