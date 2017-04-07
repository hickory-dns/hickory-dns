extern crate futures;
extern crate log;
extern crate trust_dns;
extern crate tokio_core;
extern crate openssl;

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, stdout, Write};
use std::mem;
use std::net::*;
use std::process::{Command, Stdio};
use std::thread::Builder;
use std::panic::{catch_unwind, UnwindSafe};

use openssl::x509::X509;

use tokio_core::reactor::Core;

use trust_dns::client::*;
use trust_dns::rr::*;
use trust_dns::tcp::TcpClientStream;
use trust_dns::tls::TlsClientStream;

fn named_test_harness<F, R>(toml: &str, test: F)
    where F: FnOnce(u16, u16) -> R + UnwindSafe
{
    // find a random port to listen on
    let (test_port, test_tls_port) = {
        let server = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        let server_addr = server.local_addr().unwrap();
        let test_port = server_addr.port();

        let server = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        let server_addr = server.local_addr().unwrap();
        let test_tls_port = server_addr.port();

        assert!(test_port != test_tls_port);
        (test_port, test_tls_port)
    };

    let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or(".".to_owned());
    println!("using server src path: {}", server_path);

    let mut named = Command::new(&format!("{}/../target/debug/named", server_path))
                          .stdout(Stdio::piped())
                          //.arg("-d")
                          .arg(&format!("--config={}/tests/named_test_configs/{}", server_path, toml))
                          .arg(&format!("--zonedir={}/tests/named_test_configs", server_path))
                          .arg(&format!("--port={}", test_port))
                          .arg(&format!("--tls-port={}", test_tls_port))
                          .spawn()
                          .expect("failed to start named");

    let mut named_out = BufReader::new(mem::replace(&mut named.stdout, None).expect("no stdout"));

    // forced thread killer
    let succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let succeeded_clone = succeeded.clone();
    let killer_join = std::thread::Builder::new()
        .name("thread_killer".to_string())
        .spawn(move || {
            let succeeded = succeeded_clone;

            let mut kill_named = || {
                println!("killing named");
                named.kill().expect("could not kill process");
                named.wait().expect("waiting failed");
            };

            for _ in 0..15 {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if succeeded.load(std::sync::atomic::Ordering::Relaxed) {
                    kill_named();
                    return;
                }
            }

            kill_named();
            panic!("timeout");
        })
        .expect("could not start thread killer");

    // we should get the correct output before 1000 lines...
    let mut output = String::new();
    let mut found = false;
    for _ in 0..1000 {
        output.clear();
        named_out.read_line(&mut output).expect("could not read stdout");
        if !output.is_empty() {
            stdout().write(b"SRV: ").unwrap();
            stdout().write(output.as_bytes()).unwrap();
        }
        if output.ends_with("awaiting connections...\n") {
            found = true;
            break;
        }
    }

    stdout().flush().unwrap();
    assert!(found);

    // spawn a thread to capture stdout
    let succeeded_clone = succeeded.clone();
    Builder::new()
        .name("named stdout".into())
        .spawn(move || {
            let succeeded = succeeded_clone;
            while !succeeded.load(std::sync::atomic::Ordering::Relaxed) {
                output.clear();
                named_out.read_line(&mut output).expect("could not read stdout");
                if !output.is_empty() {
                    stdout().write(b"SRV: ").unwrap();
                    stdout().write(output.as_bytes()).unwrap();
                }
            }
        })
        .expect("no thread available");

    println!("running test...");

    let result = catch_unwind(move || test(test_port, test_tls_port));

    println!("test completed");
    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    killer_join.join().expect("join failed");

    assert!(result.is_ok(), "test failed");
}


// This only validates that a query to the server works, it shouldn't be used for more than this.
//  i.e. more complex checks live with the clients and authorities to validate deeper funcionality
fn query(io_loop: &mut Core, client: &mut BasicClientHandle) -> bool {
    let name = domain::Name::with_labels(vec!["www".to_string(),
                                              "example".to_string(),
                                              "com".to_string()]);

    println!("sending request");
    let response = io_loop.run(client.query(name.clone(), DNSClass::IN, RecordType::A));
    println!("got response: {}", response.is_ok());
    if response.is_err() {
        return false;
    }
    let response = response.unwrap();


    let record = &response.answers()[0];

    if let &RData::A(ref address) = record.rdata() {
        address == &Ipv4Addr::new(127, 0, 0, 1)
    } else {
        false
    }
}

#[test]
fn test_example_toml_startup() {
    use trust_dns::logger;
    use log::LogLevel;
    logger::TrustDnsLogger::enable_logging(LogLevel::Debug);

    named_test_harness("example.toml", |port, _| {
        let mut io_loop = Core::new().unwrap();
        let addr: SocketAddr = ("127.0.0.1", port).to_socket_addrs().unwrap().next().unwrap();
        let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, io_loop.handle(), None);

        assert!(query(&mut io_loop, &mut client));

        // just tests that multiple queries work
        let addr: SocketAddr = ("127.0.0.1", port).to_socket_addrs().unwrap().next().unwrap();
        let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, io_loop.handle(), None);

        assert!(query(&mut io_loop, &mut client));
    })
}

#[test]
fn test_ipv4_only_toml_startup() {
    named_test_harness("ipv4_only.toml", |port, _| {
        let mut io_loop = Core::new().unwrap();
        let addr: SocketAddr = ("127.0.0.1", port).to_socket_addrs().unwrap().next().unwrap();
        let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, io_loop.handle(), None);

        // ipv4 should succeed
        assert!(query(&mut io_loop, &mut client));

        let addr: SocketAddr = ("::1", port).to_socket_addrs().unwrap().next().unwrap();
        let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, io_loop.handle(), None);

        // ipv6 should fail
        assert!(!query(&mut io_loop, &mut client));
    })
}

// TODO: this is commented out b/c at least on macOS, ipv4 will route properly to ipv6 only
//  listeners over the [::ffff:127.0.0.1] interface
//
// #[ignore]
// #[test]
// fn test_ipv6_only_toml_startup() {
//   named_test_harness("ipv6_only.toml", |port, _| {
//     let mut io_loop = Core::new().unwrap();
//     let addr: SocketAddr = ("127.0.0.1", port).to_socket_addrs().unwrap().next().unwrap();
//     let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
//     let client = ClientFuture::new(stream, sender, io_loop.handle(), None);
//
//     // ipv4 should fail
//     assert!(!query(&mut io_loop, client));
//
//     let addr: SocketAddr = ("::1", port).to_socket_addrs().unwrap().next().unwrap();
//     let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
//     let client = ClientFuture::new(stream, sender, io_loop.handle(), None);
//
//     // ipv6 should succeed
//     assert!(query(&mut io_loop, client));
//
//     assert!(true);
//   })
// }

#[ignore]
#[test]
fn test_ipv4_and_ipv6_toml_startup() {
    named_test_harness("ipv4_and_ipv6.toml", |port, _| {
        let mut io_loop = Core::new().unwrap();
        let addr: SocketAddr = ("127.0.0.1", port).to_socket_addrs().unwrap().next().unwrap();
        let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, io_loop.handle(), None);

        // ipv4 should succeed
        assert!(query(&mut io_loop, &mut client));

        let addr: SocketAddr = ("::1", port).to_socket_addrs().unwrap().next().unwrap();
        let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, io_loop.handle(), None);

        // ipv6 should succeed
        assert!(query(&mut io_loop, &mut client));

        assert!(true);
    })
}

#[test]
fn test_example_tls_toml_startup() {
    named_test_harness("dns_over_tls.toml", move |_, tls_port| {
        let mut cert_der = vec![];
        let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or(".".to_owned());
        println!("using server src path: {}", server_path);

        File::open(&format!("{}/tests/named_test_configs/sec/example.cert", server_path))
            .unwrap()
            .read_to_end(&mut cert_der)
            .unwrap();

        let mut io_loop = Core::new().unwrap();
        let addr: SocketAddr = ("127.0.0.1", tls_port).to_socket_addrs().unwrap().next().unwrap();
        let mut tls_conn_builder = TlsClientStream::builder();
        let cert = to_trust_anchor(&cert_der);
        tls_conn_builder.add_ca(cert);
        let (stream, sender) =
            tls_conn_builder.build(addr, "ns.example.com".to_string(), io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, io_loop.handle(), None);

        // ipv4 should succeed
        assert!(query(&mut io_loop, &mut client));

        let addr: SocketAddr = ("127.0.0.1", tls_port).to_socket_addrs().unwrap().next().unwrap();
        let mut tls_conn_builder = TlsClientStream::builder();
        let cert = to_trust_anchor(&cert_der);
        tls_conn_builder.add_ca(cert);
        let (stream, sender) =
            tls_conn_builder.build(addr, "ns.example.com".to_string(), io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, io_loop.handle(), None);

        // ipv6 should succeed
        assert!(query(&mut io_loop, &mut client));

        assert!(true);
    })
}

fn to_trust_anchor(cert_der: &[u8]) -> X509 {
    X509::from_der(&cert_der).unwrap()
}
