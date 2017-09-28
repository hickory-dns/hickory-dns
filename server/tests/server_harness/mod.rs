use std::env;
use std::io::*;
use std::mem;
use std::net::*;
use std::panic::{catch_unwind, UnwindSafe};
use std::process::{Command, Stdio};
use std::sync::*;
use std::time::*;
use std::thread;

use tokio_core::reactor::Core;

use trust_dns::client::*;
use trust_dns::rr::*;


/// Spins up a Server and handles shutting it down after running the test
#[allow(dead_code)]
pub fn named_test_harness<F, R>(toml: &str, test: F)
where
    F: FnOnce(u16, u16) -> R + UnwindSafe,
{
    // find a random port to listen on
    let (test_port, test_tls_port) = {
        let server = UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        let server_addr = server.local_addr().unwrap();
        let test_port = server_addr.port();

        let server = UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        let server_addr = server.local_addr().unwrap();
        let test_tls_port = server_addr.port();

        assert!(test_port != test_tls_port);
        (test_port, test_tls_port)
    };

    let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or(".".to_owned());
    println!("using server src path: {}", server_path);

    let mut named = Command::new(&format!("{}/../target/debug/named", server_path))
        .stdout(Stdio::piped())
        .arg("-d")
        .arg(&format!(
            "--config={}/tests/named_test_configs/{}",
            server_path,
            toml
        ))
        .arg(&format!(
            "--zonedir={}/tests/named_test_configs",
            server_path
        ))
        .arg(&format!("--port={}", test_port))
        .arg(&format!("--tls-port={}", test_tls_port))
        .spawn()
        .expect("failed to start named");

    let mut named_out = BufReader::new(mem::replace(&mut named.stdout, None).expect("no stdout"));

    // forced thread killer
    let succeeded = Arc::new(atomic::AtomicBool::new(false));
    let succeeded_clone = succeeded.clone();
    let killer_join = thread::Builder::new()
        .name("thread_killer".to_string())
        .spawn(move || {
            let succeeded = succeeded_clone;

            let mut kill_named = || {
                println!("killing named");
                named.kill().expect("could not kill process");
                named.wait().expect("waiting failed");
            };

            for _ in 0..15 {
                thread::sleep(Duration::from_secs(1));
                if succeeded.load(atomic::Ordering::Relaxed) {
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
        named_out.read_line(&mut output).expect(
            "could not read stdout",
        );
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
    thread::Builder::new()
        .name("named stdout".into())
        .spawn(move || {
            let succeeded = succeeded_clone;
            while !succeeded.load(atomic::Ordering::Relaxed) {
                output.clear();
                named_out.read_line(&mut output).expect(
                    "could not read stdout",
                );
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
    succeeded.store(true, atomic::Ordering::Relaxed);
    killer_join.join().expect("join failed");

    assert!(result.is_ok(), "test failed");
}

// This only validates that a query to the server works, it shouldn't be used for more than this.
//  i.e. more complex checks live with the clients and authorities to validate deeper funcionality
#[allow(dead_code)]
pub fn query<C: ClientHandle>(io_loop: &mut Core, client: &mut C) -> bool {
    let name = domain::Name::from_labels(vec!["www", "example", "com"]);

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

// This only validates that a query to the server works, it shouldn't be used for more than this.
//  i.e. more complex checks live with the clients and authorities to validate deeper funcionality
#[allow(dead_code)]
pub fn query_all_dnssec<C: ClientHandle>(io_loop: &mut Core, client: &mut C) -> bool {
    // FIXME: query for all Records and show that they are good.
    let name = domain::Name::from_labels(vec!["www", "example", "com"]);

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