pub mod mut_message_client;

use std::env;
use std::io::{stdout, BufRead, BufReader, Write};
use std::mem;
use std::net::*;
use std::panic::{catch_unwind, UnwindSafe};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::*;
use std::thread;
use std::time::*;

use futures::Future;
use tokio::runtime::current_thread::Runtime;

use trust_dns_client::client::*;
use trust_dns_client::proto::error::ProtoError;
use trust_dns_client::proto::xfer::DnsResponse;
use trust_dns_client::rr::dnssec::*;
use trust_dns_client::rr::rdata::{DNSSECRData, DNSSECRecordType};
use trust_dns_client::rr::*;

use self::mut_message_client::MutMessageHandle;

/// Spins up a Server and handles shutting it down after running the test
#[allow(dead_code)]
pub fn named_test_harness<F, R>(toml: &str, test: F)
where
    F: FnOnce(u16, u16, u16) -> R + UnwindSafe,
{
    // find a random port to listen on
    let (test_port, test_tls_port, test_https_port) = {
        let server = UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        let server_addr = server.local_addr().unwrap();
        let test_port = server_addr.port();

        let server = UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        let server_addr = server.local_addr().unwrap();
        let test_tls_port = server_addr.port();

        let server = UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        let server_addr = server.local_addr().unwrap();
        let test_https_port = server_addr.port();

        assert!(test_port != test_tls_port);
        assert!(test_port != test_https_port);
        assert!(test_tls_port != test_https_port);
        (test_port, test_tls_port, test_https_port)
    };

    let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or_else(|_| ".".to_owned());
    println!("using server src path: {}", server_path);

    let mut named = Command::new(&format!("{}/../target/debug/named", server_path))
        .stdout(Stdio::piped())
        .env(
            "RUST_LOG",
            "trust_dns_client=debug,trust_dns_https=debug,trust_dns_proto=debug,trust_dns_resolver=debug,trust_dns_server=debug",
        ).arg("-d")
        .arg(&format!(
            "--config={}/../tests/test-data/named_test_configs/{}",
            server_path, toml
        )).arg(&format!(
            "--zonedir={}/../tests/test-data/named_test_configs",
            server_path
        )).arg(&format!("--port={}", test_port))
        .arg(&format!("--tls-port={}", test_tls_port))
        .arg(&format!("--https-port={}", test_https_port))
        .spawn()
        .expect("failed to start named");

    println!("server starting");

    let mut named_out = BufReader::new(mem::replace(&mut named.stdout, None).expect("no stdout"));

    // forced thread killer
    let named = Arc::new(Mutex::new(named));
    let named_killer = Arc::clone(&named);
    let succeeded = Arc::new(atomic::AtomicBool::new(false));
    let succeeded_clone = succeeded.clone();
    let killer_join = thread::Builder::new()
        .name("thread_killer".to_string())
        .spawn(move || {
            let succeeded = succeeded_clone;

            let kill_named = || {
                info!("killing named");

                let mut named = named_killer.lock().unwrap();
                if let Err(e) = named.kill() {
                    warn!("warning: failed to kill named: {:?}", e);
                }
            };

            for _ in 0..30 {
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
    let wait_for_start_until = Instant::now() + Duration::from_secs(60);

    while Instant::now() < wait_for_start_until {
        {
            assert!(
                named
                    .lock()
                    .unwrap()
                    .try_wait()
                    .expect("failed to check status of named")
                    .is_none(),
                "named has already exited"
            );
        }

        output.clear();
        named_out
            .read_line(&mut output)
            .expect("could not read stdout");
        if !output.is_empty() {
            // uncomment for debugging
            // println!("SRV: {}", output.trim_end());
        }
        if output.contains("awaiting connections...") {
            found = true;
            break;
        }
    }

    stdout().flush().unwrap();
    assert!(found);
    println!("server started");

    // spawn a thread to capture stdout
    let succeeded_clone = succeeded.clone();
    thread::Builder::new()
        .name("named stdout".into())
        .spawn(move || {
            let succeeded = succeeded_clone;
            while !succeeded.load(atomic::Ordering::Relaxed) {
                output.clear();
                named_out
                    .read_line(&mut output)
                    .expect("could not read stdout");
                if !output.is_empty() {
                    // uncomment for debugging
                    // println!("SRV: {}", output.trim_end());
                }
            }
        })
        .expect("no thread available");

    println!("running test...");

    let result = catch_unwind(move || test(test_port, test_tls_port, test_https_port));

    println!("test completed");
    succeeded.store(true, atomic::Ordering::Relaxed);
    killer_join.join().expect("join failed");

    assert!(result.is_ok(), "test failed");
}

pub fn query_message<C: ClientHandle>(
    io_loop: &mut Runtime,
    client: &mut C,
    name: Name,
    record_type: RecordType,
) -> DnsResponse {
    println!("sending request: {} for: {}", name, record_type);
    let response = io_loop.block_on(client.query(name.clone(), DNSClass::IN, record_type));
    //println!("got response: {}");
    response.expect("request failed")
}

// This only validates that a query to the server works, it shouldn't be used for more than this.
//  i.e. more complex checks live with the clients and authorities to validate deeper functionality
#[allow(dead_code)]
pub fn query_a<C: ClientHandle>(io_loop: &mut Runtime, client: &mut C) {
    let name = Name::from_str("www.example.com").unwrap();
    let response = query_message(io_loop, client, name, RecordType::A);
    let record = &response.answers()[0];

    if let RData::A(ref address) = *record.rdata() {
        assert_eq!(address, &Ipv4Addr::new(127, 0, 0, 1))
    } else {
        panic!("wrong RDATA")
    }
}

// This only validates that a query to the server works, it shouldn't be used for more than this.
//  i.e. more complex checks live with the clients and authorities to validate deeper functionality
#[allow(dead_code)]
pub fn query_all_dnssec<R: Future<Output = Result<DnsResponse, ProtoError>> + Send + Unpin>(
    io_loop: &mut Runtime,
    client: BasicClientHandle<R>,
    algorithm: Algorithm,
    with_rfc6975: bool,
) {
    let name = Name::from_str("example.com.").unwrap();
    let mut client = MutMessageHandle::new(client);
    client.dnssec_ok = true;
    if with_rfc6975 {
        client.support_algorithms = Some(SupportedAlgorithms::from_vec(&[algorithm]));
    }

    let response = query_message(
        io_loop,
        &mut client,
        name.clone(),
        RecordType::DNSSEC(DNSSECRecordType::DNSKEY),
    );

    let dnskey = response
        .answers()
        .iter()
        .filter(|r| r.rr_type() == RecordType::DNSSEC(DNSSECRecordType::DNSKEY))
        .map(|r| {
            if let RData::DNSSEC(DNSSECRData::DNSKEY(ref dnskey)) = *r.rdata() {
                dnskey.clone()
            } else {
                panic!("wrong RDATA")
            }
        })
        .find(|d| d.algorithm() == algorithm);
    assert!(dnskey.is_some(), "DNSKEY not found");

    let response = query_message(
        io_loop,
        &mut client,
        name,
        RecordType::DNSSEC(DNSSECRecordType::DNSKEY),
    );

    let rrsig = response
        .answers()
        .iter()
        .filter(|r| r.rr_type() == RecordType::DNSSEC(DNSSECRecordType::RRSIG))
        .map(|r| {
            if let RData::DNSSEC(DNSSECRData::SIG(ref rrsig)) = *r.rdata() {
                rrsig.clone()
            } else {
                panic!("wrong RDATA")
            }
        })
        .filter(|rrsig| rrsig.algorithm() == algorithm)
        .find(|rrsig| rrsig.type_covered() == RecordType::DNSSEC(DNSSECRecordType::DNSKEY));
    assert!(rrsig.is_some(), "Associated RRSIG not found");
}

#[allow(dead_code)]
pub fn query_all_dnssec_with_rfc6975<
    R: Future<Output = Result<DnsResponse, ProtoError>> + Send + Unpin,
>(
    io_loop: &mut Runtime,
    client: BasicClientHandle<R>,
    algorithm: Algorithm,
) {
    query_all_dnssec(io_loop, client, algorithm, true)
}

#[allow(dead_code)]
pub fn query_all_dnssec_wo_rfc6975<
    R: Future<Output = Result<DnsResponse, ProtoError>> + Send + Unpin,
>(
    io_loop: &mut Runtime,
    client: BasicClientHandle<R>,
    algorithm: Algorithm,
) {
    query_all_dnssec(io_loop, client, algorithm, false)
}
