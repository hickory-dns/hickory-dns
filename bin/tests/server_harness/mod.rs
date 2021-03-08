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
use regex::Regex;
use tokio::runtime::Runtime;

use trust_dns_client::client::*;
use trust_dns_client::proto::error::ProtoError;
use trust_dns_client::proto::xfer::DnsResponse;
use trust_dns_client::rr::dnssec::*;
use trust_dns_client::rr::rdata::{DNSSECRData, DNSSECRecordType};
use trust_dns_client::rr::*;

use self::mut_message_client::MutMessageHandle;

fn collect_and_print<R: BufRead>(read: &mut R, output: &mut String) {
    output.clear();
    read.read_line(output).expect("could not read stdio");

    if !output.is_empty() {
        // uncomment for debugging
        // println!("SRV: {}", output.trim_end());
    }
}

/// Spins up a Server and handles shutting it down after running the test
#[allow(dead_code)]
pub fn named_test_harness<F, R>(toml: &str, test: F)
where
    F: FnOnce(Option<u16>, Option<u16>, Option<u16>, Option<u16>) -> R + UnwindSafe,
{
    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    println!("using server src path: {}", server_path);

    let mut named = Command::new(&format!("{}/target/debug/named", server_path))
        .stdout(Stdio::piped())
        .env(
            "RUST_LOG",
            "trust_dns_client=debug,trust_dns_https=debug,trust_dns_proto=debug,trust_dns_resolver=debug,trust_dns_server=debug",
        ).arg("-d")
        .arg(&format!(
            "--config={}/tests/test-data/named_test_configs/{}",
            server_path, toml
        )).arg(&format!(
            "--zonedir={}/tests/test-data/named_test_configs",
            server_path
        )).arg(&format!("--port={}", 0))
        .arg(&format!("--tls-port={}", 0))
        .arg(&format!("--https-port={}", 0))
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

    // These will be collected from the server startup
    let mut test_udp_port = Option::<u16>::None;
    let mut test_tcp_port = Option::<u16>::None;
    let mut test_tls_port = Option::<u16>::None;
    let mut test_https_port = Option::<u16>::None;

    // we should get the correct output before 1000 lines...
    let mut output = String::new();
    let mut found = false;
    let wait_for_start_until = Instant::now() + Duration::from_secs(60);

    // Search strings for the ports used during testing
    let udp_regex = Regex::new(r"listening for UDP on (?:V4\()?0\.0\.0\.0:(\d+)\)?").unwrap();
    let tcp_regex = Regex::new(r"listening for TCP on (?:V4\()?0\.0\.0\.0:(\d+)\)?").unwrap();
    let tls_regex = Regex::new(r"listening for TLS on (?:V4\()?0\.0\.0\.0:(\d+)\)?").unwrap();
    let https_regex = Regex::new(r"listening for HTTPS on (?:V4\()?0\.0\.0\.0:(\d+)\)?").unwrap();

    while Instant::now() < wait_for_start_until {
        {
            if let Some(ret_code) = named
                .lock()
                .unwrap()
                .try_wait()
                .expect("failed to check status of named")
            {
                panic!("named has already exited with code: {}", ret_code);
            }
        }

        collect_and_print(&mut named_out, &mut output);

        if let Some(udp) = udp_regex.captures(&output) {
            test_udp_port = Some(
                u16::from_str_radix(udp.get(1).expect("udp missing port").as_str(), 10)
                    .expect("could not parse udp port"),
            );
        } else if let Some(tcp) = tcp_regex.captures(&output) {
            test_tcp_port = Some(
                u16::from_str_radix(tcp.get(1).expect("tcp missing port").as_str(), 10)
                    .expect("could not parse tcp port"),
            );
        } else if let Some(tls) = tls_regex.captures(&output) {
            test_tls_port = Some(
                u16::from_str_radix(tls.get(1).expect("tls missing port").as_str(), 10)
                    .expect("could not parse tls port"),
            );
        } else if let Some(https) = https_regex.captures(&output) {
            test_https_port = Some(
                u16::from_str_radix(https.get(1).expect("https missing port").as_str(), 10)
                    .expect("could not parse https port"),
            );
        } else if output.contains("awaiting connections...") {
            found = true;
            break;
        }
    }

    stdout().flush().unwrap();
    assert!(found);
    println!(
        "Test server started. ports: udp {:?}, tcp {:?}, tls {:?}, https {:?}",
        test_udp_port, test_tcp_port, test_tls_port, test_https_port
    );

    // spawn a thread to capture stdout
    let succeeded_clone = succeeded.clone();
    thread::Builder::new()
        .name("named stdout".into())
        .spawn(move || {
            let succeeded = succeeded_clone;
            while !succeeded.load(atomic::Ordering::Relaxed) {
                collect_and_print(&mut named_out, &mut output);

                if let Some(_ret_code) = named
                    .lock()
                    .unwrap()
                    .try_wait()
                    .expect("failed to check status of named")
                {
                    // uncomment for debugging:
                    // println!("named exited with code: {}", _ret_code);
                }
            }
        })
        .expect("no thread available");

    println!("running test...");

    let result =
        catch_unwind(move || test(test_udp_port, test_tcp_port, test_tls_port, test_https_port));

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
    let response = io_loop.block_on(client.query(name, DNSClass::IN, record_type));
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
pub fn query_all_dnssec<R>(
    io_loop: &mut Runtime,
    client: AsyncClient<R>,
    algorithm: Algorithm,
    with_rfc6975: bool,
) where
    R: Future<Output = Result<DnsResponse, ProtoError>> + Send + Unpin,
{
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
pub fn query_all_dnssec_with_rfc6975<R>(
    io_loop: &mut Runtime,
    client: AsyncClient<R>,
    algorithm: Algorithm,
) where
    R: Future<Output = Result<DnsResponse, ProtoError>> + Send + Unpin,
{
    query_all_dnssec(io_loop, client, algorithm, true)
}

#[allow(dead_code)]
pub fn query_all_dnssec_wo_rfc6975<R>(
    io_loop: &mut Runtime,
    client: AsyncClient<R>,
    algorithm: Algorithm,
) where
    R: Future<Output = Result<DnsResponse, ProtoError>> + Send + Unpin,
{
    query_all_dnssec(io_loop, client, algorithm, false)
}
