#![allow(unreachable_pub)]

use std::{
    collections::HashMap,
    env,
    io::{BufRead, BufReader},
    net::SocketAddr,
    process::{Child, ChildStdout, Command, Stdio},
    str::FromStr,
    time::*,
};

use regex::Regex;
use tokio::runtime::Runtime;
use tracing::{info, warn};

use hickory_net::{NetError, client::ClientHandle, xfer::Protocol};
#[cfg(feature = "__dnssec")]
use hickory_net::{client::Client, runtime::TokioRuntimeProvider, xfer::DnsHandle};
#[cfg(feature = "__dnssec")]
use hickory_proto::{
    dnssec::Algorithm,
    op::{DnsRequest, Edns},
};
use hickory_proto::{
    op::{DnsResponse, ResponseCode},
    rr::{DNSClass, Name, RData, RecordType, rdata::A},
};
#[cfg(feature = "__dnssec")]
use hickory_server::zone_handler::LookupOptions;

#[derive(Debug, Default)]
struct SocketPort {
    v4: u16,
    v6: u16,
}

#[derive(Debug, Default)]
pub struct SocketPorts(HashMap<ServerProtocol, SocketPort>);

impl SocketPorts {
    /// This will overwrite the existing value
    fn put(&mut self, protocol: impl Into<ServerProtocol>, addr: SocketAddr) {
        let entry = self.0.entry(protocol.into()).or_default();

        if addr.is_ipv4() {
            entry.v4 = addr.port();
        } else {
            entry.v6 = addr.port();
        }
    }

    /// Assumes there is only one V4 addr for the IP based on the usage in the Server
    pub fn get_v4(&self, protocol: impl Into<ServerProtocol>) -> Option<u16> {
        self.0
            .get(&protocol.into())
            .iter()
            .find_map(|ports| if ports.v4 == 0 { None } else { Some(ports.v4) })
    }

    /// Assumes there is only one V4 addr for the IP based on the usage in the Server
    pub fn get_v6(&self, protocol: impl Into<ServerProtocol>) -> Option<u16> {
        self.0
            .get(&protocol.into())
            .iter()
            .find_map(|ports| if ports.v6 == 0 { None } else { Some(ports.v6) })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ServerProtocol {
    Dns(Protocol),
    #[cfg(feature = "metrics")]
    PrometheusMetrics,
}

impl From<Protocol> for ServerProtocol {
    fn from(proto: Protocol) -> Self {
        Self::Dns(proto)
    }
}

fn collect_and_print<R: BufRead>(read: &mut R, output: &mut String) {
    output.clear();
    read.read_line(output).expect("could not read stdio");

    if !output.is_empty() {
        // uncomment for debugging
        // println!("SRV: {}", output.trim_end());
    }
}

pub struct TestServer {
    pub ports: SocketPorts,
    child: Child,
    stdout: BufReader<ChildStdout>,
}

impl TestServer {
    /// Spins up a Server and handles shutting it down after running the test
    #[allow(dead_code)]
    pub fn start(toml: &str) -> Self {
        let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
        println!("using server src path: {server_path}");

        let mut command = Command::new(env!("CARGO_BIN_EXE_hickory-dns"));
        command
        .stdout(Stdio::piped())
        .env(
            "RUST_LOG",
            "hickory_dns=debug,hickory_client=debug,hickory_proto=debug,hickory_resolver=debug,hickory_server=debug",
        )
        .arg("-d")
        .arg(format!(
            "--config={server_path}/tests/test-data/test_configs/{toml}"
        ))
        .arg(format!(
            "--zonedir={server_path}/tests/test-data/test_configs"
        ))
        .arg(format!("--port={}", 0));
        #[cfg(feature = "__tls")]
        command.arg(format!("--tls-port={}", 0));
        #[cfg(feature = "__https")]
        command.arg(format!("--https-port={}", 0));
        #[cfg(feature = "__quic")]
        command.arg(format!("--quic-port={}", 0));
        #[cfg(feature = "prometheus-metrics")]
        command.arg(format!("--prometheus-listen-address=127.0.0.1:{}", 0));

        println!("named cli options: {command:#?}");

        let mut named = command.spawn().expect("failed to start named");

        println!("server starting");

        let mut stdout = BufReader::new(named.stdout.take().expect("no stdout"));

        // These will be collected from the server startup output
        let mut ports = SocketPorts::default();

        let mut output = String::new();
        let mut found = false;
        let wait_for_start_until = Instant::now() + Duration::from_secs(60);

        // Search strings for the ports used during testing
        let addr_regex = Regex::new(
            r"listening for (UDP|TCP|TLS|HTTPS|QUIC|Prometheus metrics) on ((?:(?:0\.0\.0\.0)|(?:127\.0\.0\.1)|(?:\[::\])):\d+)",
        )
        .unwrap();

        while Instant::now() < wait_for_start_until {
            if let Some(ret_code) = named.try_wait().expect("failed to check status of named") {
                panic!("named has already exited with code: {ret_code}");
            }

            collect_and_print(&mut stdout, &mut output);

            if let Some(addr) = addr_regex.captures(&output) {
                let proto = addr.get(1).expect("missing protocol").as_str();
                let socket_addr = addr.get(2).expect("missing socket addr").as_str();

                let socket_addr =
                    SocketAddr::from_str(socket_addr).expect("could not parse socket_addr");

                match proto {
                    "UDP" => ports.put(Protocol::Udp, socket_addr),
                    "TCP" => ports.put(Protocol::Tcp, socket_addr),
                    #[cfg(feature = "__tls")]
                    "TLS" => ports.put(Protocol::Tls, socket_addr),
                    #[cfg(feature = "__https")]
                    "HTTPS" => ports.put(Protocol::Https, socket_addr),
                    #[cfg(feature = "__quic")]
                    "QUIC" => ports.put(Protocol::Quic, socket_addr),
                    #[cfg(feature = "metrics")]
                    "Prometheus metrics" => {
                        ports.put(ServerProtocol::PrometheusMetrics, socket_addr)
                    }
                    _ => panic!("unsupported protocol: {proto}"),
                }
            } else if output.contains("awaiting connections...") {
                found = true;
                break;
            }
        }

        assert!(found);
        println!("Test server started. ports: {ports:?}");

        Self {
            ports,
            child: named,
            stdout,
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        match self.child.kill() {
            Ok(()) => info!("killed test server"),
            Err(err) => warn!("could not kill test server: {err}"),
        }

        let mut line = String::new();
        loop {
            match self.stdout.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    print!("SRV: {line}");
                    line.clear();
                }
                Err(err) => {
                    warn!("could not read remaining stdout: {err}");
                    break;
                }
            }
        }
    }
}

pub fn query_message<C: ClientHandle>(
    io_loop: &mut Runtime,
    client: &mut C,
    name: Name,
    record_type: RecordType,
) -> Result<DnsResponse, NetError> {
    println!("sending request: {name} for: {record_type}");
    io_loop.block_on(client.query(name, DNSClass::IN, record_type))
}

// This only validates that a query to the server works, it shouldn't be used for more than this.
//  i.e. more complex checks live with the clients and zone handlers to validate deeper functionality
pub fn query_a<C: ClientHandle>(io_loop: &mut Runtime, client: &mut C) {
    let name = Name::from_str("www.example.com.").unwrap();
    let response = query_message(io_loop, client, name, RecordType::A).unwrap();
    let record = &response.answers()[0];

    if let RData::A(address) = record.data() {
        assert_eq!(address, &A::new(127, 0, 0, 1))
    } else {
        panic!("wrong RDATA")
    }
}

// This only validates that a query to the server works, it shouldn't be used for more than this.
//  i.e. more complex checks live with the clients and zone handlers to validate deeper functionality
pub fn query_a_refused<C: ClientHandle>(io_loop: &mut Runtime, client: &mut C) {
    let name = Name::from_str("www.example.com.").unwrap();
    let response = query_message(io_loop, client, name, RecordType::A).unwrap();

    assert_eq!(response.response_code(), ResponseCode::Refused);
}

// This only validates that a query to the server works, it shouldn't be used for more than this.
//  i.e. more complex checks live with the clients and zone handlers to validate deeper functionality
#[cfg(feature = "__dnssec")]
pub fn query_all_dnssec(
    io_loop: &mut Runtime,
    client: Client<TokioRuntimeProvider>,
    algorithm: Algorithm,
) {
    use hickory_proto::{
        dnssec::{
            PublicKey,
            rdata::{DNSKEY, RRSIG},
        },
        rr::{Record, RecordData},
    };

    let name = Name::from_str("example.com.").unwrap();
    let mut client = MutMessageHandle::new(client);
    client.lookup_options.dnssec_ok = true;

    let response = query_message(io_loop, &mut client, name.clone(), RecordType::DNSKEY).unwrap();

    let dnskey = response
        .answers()
        .iter()
        .map(Record::data)
        .filter_map(DNSKEY::try_borrow)
        .find(|d| d.public_key().algorithm() == algorithm);
    assert!(dnskey.is_some(), "DNSKEY not found");

    let response = query_message(io_loop, &mut client, name, RecordType::DNSKEY).unwrap();

    let rrsig = response
        .answers()
        .iter()
        .map(Record::data)
        .filter_map(RRSIG::try_borrow)
        .filter(|rrsig| rrsig.input().algorithm == algorithm)
        .find(|rrsig| rrsig.input().type_covered == RecordType::DNSKEY);
    assert!(rrsig.is_some(), "Associated RRSIG not found");
}

#[cfg(feature = "__dnssec")]
#[derive(Clone)]
pub struct MutMessageHandle<C: ClientHandle + Unpin> {
    client: C,
    pub lookup_options: LookupOptions,
}

#[cfg(feature = "__dnssec")]
impl<C: ClientHandle + Unpin> MutMessageHandle<C> {
    pub fn new(client: C) -> Self {
        Self {
            client,
            #[cfg(feature = "__dnssec")]
            lookup_options: LookupOptions::default(),
        }
    }
}

#[cfg(feature = "__dnssec")]
impl<C: ClientHandle + Unpin> DnsHandle for MutMessageHandle<C> {
    type Response = <C as DnsHandle>::Response;
    type Runtime = C::Runtime;

    fn is_verifying_dnssec(&self) -> bool {
        true
    }

    fn send(&self, mut request: DnsRequest) -> Self::Response {
        // mutable block
        let edns = request.extensions_mut().get_or_insert_with(Edns::new);
        edns.set_dnssec_ok(true);

        println!("sending message");
        self.client.send(request)
    }
}
