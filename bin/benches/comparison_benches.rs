#![cfg(nightly)]
#![feature(test)]

extern crate test;

use std::env;
use std::fs::{DirBuilder, File};
use std::future::Future;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use hickory_proto::runtime::TokioRuntimeProvider;
use test::Bencher;
use tokio::runtime::Runtime;

use hickory_client::client::{Client, ClientHandle};
use hickory_proto::ProtoError;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::tcp::TcpClientStream;
use hickory_proto::udp::UdpClientStream;
use hickory_proto::xfer::{DnsMultiplexer, DnsRequestSender};

fn find_test_port() -> u16 {
    let server = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
    let server_addr = server.local_addr().unwrap();
    server_addr.port()
}

struct NamedProcess {
    named: Child,
}

impl Drop for NamedProcess {
    fn drop(&mut self) {
        self.named.kill().expect("could not kill process");
        self.named.wait().expect("waiting failed");
    }
}

fn wrap_process(named: Child, server_port: u16) -> NamedProcess {
    let mut started = false;
    let provider = TokioRuntimeProvider::new();

    for _ in 0..20 {
        let io_loop = Runtime::new().unwrap();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, server_port));
        let stream = UdpClientStream::builder(addr, provider.clone()).build();
        let client = Client::connect(stream);
        let (mut client, bg) = io_loop.block_on(client).expect("failed to create client");
        io_loop.spawn(bg);

        let name = Name::from_str("www.example.com.").unwrap();
        let response = io_loop.block_on(client.query(name.clone(), DNSClass::IN, RecordType::A));

        if response.is_ok() {
            started = true;
            break;
        } else {
            // wait for the server to start
            thread::sleep(Duration::from_millis(500));
        }
    }

    assert!(started, "server did not startup...");
    // return handle to child process
    NamedProcess { named }
}

/// Returns a NamedProcess (cleans the process up on drop), and a socket addr for connecting
///  to the server.
fn hickory_process() -> (NamedProcess, u16) {
    // find a random port to listen on
    let test_port = find_test_port();

    let ws_root = env::var("WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    let named_path = env!("CARGO_BIN_EXE_hickory-dns");
    let config_path = format!("{}/tests/test-data/test_configs/example.toml", ws_root);
    let zone_dir = format!("{}/tests/test-data/test_configs", ws_root);

    File::open(&named_path).expect(&named_path);
    File::open(&config_path).expect(&config_path);
    File::open(&zone_dir).expect(&zone_dir);

    let named = Command::new(&named_path)
        .stdout(Stdio::null())
        .arg("-q") // TODO: need to rethink this one...
        .arg(&format!("--config={}", config_path))
        .arg(&format!("--zonedir={}", zone_dir))
        .arg(&format!("--port={}", test_port))
        .spawn()
        .expect("failed to start hickory-dns");
    //

    let process = wrap_process(named, test_port);

    // return handle to child process
    (process, test_port)
}

/// Runs the bench tesk using the specified client
fn bench<F, S>(b: &mut Bencher, stream: F)
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender,
{
    let io_loop = Runtime::new().unwrap();
    let client = Client::connect(stream);
    let (mut client, bg) = io_loop.block_on(client).expect("failed to create client");
    io_loop.spawn(bg);

    let name = Name::from_str("www.example.com.").unwrap();

    // validate the request
    let query = client.query(name.clone(), DNSClass::IN, RecordType::A);
    let response = io_loop.block_on(query).expect("Request failed");

    assert_eq!(response.response_code(), ResponseCode::NoError);

    let record = &response.answers()[0];
    if let RData::A(address) = record.data() {
        assert_eq!(address, &A(Ipv4Addr::LOCALHOST));
    } else {
        unreachable!();
    }

    b.iter(|| {
        let response = io_loop.block_on(client.query(name.clone(), DNSClass::IN, RecordType::A));
        response.unwrap();
    });
}

#[bench]
fn hickory_udp_bench(b: &mut Bencher) {
    let (named, server_port) = hickory_process();

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, server_port));
    let stream = UdpClientStream::builder(addr, TokioRuntimeProvider::new()).build();
    bench(b, stream);

    // cleaning up the named process
    drop(named);
}

#[bench]
#[ignore]
fn hickory_udp_bench_prof(b: &mut Bencher) {
    let server_port = 6363;

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, server_port));
    let stream = UdpClientStream::builder(addr, TokioRuntimeProvider::new()).build();
    bench(b, stream);
}

#[bench]
fn hickory_tcp_bench(b: &mut Bencher) {
    let (named, server_port) = hickory_process();

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, server_port));
    let (stream, sender) = TcpClientStream::new(addr, None, None, TokioRuntimeProvider::new());
    let mp = DnsMultiplexer::new(stream, sender, None);
    bench(b, mp);

    // cleaning up the named process
    drop(named);
}

// downloaded from https://www.isc.org/downloads/file/bind-9-11-0-p1/
// cd bind-9-11-0-p1
// .configure
// make
// export TDNS_BIND_PATH=${PWD}/bin/named/named
fn bind_process() -> (NamedProcess, u16) {
    let test_port = find_test_port();

    let bind_path = env::var("TDNS_BIND_PATH").unwrap_or_else(|_| "".to_owned());
    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());

    let bind_path = format!("{}/sbin/named", bind_path);

    // create the work directory
    let working_dir = format!("{}/../target/bind_pwd", server_path);
    if !Path::new(&working_dir).exists() {
        DirBuilder::new()
            .create(&working_dir)
            .expect("failed to create dir");
    }

    let mut named = Command::new(bind_path)
        .current_dir(&working_dir)
        .stderr(Stdio::piped())
        .arg("-c")
        .arg("../../server/benches/bind_conf/example.conf")
        //.arg("-d").arg("0")
        .arg("-D")
        .arg("Hickory DNS cmp bench")
        .arg("-g")
        .arg("-p")
        .arg(&format!("{}", test_port))
        .spawn()
        .expect("failed to start named");

    mem::replace(&mut named.stderr, None).unwrap();
    let process = wrap_process(named, test_port);
    (process, test_port)
}

#[bench]
#[ignore]
fn bind_udp_bench(b: &mut Bencher) {
    let (named, server_port) = bind_process();

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, server_port));
    let stream = UdpClientStream::builder(addr, TokioRuntimeProvider::new()).build();
    bench(b, stream);

    // cleaning up the named process
    drop(named);
}

#[bench]
#[ignore]
fn bind_tcp_bench(b: &mut Bencher) {
    let (named, server_port) = bind_process();

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, server_port));
    let (stream, sender) = TcpClientStream::new(addr, None, None, TokioRuntimeProvider::new());
    let mp = DnsMultiplexer::new(stream, sender, None);
    bench(b, mp);

    // cleaning up the named process
    drop(named);
}
