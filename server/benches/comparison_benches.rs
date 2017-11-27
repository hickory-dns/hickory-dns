#![feature(test)]

extern crate futures;
extern crate test;
extern crate tokio_core;

extern crate trust_dns;
extern crate trust_dns_server;

use std::fs::DirBuilder;
use std::env;
use std::io::{stdout, BufRead, BufReader, Read, Write};
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use test::Bencher;
use tokio_core::reactor::Core;

use trust_dns::client::*;
use trust_dns::op::*;
use trust_dns::rr::*;
use trust_dns::udp::*;
use trust_dns::tcp::*;

fn find_test_port() -> u16 {
    let server = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
    let server_addr = server.local_addr().unwrap();
    server_addr.port()
}

struct NamedProcess {
    named: Child,
    thread_notice: Arc<AtomicBool>,
}

impl Drop for NamedProcess {
    fn drop(&mut self) {
        self.named.kill().expect("could not kill process");
        self.named.wait().expect("waiting failed");

        self.thread_notice.store(true, Ordering::Relaxed);
    }
}

fn wrap_process<R>(named: Child, io: R, started_str: &str) -> NamedProcess
where
    R: Read + Send + 'static,
{
    let mut named_out = BufReader::new(io);

    // we should get the correct output before 1000 lines...
    let mut output = String::new();
    let mut found = false;
    for _ in 0..1000 {
        output.clear();
        named_out
            .read_line(&mut output)
            .expect("could not read stdout");

        print!("SRV: {}", output);

        if output.contains(started_str) {
            found = true;
            break;
        }
    }

    stdout().flush().unwrap();
    assert!(found, "server did not startup...");

    let thread_notice = Arc::new(AtomicBool::new(false));
    let thread_notice_clone = thread_notice.clone();

    thread::Builder::new()
        .name("named stdout".into())
        .spawn(move || {
            let thread_notice = thread_notice_clone;
            while !thread_notice.load(std::sync::atomic::Ordering::Relaxed) {
                output.clear();
                named_out
                    .read_line(&mut output)
                    .expect("could not read stdout");
                // stdout().write(b"SRV: ").unwrap();
                // stdout().write(output.as_bytes()).unwrap();
            }
        })
        .expect("no thread available");

    println!("DNS server startup complete");

    // return handle to child process
    NamedProcess {
        named: named,
        thread_notice: thread_notice,
    }
}

/// Returns a NamedProcess (cleans the process up on drop), and a socket addr for connecting
///  to the server.
fn trust_dns_process() -> (NamedProcess, u16) {
    // find a random port to listen on
    let test_port = find_test_port();

    let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or(".".to_owned());

    let mut named = Command::new(&format!("{}/../target/debug/named", server_path))
        .stdout(Stdio::piped())
        //.arg("-q") TODO: need to rethink this one...
        .arg(&format!(
            "--config={}/tests/named_test_configs/example.toml",
            server_path
        ))
        .arg(&format!(
            "--zonedir={}/tests/named_test_configs",
            server_path
        ))
        .arg(&format!("--port={}", test_port))
        .spawn()
        .expect("failed to start named");
    //

    let stdout = mem::replace(&mut named.stdout, None).unwrap();
    let process = wrap_process(named, stdout, "awaiting connections...");

    println!("TRust-DNS startup complete");

    // return handle to child process
    (process, test_port)
}

/// Runs the bench tesk using the specified client
fn bench(b: &mut Bencher, io_loop: &mut Core, client: &mut BasicClientHandle) {
    let name = domain::Name::from_labels(vec!["www", "example", "com"]);

    // validate the request
    let response = io_loop.run(client.query(name.clone(), DNSClass::IN, RecordType::A));
    assert!(
        !response.is_err(),
        "request failed: {}",
        response.unwrap_err()
    );

    let response = response.unwrap();
    assert_eq!(response.response_code(), ResponseCode::NoError);

    let record = &response.answers()[0];
    if let &RData::A(ref address) = record.rdata() {
        assert_eq!(address, &Ipv4Addr::new(127, 0, 0, 1));
    } else {
        assert!(false);
    }

    b.iter(|| {
        let response = io_loop.run(client.query(name.clone(), DNSClass::IN, RecordType::A));
        response.unwrap()
    });
}


#[bench]
fn trust_dns_udp_bench(b: &mut Bencher) {
    let (named, server_port) = trust_dns_process();

    let mut io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("127.0.0.1", server_port)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let handle = io_loop.handle();
    let (stream, sender) = UdpClientStream::new(addr, &handle);
    let mut client = ClientFuture::new(stream, sender, &handle, None);

    bench(b, &mut io_loop, &mut client);

    // cleaning up the named process
    drop(named);
}

#[bench]
fn trust_dns_tcp_bench(b: &mut Bencher) {
    let (named, server_port) = trust_dns_process();

    let mut io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("127.0.0.1", server_port)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let handle = io_loop.handle();
    let (stream, sender) = TcpClientStream::new(addr, &handle);
    let mut client = ClientFuture::new(stream, sender, &handle, None);

    bench(b, &mut io_loop, &mut client);

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

    let bind_path = env::var("TDNS_BIND_PATH").unwrap_or("bind".to_owned());
    let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or(".".to_owned());

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
                      .arg("-c").arg(&format!("../../server/benches/bind_conf/example.conf"))
                      //.arg("-d").arg("0")
                      .arg("-D").arg("TRust-DNS cmp bench")
                      .arg("-g")
                      .arg("-p").arg(&format!("{}", test_port))
                      .spawn()
                      .expect("failed to start named");

    //
    let stderr = mem::replace(&mut named.stderr, None).unwrap();
    let process = wrap_process(named, stderr, "running\n");
    (process, test_port)
}

#[bench]
#[ignore]
fn bind_udp_bench(b: &mut Bencher) {
    let (named, server_port) = bind_process();

    let mut io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("127.0.0.1", server_port)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let handle = io_loop.handle();
    let (stream, sender) = UdpClientStream::new(addr, &handle);
    let mut client = ClientFuture::new(stream, sender, &handle, None);

    bench(b, &mut io_loop, &mut client);

    // cleaning up the named process
    drop(named);
}

#[bench]
#[ignore]
fn bind_tcp_bench(b: &mut Bencher) {
    let (named, server_port) = bind_process();

    let mut io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("127.0.0.1", server_port)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let handle = io_loop.handle();
    let (stream, sender) = TcpClientStream::new(addr, &handle);
    let mut client = ClientFuture::new(stream, sender, &handle, None);

    bench(b, &mut io_loop, &mut client);

    // cleaning up the named process
    drop(named);
}
