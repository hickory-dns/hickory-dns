extern crate trust_dns;
extern crate tokio_core;

use std::io::{BufRead, BufReader, stdout, Write};
use std::mem;
use std::net::*;
use std::process::{Command, Stdio};
use std::thread::{Builder};
use std::panic::{catch_unwind, UnwindSafe};

use tokio_core::reactor::Core;

use trust_dns::client::*;
use trust_dns::rr::*;
use trust_dns::tcp::*;

fn named_test_harness<F, R>(toml: &str, test: F) where F: FnOnce(u16) -> R + UnwindSafe {
  // find a random port to listen on
  let test_port = {
    let server = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
    let server_addr = server.local_addr().unwrap();
    server_addr.port()
  };

  let mut named = Command::new("target/debug/named")
                          .stdout(Stdio::piped())
                          .arg(&format!("--config=tests/named_test_configs/{}", toml))
                          .arg("--zonedir=tests/named_test_configs")
                          .arg(&format!("--port={}", test_port))
                          .spawn()
                          .expect("failed to start named");

  let mut named_out = BufReader::new(mem::replace(&mut named.stdout, None).expect("no stdout"));

  // forced thread killer
  let succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
  let succeeded_clone = succeeded.clone();
  let killer_join = std::thread::Builder::new().name("thread_killer".to_string()).spawn(move || {
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
        return
      }
    }

    kill_named();
    panic!("timeout");
  }).expect("could not start thread killer");

  // we should get the correct output before 1000 lines...
  let mut output = String::new();
  let mut found = false;
  for _ in 0..1000 {
    output.clear();
    named_out.read_line(&mut output).expect("could not read stdout");
    stdout().write(output.as_bytes()).unwrap();
    if output == "awaiting connections...\n" { found = true; break }
  }

  stdout().flush().unwrap();
  assert!(found);

  // spawn a thread to capture stdout
  let succeeded_clone = succeeded.clone();
  Builder::new().name("named stdout".into()).spawn(move ||{
    let succeeded = succeeded_clone;
    while !succeeded.load(std::sync::atomic::Ordering::Relaxed) {
      output.clear();
      named_out.read_line(&mut output).expect("could not read stdout");
      stdout().write(output.as_bytes()).unwrap();
    }
  }).expect("no thread available");

  println!("running test...");

  let result = catch_unwind(move || test(test_port));

  println!("test completed");
  succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
  killer_join.join().expect("join failed");

  assert!(result.is_ok(), "test failed");
}


// This only validates that a query to the server works, it shouldn't be used for more than this.
//  i.e. more complex checks live with the clients and authorities to validate deeper funcionality
fn test_query(io_loop: &mut Core, client: BasicClientHandle) -> bool {
  let name = domain::Name::with_labels(vec!["www".to_string(), "example".to_string(), "com".to_string()]);

  let response = io_loop.run(client.query(name.clone(), DNSClass::IN, RecordType::A));
  if response.is_err() { return false }
  let response = response.unwrap();

  let record = &response.get_answers()[0];

  if let &RData::A(ref address) = record.get_rdata() {
    address == &Ipv4Addr::new(127,0,0,1)
  } else {
    false
  }
}

#[test]
fn test_example_toml_startup() {
  named_test_harness("example.toml", |port| {
    let mut io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("127.0.0.1", port).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
    let client = ClientFuture::new(stream, sender, io_loop.handle(), None);

    assert!(test_query(&mut io_loop, client));
    assert!(true);
  })
}

#[test]
fn test_ipv4_only_toml_startup() {
  named_test_harness("ipv4_only.toml", |port| {
    let mut io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("127.0.0.1", port).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
    let client = ClientFuture::new(stream, sender, io_loop.handle(), None);

    // ipv4 should succeed
    assert!(test_query(&mut io_loop, client));

    let addr: SocketAddr = ("::1", port).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
    let client = ClientFuture::new(stream, sender, io_loop.handle(), None);

    // ipv6 should fail
    assert!(!test_query(&mut io_loop, client));

    assert!(true);
  })
}

// TODO: this is commented out b/c at least on macOS, ipv4 will route properly to ipv6 only
//  listeners over the [::ffff:127.0.0.1] interface
//
// #[test]
// fn test_ipv6_only_toml_startup() {
//   named_test_harness("ipv6_only.toml", |port| {
//     let mut io_loop = Core::new().unwrap();
//     let addr: SocketAddr = ("127.0.0.1", port).to_socket_addrs().unwrap().next().unwrap();
//     let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
//     let client = ClientFuture::new(stream, sender, io_loop.handle(), None);
//
//     // ipv4 should fail
//     assert!(!test_query(&mut io_loop, client));
//
//     let addr: SocketAddr = ("::1", port).to_socket_addrs().unwrap().next().unwrap();
//     let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
//     let client = ClientFuture::new(stream, sender, io_loop.handle(), None);
//
//     // ipv6 should succeed
//     assert!(test_query(&mut io_loop, client));
//
//     assert!(true);
//   })
// }

#[ignore]
#[test]
fn test_ipv4_and_ipv6_toml_startup() {
  named_test_harness("ipv4_and_ipv6.toml", |port| {
    let mut io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("127.0.0.1", port).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
    let client = ClientFuture::new(stream, sender, io_loop.handle(), None);

    // ipv4 should succeed
    assert!(test_query(&mut io_loop, client));

    let addr: SocketAddr = ("::1", port).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
    let client = ClientFuture::new(stream, sender, io_loop.handle(), None);

    // ipv6 should succeed
    assert!(test_query(&mut io_loop, client));

    assert!(true);
  })
}
