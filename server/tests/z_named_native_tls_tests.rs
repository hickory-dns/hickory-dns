#![cfg(not(windows))]
#![cfg(feature = "tls")]

extern crate chrono;
extern crate futures;
extern crate log;
extern crate native_tls;
extern crate tokio_core;
extern crate trust_dns;
extern crate trust_dns_native_tls;
extern crate trust_dns_proto;
extern crate trust_dns_server;

mod server_harness;

use std::env;
use std::fs::File;
use std::io::*;
use std::net::*;

use native_tls::Certificate;
use tokio_core::reactor::Core;

use trust_dns::client::*;
use trust_dns_native_tls::TlsClientStreamBuilder;

use server_harness::{named_test_harness, query_a};


#[test]
fn test_example_tls_toml_startup() {
    named_test_harness("dns_over_tls.toml", move |_, tls_port| {
        let mut cert_der = vec![];
        let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or(".".to_owned());
        println!("using server src path: {}", server_path);

        File::open(&format!(
            "{}/tests/named_test_configs/sec/example.cert",
            server_path
        )).unwrap()
            .read_to_end(&mut cert_der)
            .unwrap();

        let mut io_loop = Core::new().unwrap();
        let addr: SocketAddr = ("127.0.0.1", tls_port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let mut tls_conn_builder = TlsClientStreamBuilder::new();
        let cert = to_trust_anchor(&cert_der);
        tls_conn_builder.add_ca(cert);
        let (stream, sender) =
            tls_conn_builder.build(addr, "ns.example.com".to_string(), &io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

        // ipv4 should succeed
        query_a(&mut io_loop, &mut client);

        let addr: SocketAddr = ("127.0.0.1", tls_port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let mut tls_conn_builder = TlsClientStreamBuilder::new();
        let cert = to_trust_anchor(&cert_der);
        tls_conn_builder.add_ca(cert);
        let (stream, sender) =
            tls_conn_builder.build(addr, "ns.example.com".to_string(), &io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

        // ipv6 should succeed
        query_a(&mut io_loop, &mut client);

        assert!(true);
    })
}

fn to_trust_anchor(cert_der: &[u8]) -> Certificate {
    Certificate::from_der(&cert_der).unwrap()
}
