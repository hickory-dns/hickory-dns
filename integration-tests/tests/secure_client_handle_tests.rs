extern crate tokio_core;
extern crate trust_dns;
extern crate trust_dns_integration;
extern crate trust_dns_server;

use std::net::*;
use std::sync::Arc;

use tokio_core::reactor::Core;

use trust_dns::client::{BasicClientHandle, ClientFuture, ClientHandle, MemoizeClientHandle,
                        SecureClientHandle};
use trust_dns::op::ResponseCode;
use trust_dns::rr::domain;
use trust_dns::rr::{DNSClass, RData, RecordType};
use trust_dns::rr::rdata::DNSSECRecordType;
use trust_dns::rr::dnssec::TrustAnchor;
use trust_dns::tcp::TcpClientStream;
use trust_dns::udp::UdpClientStream;

use trust_dns_server::authority::Catalog;

use trust_dns_integration::TestClientStream;
use trust_dns_integration::authority::create_secure_example;

#[test]
fn test_secure_query_example_nonet() {
    with_nonet(test_secure_query_example);
}

#[test]
#[ignore]
fn test_secure_query_example_udp() {
    with_udp(test_secure_query_example);
}

#[test]
#[ignore]
fn test_secure_query_example_tcp() {
    with_tcp(test_secure_query_example);
}

fn test_secure_query_example<H>(mut client: SecureClientHandle<H>, mut io_loop: Core)
where
    H: ClientHandle + 'static,
{
    let name = domain::Name::from_labels(vec!["www", "example", "com"]);
    let response = io_loop
        .run(client.query(name.clone(), DNSClass::IN, RecordType::A))
        .expect("query failed");

    println!("response records: {:?}", response);
    assert!(response.edns().expect("edns not here").dnssec_ok());

    assert!(!response.answers().is_empty());
    let record = &response.answers()[0];
    assert_eq!(record.name(), &name);
    assert_eq!(record.rr_type(), RecordType::A);
    assert_eq!(record.dns_class(), DNSClass::IN);

    if let &RData::A(ref address) = record.rdata() {
        assert_eq!(address, &Ipv4Addr::new(93, 184, 216, 34))
    } else {
        assert!(false);
    }
}

#[test]
fn test_nsec_query_example_nonet() {
    with_nonet(test_nsec_query_example);
}

#[test]
#[ignore]
fn test_nsec_query_example_udp() {
    with_udp(test_nsec_query_example);
}

#[test]
#[ignore]
fn test_nsec_query_example_tcp() {
    with_tcp(test_nsec_query_example);
}

fn test_nsec_query_example<H>(mut client: SecureClientHandle<H>, mut io_loop: Core)
where
    H: ClientHandle + 'static,
{
    let name = domain::Name::from_labels(vec!["none", "example", "com"]);

    let response = io_loop
        .run(client.query(name.clone(), DNSClass::IN, RecordType::A))
        .expect("query failed");
    assert_eq!(response.response_code(), ResponseCode::NoError);
}

// TODO: NSEC response code wrong in Trust-DNS? Issue #53
// #[test]
// fn test_nsec_query_type_nonet() {
//   with_nonet(test_nsec_query_type);
// }

#[test]
#[ignore]
fn test_nsec_query_type_udp() {
    with_udp(test_nsec_query_type);
}

#[test]
#[ignore]
fn test_nsec_query_type_tcp() {
    with_tcp(test_nsec_query_type);
}

fn test_nsec_query_type<H>(mut client: SecureClientHandle<H>, mut io_loop: Core)
where
    H: ClientHandle + 'static,
{
    let name = domain::Name::from_labels(vec!["www", "example", "com"]);

    let response = io_loop
        .run(client.query(name.clone(), DNSClass::IN, RecordType::NS))
        .expect("query failed");

    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answers().is_empty());
}

// TODO: this test is flaky
#[test]
#[ignore]
fn test_dnssec_rollernet_td_udp() {
    with_udp(dnssec_rollernet_td_test);
}

// TODO: this test is flaky
#[test]
#[ignore]
fn test_dnssec_rollernet_td_tcp() {
    with_udp(dnssec_rollernet_td_test);
}

// TODO: this test is flaky
#[test]
#[ignore]
fn test_dnssec_rollernet_td_tcp_mixed_case() {
    with_tcp(dnssec_rollernet_td_mixed_case_test);
}

fn dnssec_rollernet_td_test<H>(mut client: SecureClientHandle<H>, mut io_loop: Core)
where
    H: ClientHandle + 'static,
{
    let name = domain::Name::parse("rollernet.us.", None).unwrap();

    let response = io_loop
        .run(client.query(
            name.clone(),
            DNSClass::IN,
            RecordType::DNSSEC(DNSSECRecordType::DS),
        ))
        .expect("query failed");

    assert_eq!(response.response_code(), ResponseCode::NoError);
    // rollernet doesn't have any DS records...
    //  would have failed validation
    assert!(response.answers().is_empty());
}

fn dnssec_rollernet_td_mixed_case_test<H>(mut client: SecureClientHandle<H>, mut io_loop: Core)
where
    H: ClientHandle + 'static,
{
    let name = domain::Name::parse("RollErnet.Us.", None).unwrap();

    let response = io_loop
        .run(client.query(
            name.clone(),
            DNSClass::IN,
            RecordType::DNSSEC(DNSSECRecordType::DS),
        ))
        .expect("query failed");

    assert_eq!(response.response_code(), ResponseCode::NoError);
    // rollernet doesn't have any DS records...
    //  would have failed validation
    assert!(response.answers().is_empty());
}

fn with_nonet<F>(test: F)
where
    F: Fn(SecureClientHandle<MemoizeClientHandle<BasicClientHandle>>, Core),
{
    let succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let succeeded_clone = succeeded.clone();
    let join = std::thread::Builder::new()
        .name("thread_killer".to_string())
        .spawn(move || {
            let succeeded = succeeded_clone.clone();
            for _ in 0..15 {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if succeeded.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
            }

            panic!("timeout");
        })
        .unwrap();

    let authority = create_secure_example();

    let trust_anchor = {
        let signers = authority.secure_keys();
        let public_key = signers
            .first()
            .expect("expected a key in the authority")
            .key()
            .to_public_key()
            .expect("could not convert keypair to public_key");


        let mut trust_anchor = TrustAnchor::new();
        trust_anchor.insert_trust_anchor(&public_key);

        trust_anchor
    };

    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), authority);

    let io_loop = Core::new().unwrap();
    let (stream, sender) = TestClientStream::new(Arc::new(catalog));
    let client = ClientFuture::new(stream, Box::new(sender), &io_loop.handle(), None);
    let client = MemoizeClientHandle::new(client);
    let secure_client = SecureClientHandle::with_trust_anchor(client, trust_anchor);

    test(secure_client, io_loop);
    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    join.join().unwrap();
}

fn with_udp<F>(test: F)
where
    F: Fn(SecureClientHandle<MemoizeClientHandle<BasicClientHandle>>, Core),
{
    let succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let succeeded_clone = succeeded.clone();
    let join = std::thread::Builder::new()
        .name("thread_killer".to_string())
        .spawn(move || {
            let succeeded = succeeded_clone.clone();
            for _ in 0..15 {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if succeeded.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
            }

            panic!("timeout");
        })
        .unwrap();

    let io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = UdpClientStream::new(addr, &io_loop.handle());
    let client = ClientFuture::new(stream, sender, &io_loop.handle(), None);
    let client = MemoizeClientHandle::new(client);
    let secure_client = SecureClientHandle::new(client);

    test(secure_client, io_loop);
    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    join.join().unwrap();
}

fn with_tcp<F>(test: F)
where
    F: Fn(SecureClientHandle<MemoizeClientHandle<BasicClientHandle>>, Core),
{
    let succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let succeeded_clone = succeeded.clone();
    let join = std::thread::Builder::new()
        .name("thread_killer".to_string())
        .spawn(move || {
            let succeeded = succeeded_clone.clone();
            for _ in 0..15 {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if succeeded.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
            }

            panic!("timeout");
        })
        .unwrap();

    let io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = TcpClientStream::new(addr, &io_loop.handle());
    let client = ClientFuture::new(stream, sender, &io_loop.handle(), None);
    let client = MemoizeClientHandle::new(client);
    let secure_client = SecureClientHandle::new(client);

    test(secure_client, io_loop);
    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    join.join().unwrap();
}
