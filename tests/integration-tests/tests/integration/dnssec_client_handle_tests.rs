#![cfg(feature = "__dnssec")]

use std::future::Future;
use std::str::FromStr;
use std::sync::{Arc, Mutex as StdMutex};

use futures::executor::block_on;

use hickory_client::client::{Client, ClientHandle, MemoizeClientHandle};
use hickory_proto::dnssec::{DnssecDnsHandle, TrustAnchor};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::Name;
use hickory_proto::rr::{DNSClass, RecordType};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::tcp::TcpClientStream;
use hickory_proto::udp::UdpClientStream;
use hickory_server::authority::{Authority, Catalog};

use hickory_integration::example_authority::create_secure_example;
use hickory_integration::{GOOGLE_V4, TestClientStream};
use test_support::subscribe;

#[tokio::test]
async fn test_secure_query_example_nonet() {
    subscribe();
    with_nonet(test_secure_query_example).await;
}

#[tokio::test]
#[ignore = "flaky test against internet server"]
async fn test_secure_query_example_udp() {
    subscribe();
    with_udp(test_secure_query_example).await;
}

#[tokio::test]
async fn test_secure_query_example_tcp() {
    subscribe();
    with_tcp(test_secure_query_example).await;
}

async fn test_secure_query_example<H>(mut client: DnssecDnsHandle<H>)
where
    H: ClientHandle + Sync + 'static,
{
    let name = Name::from_str("www.example.com.").unwrap();
    let response = client
        .query(name.clone(), DNSClass::IN, RecordType::A)
        .await
        .expect("query failed");

    println!("response records: {response:?}");
    assert!(
        response
            .extensions()
            .as_ref()
            .expect("edns not here")
            .flags()
            .dnssec_ok
    );

    assert!(!response.answers().is_empty());
}

#[tokio::test]
async fn test_nsec_query_example_nonet() {
    subscribe();
    with_nonet(test_nsec_query_example).await;
}

#[tokio::test]
#[ignore = "flaky test against internet server"]
async fn test_nsec_query_example_udp() {
    subscribe();
    with_udp(test_nsec_query_example).await;
}

#[tokio::test]
#[ignore = "flaky test against internet server"]
async fn test_nsec_query_example_tcp() {
    subscribe();
    with_tcp(test_nsec_query_example).await;
}

async fn test_nsec_query_example<H>(mut client: DnssecDnsHandle<H>)
where
    H: ClientHandle + Sync + 'static,
{
    let name = Name::from_str("none.example.com.").unwrap();

    let response = client
        .query(name, DNSClass::IN, RecordType::A)
        .await
        .expect("query failed");
    assert_eq!(response.response_code(), ResponseCode::NXDomain);
}

// TODO: NSEC response code wrong in Hickory DNS? Issue #53
// #[test]
// fn test_nsec_query_type_nonet() {
//   with_nonet(test_nsec_query_type);
// }

#[tokio::test]
#[ignore = "flaky test against internet server"]
async fn test_nsec_query_type_udp() {
    subscribe();
    with_udp(test_nsec_query_type).await;
}

#[tokio::test]
#[ignore = "flaky test against internet server"]
async fn test_nsec_query_type_tcp() {
    subscribe();
    with_tcp(test_nsec_query_type).await;
}

async fn test_nsec_query_type<H>(mut client: DnssecDnsHandle<H>)
where
    H: ClientHandle + Sync + 'static,
{
    let name = Name::from_str("www.example.com.").unwrap();

    let response = client
        .query(name, DNSClass::IN, RecordType::NS)
        .await
        .expect("query failed");

    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answers().is_empty());
}

// // TODO: this test is flaky
// #[test]
// #[ignore]
// fn test_dnssec_rollernet_td_udp() {
//     with_udp(dnssec_rollernet_td_test);
// }

// // TODO: this test is flaky
// #[test]
// #[ignore]
// fn test_dnssec_rollernet_td_tcp() {
//     with_udp(dnssec_rollernet_td_test);
// }

// // TODO: this test is flaky
// #[test]
// #[ignore]
// fn test_dnssec_rollernet_td_tcp_mixed_case() {
//     with_tcp(dnssec_rollernet_td_mixed_case_test);
// }

// fn dnssec_rollernet_td_test<H>(mut client: DnssecDnsHandle<H>, io_loop: Runtime)
// where
//     H: ClientHandle + 'static,
// {
//     let name = Name::parse("rollernet.us.", None).unwrap();

//     let response = io_loop
//         .block_on(client.query(
//             name.clone(),
//             DNSClass::IN,
//             RecordType::DS),
//         ))
//         .expect("query failed");

//     assert_eq!(response.response_code(), ResponseCode::NoError);
//     // rollernet doesn't have any DS records...
//     //  would have failed validation
//     assert!(response.answers().is_empty());
// }

// fn dnssec_rollernet_td_mixed_case_test<H>(mut client: DnssecDnsHandle<H>, io_loop: Runtime)
// where
//     H: ClientHandle + 'static,
// {
//     let name = Name::parse("RollErnet.Us.", None).unwrap();

//     let response = io_loop
//         .block_on(client.query(
//             name.clone(),
//             DNSClass::IN,
//             RecordType::DS),
//         ))
//         .expect("query failed");

//     assert_eq!(response.response_code(), ResponseCode::NoError);
//     // rollernet doesn't have any DS records...
//     //  would have failed validation
//     assert!(response.answers().is_empty());
// }

async fn with_nonet<F, Fut>(test: F)
where
    F: Fn(DnssecDnsHandle<MemoizeClientHandle<Client>>) -> Fut,
    Fut: Future<Output = ()>,
{
    let succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let succeeded_clone = succeeded.clone();
    let join = std::thread::Builder::new()
        .name("thread_killer".to_string())
        .spawn(move || {
            let succeeded = succeeded_clone;
            for _ in 0..15 {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if succeeded.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
            }

            println!("Thread Killer has been awoken, killing process");
            std::process::exit(-1);
        })
        .unwrap();

    let authority = create_secure_example();

    let trust_anchor = {
        let signers = block_on(authority.secure_keys());
        let public_key = signers
            .first()
            .expect("expected a key in the authority")
            .key()
            .to_public_key()
            .expect("could not convert keypair to public_key");

        let mut trust_anchor = TrustAnchor::new();
        trust_anchor.insert_trust_anchor(&public_key);

        Arc::new(trust_anchor)
    };

    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), vec![Arc::new(authority)]);

    let (stream, sender) = TestClientStream::new(Arc::new(StdMutex::new(catalog)));
    let client = Client::new(stream, sender, None);

    let (client, bg) = client.await.expect("failed to create new client");

    tokio::spawn(bg);
    let client = MemoizeClientHandle::new(client);
    let secure_client = DnssecDnsHandle::with_trust_anchor(client, trust_anchor);

    test(secure_client);
    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    join.join().unwrap();
}

async fn with_udp<F, Fut>(test: F)
where
    F: Fn(DnssecDnsHandle<MemoizeClientHandle<Client>>) -> Fut,
    Fut: Future<Output = ()>,
{
    let succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let succeeded_clone = succeeded.clone();
    let join = std::thread::Builder::new()
        .name("thread_killer".to_string())
        .spawn(move || {
            let succeeded = succeeded_clone;
            for _ in 0..15 {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if succeeded.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
            }

            println!("Thread Killer has been awoken, killing process");
            std::process::exit(-1);
        })
        .unwrap();

    let stream = UdpClientStream::builder(GOOGLE_V4, TokioRuntimeProvider::new()).build();
    let client = Client::connect(stream);
    let (client, bg) = client.await.expect("client failed to connect");
    tokio::spawn(bg);

    let client = MemoizeClientHandle::new(client);
    let secure_client = DnssecDnsHandle::new(client);

    test(secure_client);
    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    join.join().unwrap();
}

// TODO: just make this a Tokio test?
async fn with_tcp<F, Fut>(test: F)
where
    F: Fn(DnssecDnsHandle<MemoizeClientHandle<Client>>) -> Fut,
    Fut: Future<Output = ()>,
{
    let succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let succeeded_clone = succeeded.clone();
    let join = std::thread::Builder::new()
        .name("thread_killer".to_string())
        .spawn(move || {
            let succeeded = succeeded_clone;
            for _ in 0..15 {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if succeeded.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
            }

            println!("Thread Killer has been awoken, killing process");
            std::process::exit(-1);
        })
        .unwrap();

    let (stream, sender) = TcpClientStream::new(GOOGLE_V4, None, None, TokioRuntimeProvider::new());
    let client = Client::new(Box::new(stream), sender, None);
    let (client, bg) = client.await.expect("client failed to connect");
    tokio::spawn(bg);

    let client = MemoizeClientHandle::new(client);
    let secure_client = DnssecDnsHandle::new(client);

    test(secure_client);
    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    join.join().unwrap();
}
