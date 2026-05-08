//! This tests the recursive resolver's behavior in the presence of a [ghost domain attack][ndss].
//!
//! In this setting, a referral is modified or removed in a parent zone. The prior owner of the
//! child zone should lose control over the domain name once the TTL of the referral records
//! expires. However, in resolvers vulnerable to the ghost domain attack, the resolver may keep
//! using the same NS RRset past this time. If the attacker keeps requesting the zone's NS RRset,
//! the resolver may request the child zone's apex NS RRset from the old name server without
//! checking the parent zone's referral, and improperly extend the cache lifetime of the NS RRset.
//! With repeated requests, the attacker may be able to extend the cached NS RRset's lifetime
//! indefinitely.
//!
//! [ndss]:
//!     https://www.ndss-symposium.org/ndss2012/ndss-2012-programme/ghost-domain-names-revoked-yet-still-resolvable/

use std::{
    cell::Cell,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use tracing::info;

use hickory_net::{
    runtime::{RuntimeProvider, Time, TokioHandle},
    xfer::Protocol,
};
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, NS, TXT},
    },
};
use test_support::{
    MockNetworkHandler, MockProvider, MockRecord, MockResponseSection, MockTcpStream,
    MockUdpSocket, subscribe,
};

use crate::recursor::{DnssecPolicy, Recursor, RecursorOptions};

#[tokio::test]
#[ignore]
async fn test_ghost_domain() {
    subscribe();

    let root_ns_ip = Ipv4Addr::new(10, 1, 0, 1);
    let old_ns_ip = Ipv4Addr::new(10, 2, 0, 1);
    let new_ns_ip = Ipv4Addr::new(10, 3, 0, 1);

    let zone_name = Name::parse("testing.", None).unwrap();
    let query_name = Name::parse("www.testing.", None).unwrap();
    let old_ns_name = Name::parse("old-ns.", None).unwrap();
    let new_ns_name = Name::parse("new-ns.", None).unwrap();
    let root_ns_name = Name::parse("root-ns.", None).unwrap();
    let rname = Name::parse("admin.example.", None).unwrap();

    let switch_referral = Arc::new(AtomicBool::new(false));

    let ttl = 1000;
    let handler = MockNetworkHandler::new(vec![
        // Original referral (this gets overridden partway through the test)
        MockRecord::ns(root_ns_ip.into(), &zone_name, &old_ns_name).with_ttl(ttl),
        MockRecord::a(root_ns_ip.into(), &old_ns_name, old_ns_ip.into())
            .with_query_name(&zone_name)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional)
            .with_ttl(ttl),
        // Addresses of name servers
        MockRecord::a(root_ns_ip.into(), &old_ns_name, old_ns_ip.into()).with_ttl(ttl),
        MockRecord::a(root_ns_ip.into(), &new_ns_name, new_ns_ip.into()).with_ttl(ttl),
        // Apex NS RRset query, according to old name server
        MockRecord::ns(old_ns_ip.into(), &zone_name, &old_ns_name)
            .with_section(MockResponseSection::Answer)
            .with_ttl(ttl),
        // Apex NS RRset query, according to new name server
        MockRecord::ns(new_ns_ip.into(), &zone_name, &new_ns_name)
            .with_section(MockResponseSection::Answer)
            .with_ttl(ttl),
        // Record in victim zone according to old name server
        MockRecord::txt(old_ns_ip.into(), &query_name, vec!["old".to_string()]).with_ttl(ttl),
        // Record in victim zone according to new name server
        MockRecord::txt(new_ns_ip.into(), &query_name, vec!["new".to_string()]).with_ttl(ttl),
        // Provide an SOA record in response to QNAME minimzation queries. (Without this, the mock
        // handler would return a SERVFAIL response, due to the lack of a canned response for the
        // query).
        MockRecord::soa(old_ns_ip.into(), &query_name, &old_ns_name, &rname)
            .with_query_type(RecordType::NS)
            .with_ttl(ttl),
        MockRecord::soa(new_ns_ip.into(), &query_name, &new_ns_name, &rname)
            .with_query_type(RecordType::NS)
            .with_ttl(ttl),
        MockRecord::soa(root_ns_ip.into(), &Name::root(), &root_ns_name, &rname)
            .with_query_name(&old_ns_name)
            .with_query_type(RecordType::NS)
            .with_ttl(ttl),
        MockRecord::soa(root_ns_ip.into(), &Name::root(), &root_ns_name, &rname)
            .with_query_name(&new_ns_name)
            .with_query_type(RecordType::NS)
            .with_ttl(ttl),
        // Provide an SOA record in response to AAAA queries.
        MockRecord::soa(root_ns_ip.into(), &Name::root(), &root_ns_name, &rname)
            .with_query_name(&old_ns_name)
            .with_query_type(RecordType::AAAA)
            .with_ttl(ttl),
        MockRecord::soa(root_ns_ip.into(), &Name::root(), &root_ns_name, &rname)
            .with_query_name(&new_ns_name)
            .with_query_type(RecordType::AAAA)
            .with_ttl(ttl),
    ])
    .with_mutation(Box::new({
        let zone_name = zone_name.clone();
        let switch_referral = switch_referral.clone();
        move |destination: IpAddr, _protocol: Protocol, msg: &mut Message| {
            let query = &msg.queries[0];
            if destination == root_ns_ip && query.name == zone_name {
                // This is a referral, set AA=0.
                msg.metadata.authoritative = false;

                // Check if we should point the referral to the new name server now.
                if switch_referral.load(Ordering::SeqCst) {
                    info!("responding with new referral");
                    msg.answers.clear();
                    msg.authorities.clear();
                    msg.additionals.clear();

                    msg.authorities.push(Record::from_rdata(
                        zone_name.clone(),
                        ttl,
                        RData::NS(NS(new_ns_name.clone())),
                    ));
                    msg.additionals.push(Record::from_rdata(
                        new_ns_name.clone(),
                        ttl,
                        RData::A(A(new_ns_ip)),
                    ));
                } else {
                    info!("responding with old referral");
                }
            }
        }
    }));
    let provider = TestRuntimeProvider(MockProvider::new(handler));
    let recursor = Recursor::new(
        &[root_ns_ip.into()],
        DnssecPolicy::SecurityUnaware,
        None,
        RecursorOptions {
            deny_server: Vec::new(),
            ..Default::default()
        },
        provider,
    )
    .unwrap();

    // There are multiple different subsystems that interact with time in the recursor. DNS and
    // DNSSEC logic uses u64 timestamps, provided by our `Time` implementation. The `moka` cache
    // uses `std::time::Instant`s retrieved directly from the standard library for expiration. Our
    // `ResponseCache` wrapper around that cache takes in `std::time::Instant` arguments to double
    // check whether cache entries are still valid. The name server pool cache uses
    // `tokio::time::Instant` to determine if entries are still valid.
    TIME.set(Some(0));
    let cache_t1 = Instant::now();
    tokio::time::pause();
    let tokio_start = tokio::time::Instant::now();

    info!("first request");
    let response_1 = recursor
        .resolve(
            Query::query(query_name.clone(), RecordType::TXT),
            cache_t1,
            false,
        )
        .await
        .unwrap();
    assert_eq!(response_1.response_code, ResponseCode::NoError);
    assert!(response_1.answers.iter().any(|record| {
        let RData::TXT(TXT {
            txt_data: strings, ..
        }) = &record.data
        else {
            return false;
        };
        strings[0].as_ref() == b"old"
    }));

    // Switch the root zone's referral to point to the new name server.
    switch_referral.store(true, Ordering::SeqCst);

    // Advance time by less than the TTL.
    TIME.set(Some(750));
    let cache_t2 = cache_t1 + Duration::from_secs(750);
    tokio::time::advance(Duration::from_secs(750)).await;

    // Make a query for the apex NS RRset to keep it fresh in the cache.
    info!("second request");
    let response_2 = recursor
        .resolve(
            Query::query(zone_name.clone(), RecordType::NS),
            cache_t2,
            false,
        )
        .await
        .unwrap();
    assert_eq!(response_2.response_code, ResponseCode::NoError);
    assert!(
        response_2
            .all_sections()
            .any(|record| record.record_type() == RecordType::NS)
    );

    // Advance time again. It has now been longer than the TTL since the original request was made,
    // and ever since, the root zone's referral has pointed to the new name server. The resolver
    // should now make a fresh request to the root server to get an updated referral, talk to the
    // new server, and get the new zone data.
    TIME.set(Some(1500));
    let cache_t3 = cache_t1 + Duration::from_secs(1500);
    tokio::time::advance(Duration::from_secs(750)).await;

    // Repeat the original query.
    info!("third request");
    let response_3 = recursor
        .resolve(
            Query::query(query_name.clone(), RecordType::TXT),
            cache_t3,
            false,
        )
        .await
        .unwrap();

    info!(
        elapsed = ?tokio_start.elapsed(),
        "Tokio elapsed time after third request"
    );

    assert_eq!(response_3.response_code, ResponseCode::NoError);
    assert!(
        response_3.answers.iter().any(|record| {
            let RData::TXT(TXT {
                txt_data: strings, ..
            }) = &record.data
            else {
                return false;
            };
            strings[0].as_ref() == b"new"
        }),
        "Did not get new zone's data: {response_3:?}"
    );
}

#[derive(Clone)]
struct TestRuntimeProvider(MockProvider);

impl RuntimeProvider for TestRuntimeProvider {
    type Handle = TokioHandle;

    type Timer = TestTimer;

    type Udp = MockUdpSocket;

    type Tcp = MockTcpStream;

    fn create_handle(&self) -> Self::Handle {
        self.0.create_handle()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> std::pin::Pin<Box<dyn Send + Future<Output = Result<Self::Tcp, io::Error>>>> {
        self.0.connect_tcp(server_addr, bind_addr, timeout)
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> std::pin::Pin<Box<dyn Send + Future<Output = Result<Self::Udp, io::Error>>>> {
        self.0.bind_udp(local_addr, server_addr)
    }
}

struct TestTimer;

#[async_trait::async_trait]
impl Time for TestTimer {
    async fn delay_for(_duration: Duration) {}

    async fn timeout<F: 'static + Future + Send>(
        _duration: Duration,
        future: F,
    ) -> Result<F::Output, io::Error> {
        Ok(future.await)
    }

    fn current_time() -> u64 {
        TIME.get()
            .expect("Mock time has not been set on current threads")
    }
}

thread_local! {
    static TIME: Cell<Option<u64>> = const{ Cell::new(None) };
}
