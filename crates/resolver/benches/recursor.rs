// Benchmarks for the recursive resolver.
//
// Run with:
//
//   cargo bench -p hickory-resolver --features recursor --bench recursor
//
// Each benchmark creates a small in-process mock DNS hierarchy using
// `test_support::MockProvider`, so no real network access is required.

use std::{
    hint::black_box,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Instant,
};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use hickory_resolver::{
    proto::{
        op::Query,
        rr::{Name, RecordType},
    },
    recursor::{Recursor, RecursorOptions},
};
use test_support::{MockNetworkHandler, MockProvider, MockRecord, MockResponseSection};
use tokio::runtime::Runtime;

/// Cold-cache resolution: a fresh `Recursor` with empty NS and response caches
/// is created for every iteration. Measures the full cost of zone-cut discovery
/// plus the final answer lookup.
fn bench_cold_resolve(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("recursor/cold_resolve", |b| {
        b.to_async(&rt).iter_batched(
            make_recursor,
            |(recursor, query_name)| async move {
                black_box(
                    recursor
                        .resolve(
                            Query::query(query_name, RecordType::A),
                            Instant::now(),
                            false,
                        )
                        .await
                        .unwrap(),
                )
            },
            BatchSize::PerIteration,
        );
    });
}

/// Warm-cache resolution: a single `Recursor` is shared across all iterations.
/// Criterion's warmup phase populates the caches; subsequent iterations measure
/// pure cache-hit latency. This is the theoretical lower bound for a cached name.
fn bench_warm_resolve(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let (recursor, query_name) = make_recursor();
    let recursor = Arc::new(recursor);

    c.bench_function("recursor/warm_resolve", |b| {
        b.to_async(&rt).iter(|| {
            let recursor = recursor.clone();
            let query_name = query_name.clone();
            async move {
                black_box(
                    recursor
                        .resolve(
                            Query::query(query_name, RecordType::A),
                            Instant::now(),
                            false,
                        )
                        .await
                        .unwrap(),
                )
            }
        });
    });
}

criterion_group!(benches, bench_cold_resolve, bench_warm_resolve);
criterion_main!(benches);

/// Build a two-level mock DNS hierarchy and return a `Recursor` with its query name:
///
///   . (ROOT_IP)
///   └── testing.       (TLD_IP)
///       └── hickory-dns.testing.  (LEAF_IP)
///           └── host.hickory-dns.testing.  A -> LEAF_IP
fn make_recursor() -> (Recursor<MockProvider>, Name) {
    let query_name = Name::from_ascii("host.hickory-dns.testing.").unwrap();
    let tld_zone = Name::from_ascii("testing.").unwrap();
    let tld_ns = Name::from_ascii("testing.testing.").unwrap();
    let leaf_zone = Name::from_ascii("hickory-dns.testing.").unwrap();
    let leaf_ns = Name::from_ascii("ns.hickory-dns.testing.").unwrap();

    let provider = MockProvider::new(MockNetworkHandler::new(vec![
        // Root → TLD delegation
        MockRecord::ns(ROOT_IP, &tld_zone, &tld_ns),
        MockRecord::a(ROOT_IP, &tld_ns, TLD_IP)
            .with_query_name(&tld_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        // TLD → leaf delegation
        MockRecord::ns(TLD_IP, &leaf_zone, &leaf_ns),
        MockRecord::a(TLD_IP, &leaf_ns, LEAF_IP)
            .with_query_name(&leaf_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        // Leaf answer
        MockRecord::a(LEAF_IP, &query_name, LEAF_IP),
    ]));

    let recursor = Recursor::with_options(
        &[ROOT_IP],
        RecursorOptions {
            deny_server: Vec::new(),
            ..RecursorOptions::default()
        },
        provider,
    )
    .unwrap();

    (recursor, query_name)
}

const ROOT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
const TLD_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
const LEAF_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 3, 1));
