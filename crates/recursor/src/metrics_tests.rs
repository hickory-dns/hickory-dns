use std::{net::Ipv4Addr, time::Instant};

use hickory_proto::{
    op::{Query, ResponseCode},
    rr::{Name, RecordType},
};
use metrics::{Key, Unit, with_local_recorder};
use metrics_util::{
    CompositeKey, MetricKind,
    debugging::{DebugValue, DebuggingRecorder},
};
use test_support::{MockNetworkHandler, MockProvider, MockRecord, MockResponseSection, subscribe};
use tokio::runtime::Builder;

use crate::Recursor;

#[test]
fn test_recursor_metrics() {
    subscribe();
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    let query_name = Name::parse("hickory-dns.testing.", None).unwrap();

    with_local_recorder(&recorder, || {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();

        let tld_zone = Name::from_ascii("testing.").unwrap();
        let tld_ns = Name::from_ascii("testing.testing.").unwrap();
        let leaf_zone = Name::from_ascii("hickory-dns.testing.").unwrap();
        let leaf_ns = Name::from_ascii("leaf.testing.").unwrap();

        let handler = MockNetworkHandler::new(vec![
            MockRecord::ns(ROOT_IP.into(), &tld_zone, &tld_ns),
            MockRecord::a(ROOT_IP.into(), &tld_ns, TLD_IP.into())
                .with_query_name(&tld_zone)
                .with_query_type(RecordType::NS)
                .with_section(MockResponseSection::Additional),
            MockRecord::ns(TLD_IP.into(), &leaf_zone, &leaf_ns),
            MockRecord::a(TLD_IP.into(), &leaf_ns, LEAF_IP.into())
                .with_query_name(&leaf_zone)
                .with_query_type(RecordType::NS)
                .with_section(MockResponseSection::Additional),
            MockRecord::a(LEAF_IP.into(), &leaf_zone, A_RR_IP.into()),
        ]);

        let provider = MockProvider::new(handler);
        runtime.block_on(async {
            let recursor = Recursor::builder_with_provider(provider)
                .clear_deny_servers() // We use addresses in the default deny filters.
                .build(&[ROOT_IP.into()])
                .unwrap();
            for _ in 0..3 {
                let response = recursor
                    .resolve(
                        Query::query(query_name.clone(), RecordType::A),
                        Instant::now(),
                        false,
                    )
                    .await
                    .unwrap();
                assert_eq!(response.response_code(), ResponseCode::NoError);
            }
        });
    });

    #[allow(clippy::mutable_key_type)] // False positive, see the documentation for metrics::Key.
    let map = snapshotter.snapshot().into_hashmap();

    let (unit_opt, description_opt, value) = map
        .get(&CompositeKey::new(
            MetricKind::Counter,
            Key::from_name("hickory_recursor_outgoing_queries_total"),
        ))
        .unwrap();
    assert_eq!(unit_opt, &Some(Unit::Count));
    assert!(description_opt.is_some());
    assert_eq!(value, &DebugValue::Counter(3));

    let (unit_opt, description_opt, value) = map
        .get(&CompositeKey::new(
            MetricKind::Counter,
            Key::from_name("hickory_recursor_cache_hit_total"),
        ))
        .unwrap();
    assert_eq!(unit_opt, &Some(Unit::Count));
    assert!(description_opt.is_some());
    assert_eq!(value, &DebugValue::Counter(2));

    let (unit_opt, description_opt, value) = map
        .get(&CompositeKey::new(
            MetricKind::Counter,
            Key::from_name("hickory_recursor_cache_miss_total"),
        ))
        .unwrap();
    assert_eq!(unit_opt, &Some(Unit::Count));
    assert!(description_opt.is_some());
    assert_eq!(value, &DebugValue::Counter(1));
}

const ROOT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 1);
const TLD_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 1);
const LEAF_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 3, 1);
const A_RR_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
