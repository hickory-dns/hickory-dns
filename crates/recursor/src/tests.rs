use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{Error, Recursor, RecursorBuilder, recursor::RecursorMode};
use hickory_proto::{
    ProtoError,
    op::{Message, Query, ResponseCode},
    rr::{Name, Record, RecordType},
};
use hickory_resolver::{
    TtlConfig,
    config::{ProtocolConfig, ResolverOpts},
};
use test_support::{MockNetworkHandler, MockProvider, MockRecord, MockResponseSection, subscribe};
use tokio::time as TokioTime;

#[tokio::test]
async fn recursor_connection_deduplication() -> Result<(), ProtoError> {
    subscribe();

    let query_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let dup_query_name = Name::from_ascii("host.hickory-dns-dup.testing.")?;
    let (provider, recursor_builder) = test_fixture()?;
    let recursor = recursor_builder.build(&[ROOT_IP])?;

    // This test is inspecting the number of new TCP connection calls for each nameserver.
    // If deduplication is working correctly, there should be one for each after the
    // first query (because the handler returns truncated messages), and there should
    // still be one for each after the second query, particularly to the leaf IP which
    // is used in two separate zones.
    for query in [query_name, dup_query_name] {
        let response = recursor
            .resolve(Query::query(query, RecordType::A), Instant::now(), false)
            .await?;

        assert_eq!(response.response_code(), ResponseCode::NoError);

        assert_eq!(
            provider.count_new_connection_calls(ROOT_IP, ProtocolConfig::Tcp),
            1
        );
        assert_eq!(
            provider.count_new_connection_calls(TLD_IP, ProtocolConfig::Tcp),
            1
        );
        assert_eq!(
            provider.count_new_connection_calls(LEAF_IP, ProtocolConfig::Tcp),
            1
        );
    }

    Ok(())
}

#[tokio::test]
async fn recursor_connection_deduplication_non_cached() -> Result<(), ProtoError> {
    subscribe();

    let query_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let dup_query_name = Name::from_ascii("host.hickory-dns-dup.testing.")?;
    let (provider, recursor_builder) = test_fixture()?;
    let recursor = recursor_builder.ns_cache_size(1).build(&[ROOT_IP])?;

    let response = recursor
        .resolve(
            Query::query(query_name, RecordType::A),
            Instant::now(),
            false,
        )
        .await?;

    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert_eq!(
        provider.count_new_connection_calls(ROOT_IP, ProtocolConfig::Tcp),
        1
    );
    assert_eq!(
        provider.count_new_connection_calls(TLD_IP, ProtocolConfig::Tcp),
        1
    );
    assert_eq!(
        provider.count_new_connection_calls(LEAF_IP, ProtocolConfig::Tcp),
        1
    );

    // With the ns_cache_size set to 1, we should see new connections for the TLD
    // and leaf queries because the NameServer objects have dropped out of the
    // connection cache.
    let response = recursor
        .resolve(
            Query::query(dup_query_name, RecordType::A),
            Instant::now(),
            false,
        )
        .await
        .unwrap();

    assert_eq!(response.response_code(), ResponseCode::NoError);
    // Roots aren't subject to cache expiration
    assert_eq!(
        provider.count_new_connection_calls(ROOT_IP, ProtocolConfig::Tcp),
        1
    );
    assert_eq!(
        provider.count_new_connection_calls(TLD_IP, ProtocolConfig::Tcp),
        2
    );
    assert_eq!(
        provider.count_new_connection_calls(LEAF_IP, ProtocolConfig::Tcp),
        2
    );

    Ok(())
}

#[tokio::test(start_paused = true)]
async fn name_server_cache_ttl() -> Result<(), ProtoError> {
    let query_1_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let query_2_name = Name::from_ascii("host2.hickory-dns.testing.")?;

    let target_1_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_1_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
    let target_2_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_2_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));

    let zone_ttl = 60;
    let recursor = ns_cache_test_fixture(zone_ttl, zone_ttl, TtlConfig::default(), false)?;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_1));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_1));

    // Query the names again after pausing for 2 * the zone ttl, which should
    // force the recursor to discard the cached zone and query again.  The TLD
    // server will return a different nameserver on the second query which will
    // in turn provide different answers to the A queries.
    let _ = TokioTime::advance(Duration::from_secs((zone_ttl * 2) as u64)).await;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_2));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_2));

    Ok(())
}

#[tokio::test(start_paused = true)]
async fn name_server_cache_ttl_clamp_min() -> Result<(), ProtoError> {
    let query_1_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let query_2_name = Name::from_ascii("host2.hickory-dns.testing.")?;

    let target_1_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_1_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
    let target_2_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_2_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));

    let zone_ttl = 60;
    let recursor_min_ttl: u32 = 240;
    let recursor_max_ttl = 86400;

    assert!(zone_ttl * 2 < recursor_min_ttl); // test pre-requisite
    let mut opts = ResolverOpts::default();
    opts.positive_min_ttl = Some(Duration::from_secs(recursor_min_ttl as u64));
    opts.positive_max_ttl = Some(Duration::from_secs(recursor_max_ttl));

    let recursor = ns_cache_test_fixture(zone_ttl, zone_ttl, TtlConfig::from_opts(&opts), false)?;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_1));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_1));

    // Wait for longer than the zone ttl, but less than the recursor_min_ttl to make sure
    // the cache was clamped.  The A queries should return the same results as above.
    let _ = TokioTime::advance(Duration::from_secs(u64::from(zone_ttl * 2))).await;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_1));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_1));

    // Wait for recursor_min_ttl seconds, which should cause the NS cache to expire.
    let _ = TokioTime::advance(Duration::from_secs(recursor_min_ttl as u64)).await;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_2));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_2));

    Ok(())
}

#[tokio::test(start_paused = true)]
async fn name_server_cache_ttl_clamp_max() -> Result<(), ProtoError> {
    let query_1_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let query_2_name = Name::from_ascii("host2.hickory-dns.testing.")?;

    let target_1_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_1_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
    let target_2_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_2_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));

    let zone_ttl: u32 = 3600;
    let recursor_min_ttl = 1;
    let recursor_max_ttl = 60;

    assert!(zone_ttl > recursor_max_ttl * 2); // test pre-requisite

    let mut opts = ResolverOpts::default();
    opts.positive_min_ttl = Some(Duration::from_secs(recursor_min_ttl));
    opts.positive_max_ttl = Some(Duration::from_secs(recursor_max_ttl as u64));

    let recursor = ns_cache_test_fixture(zone_ttl, zone_ttl, TtlConfig::from_opts(&opts), false)?;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_1));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_1));

    // Wait for longer than the recursor_max_ttl, but less than the zone ttl to make
    // sure the max clamp is respected.
    let _ = TokioTime::advance(Duration::from_secs(u64::from(recursor_max_ttl * 2))).await;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_2));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_2));

    Ok(())
}

#[tokio::test(start_paused = true)]
async fn name_server_cache_ttl_glue() -> Result<(), ProtoError> {
    let query_1_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let query_2_name = Name::from_ascii("host2.hickory-dns.testing.")?;

    let target_1_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_1_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
    let target_2_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_2_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));

    let zone_ttl = 60;
    let ns_ttl = 15;

    assert!(zone_ttl > ns_ttl * 2); // test pre-requisite
    let recursor = ns_cache_test_fixture(zone_ttl, ns_ttl, TtlConfig::default(), false)?;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_1));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_1));

    // Query the names again after pausing for 2 * the glue record ttl, which should
    // force the recursor to discard the cached zone and query again.  The TLD
    // server will return a different nameserver on the second query which will
    // in turn provide different answers to the A queries.
    let _ = TokioTime::advance(Duration::from_secs((ns_ttl * 2) as u64)).await;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_2));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_2));

    Ok(())
}

#[tokio::test(start_paused = true)]
async fn name_server_cache_ttl_glue_off_domain() -> Result<(), ProtoError> {
    let query_1_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let query_2_name = Name::from_ascii("host2.hickory-dns.testing.")?;

    let target_1_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_1_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
    let target_2_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_2_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));

    let zone_ttl = 60;
    let ns_ttl = 15;

    assert!(zone_ttl > ns_ttl * 2); // test pre-requisite
    // Use ns.otherdomain.testing. as the authoritative name server for this test.
    let recursor = ns_cache_test_fixture(zone_ttl, ns_ttl, TtlConfig::default(), true)?;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_1));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_1));

    // Query the names again after pausing for 2 * the ns record ttl, which should
    // force the recursor to discard the cached zone and query again.  The TLD
    // server will return a different nameserver on the second query which will
    // in turn provide different answers to the A queries.
    let _ = TokioTime::advance(Duration::from_secs((ns_ttl * 2) as u64)).await;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_2));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_2));

    Ok(())
}

#[tokio::test]
async fn ns_pool_zone_name_test() -> Result<(), ProtoError> {
    subscribe();

    let query_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let nx_query_name = Name::from_ascii("invalid.hickory-dns.testing.")?;
    let delegated_query_name = Name::from_ascii("host.delegated.hickory-dns.testing.")?;
    let ent_query_name = Name::from_ascii("ent.hickory-dns.testing.")?;
    let ent_delegated_query_name = Name::from_ascii("host.delegated.ent.hickory-dns.testing.")?;

    let tld_zone = Name::from_ascii("testing.")?;
    let tld_ns = Name::from_ascii("testing.testing.")?;
    let leaf_zone = Name::from_ascii("hickory-dns.testing.")?;
    let leaf_ns = Name::from_ascii("ns.hickory-dns.testing.")?;
    let delegated_leaf_zone = Name::from_ascii("delegated.hickory-dns.testing.")?;
    let delegated_leaf_ns = Name::from_ascii("ns.delegated.hickory-dns.testing.")?;
    let ent_delegated_leaf_zone = Name::from_ascii("delegated.ent.hickory-dns.testing.")?;
    let ent_delegated_leaf_ns = Name::from_ascii("ns.delegated.ent.hickory-dns.testing.")?;

    let responses = vec![
        MockRecord::ns(ROOT_IP, &tld_zone, &tld_ns),
        MockRecord::a(ROOT_IP, &tld_ns, TLD_IP)
            .with_query_name(&tld_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::ns(TLD_IP, &leaf_zone, &leaf_ns),
        MockRecord::a(TLD_IP, &leaf_ns, LEAF_IP)
            .with_query_name(&leaf_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::ns(LEAF_IP, &delegated_leaf_zone, &delegated_leaf_ns),
        MockRecord::a(LEAF_IP, &delegated_leaf_ns, DELEGATED_LEAF_IP)
            .with_query_name(&delegated_leaf_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::ns(LEAF_IP, &ent_delegated_leaf_zone, &ent_delegated_leaf_ns),
        MockRecord::a(LEAF_IP, &ent_delegated_leaf_ns, ENT_DELEGATED_LEAF_IP)
            .with_query_name(&ent_delegated_leaf_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::a(LEAF_IP, &query_name, LEAF_IP),
        MockRecord::a(LEAF_IP, &ent_query_name, LEAF_IP),
        MockRecord::a(DELEGATED_LEAF_IP, &delegated_query_name, DELEGATED_LEAF_IP),
        MockRecord::a(
            ENT_DELEGATED_LEAF_IP,
            &ent_delegated_query_name,
            ENT_DELEGATED_LEAF_IP,
        ),
    ];

    let recursor_no_cache = Recursor::builder_with_provider(MockProvider::new(
        MockNetworkHandler::new(responses.clone()),
    ))
    .clear_deny_servers()
    .ns_cache_size(1)
    .build(&[ROOT_IP])?;

    let recursor_cache =
        Recursor::builder_with_provider(MockProvider::new(MockNetworkHandler::new(responses)))
            .clear_deny_servers()
            .ns_cache_size(1024)
            .build(&[ROOT_IP])?;

    for recursor in [recursor_no_cache, recursor_cache] {
        assert_eq!(
            get_zone_name(&recursor, &query_name).await?,
            Some(leaf_zone.clone())
        );
        assert_eq!(
            get_zone_name(&recursor, &leaf_zone).await?,
            Some(leaf_zone.clone())
        );
        assert_eq!(
            get_zone_name(&recursor, &nx_query_name).await?,
            Some(leaf_zone.clone())
        );
        assert_eq!(
            get_zone_name(&recursor, &delegated_query_name).await?,
            Some(delegated_leaf_zone.clone())
        );
        assert_eq!(
            get_zone_name(&recursor, &ent_query_name).await?,
            Some(leaf_zone.clone())
        );
        assert_eq!(
            get_zone_name(&recursor, &ent_delegated_query_name).await?,
            Some(ent_delegated_leaf_zone.clone())
        );

        // Sanity check - IPs are correct
        assert!(validate_response(
            ttl_lookup(&recursor, &query_name).await?,
            &query_name,
            LEAF_IP
        ));
        assert!(validate_response(
            ttl_lookup(&recursor, &delegated_query_name).await?,
            &delegated_query_name,
            DELEGATED_LEAF_IP
        ));
        assert!(validate_response(
            ttl_lookup(&recursor, &ent_delegated_query_name).await?,
            &ent_delegated_query_name,
            ENT_DELEGATED_LEAF_IP
        ));
    }

    Ok(())
}

async fn get_zone_name(
    recursor: &Recursor<MockProvider>,
    query: &Name,
) -> Result<Option<Name>, ProtoError> {
    match recursor.mode {
        RecursorMode::NonValidating { ref handle } => {
            let ns_pool = handle
                .ns_pool_for_name(query.clone(), Instant::now(), 0)
                .await?
                .1;
            Ok(ns_pool.zone().cloned())
        }
        #[cfg(feature = "__dnssec")]
        _ => panic!("test doesn't support validating mode"),
    }
}

fn ns_cache_test_fixture(
    zone_ttl: u32,
    ns_ttl: u32,
    ttl_config: TtlConfig,
    off_domain: bool,
) -> Result<Recursor<MockProvider>, Error> {
    subscribe();
    let query_1_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let query_2_name = Name::from_ascii("host2.hickory-dns.testing.")?;

    let tld_zone = Name::from_ascii("testing.")?;
    let tld_ns = Name::from_ascii("testing.testing.")?;
    let leaf_zone = Name::from_ascii("hickory-dns.testing.")?;
    let leaf_ns = Name::from_ascii("ns.hickory-dns.testing.")?;
    let off_domain_zone = Name::from_ascii("otherdomain.testing.")?;
    let off_domain_ns = Name::from_ascii("ns.otherdomain.testing.")?;
    let off_domain_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 5, 1));
    let leaf_2_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 4, 1));
    let target_1_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_1_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
    let target_2_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_2_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));

    let mut responses = vec![
        MockRecord::ns(ROOT_IP, &tld_zone, &tld_ns),
        MockRecord::a(ROOT_IP, &tld_ns, TLD_IP)
            .with_query_name(&tld_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::a(LEAF_IP, &query_1_name, target_1_ip_1).with_ttl(0),
        MockRecord::a(leaf_2_ip, &query_1_name, target_1_ip_2).with_ttl(0),
        MockRecord::a(LEAF_IP, &query_2_name, target_2_ip_1).with_ttl(0),
        MockRecord::a(leaf_2_ip, &query_2_name, target_2_ip_2).with_ttl(0),
    ];

    // Off domain here refers to a zone (hickory-dns.testing.) with an authoritative name server
    // in a completely unrelated zone (otherdomain.testing.)  ns_pool_for_zone collects these
    // addresses differently, so we need a separate test to ensure the TTL tracking code is
    // working in all cases.
    if off_domain {
        responses.append(
            &mut [
                MockRecord::ns(TLD_IP, &leaf_zone, &off_domain_ns).with_ttl(zone_ttl),
                MockRecord::ns(TLD_IP, &off_domain_zone, &off_domain_ns).with_ttl(zone_ttl),
                MockRecord::a(TLD_IP, &off_domain_ns, off_domain_ip)
                    .with_query_name(&off_domain_zone)
                    .with_query_type(RecordType::NS)
                    .with_section(MockResponseSection::Additional)
                    .with_ttl(zone_ttl),
                MockRecord::soa(
                    off_domain_ip,
                    &off_domain_ns,
                    &off_domain_zone,
                    &off_domain_ns,
                )
                .with_query_name(&off_domain_ns)
                .with_query_type(RecordType::NS),
                MockRecord::a(off_domain_ip, &off_domain_ns, LEAF_IP).with_ttl(ns_ttl),
            ]
            .into_iter()
            .collect::<Vec<MockRecord>>(),
        );
    } else {
        responses.append(
            &mut [
                MockRecord::ns(TLD_IP, &leaf_zone, &leaf_ns).with_ttl(zone_ttl),
                MockRecord::a(TLD_IP, &leaf_ns, LEAF_IP)
                    .with_query_name(&leaf_zone)
                    .with_query_type(RecordType::NS)
                    .with_section(MockResponseSection::Additional)
                    .with_ttl(ns_ttl),
            ]
            .into_iter()
            .collect::<Vec<MockRecord>>(),
        );
    }

    let counter = Arc::new(AtomicU8::new(0));

    let handler = MockNetworkHandler::new(responses).with_mutation(Box::new(
        move |destination: IpAddr, _protocol: ProtocolConfig, msg: &mut Message| {
            let leaf_ns = leaf_ns.clone();
            let query_name = msg.queries()[0].name();
            let query_type = msg.queries()[0].query_type();

            if !off_domain {
                if destination == TLD_IP && *query_name == leaf_zone && query_type == RecordType::NS
                {
                    let count = counter.fetch_add(1, Ordering::Relaxed);
                    if count > 0 {
                        let _ = msg.take_additionals();
                        msg.add_additional(Record::from_rdata(leaf_ns, ns_ttl, leaf_2_ip.into()));
                    }
                }
            } else if destination == off_domain_ip
                && *query_name == off_domain_ns
                && query_type == RecordType::A
            {
                let count = counter.fetch_add(1, Ordering::Relaxed);
                if count > 0 {
                    let _ = msg.take_answers();
                    msg.add_answer(Record::from_rdata(leaf_ns, zone_ttl, leaf_2_ip.into()));
                }
            }
        },
    ));

    let provider = MockProvider::new(handler);
    Recursor::builder_with_provider(provider)
        .clear_deny_servers() // We use addresses in the default deny filters.
        .ttl_config(ttl_config)
        .build(&[ROOT_IP])
}

async fn ttl_lookup(recursor: &Recursor<MockProvider>, name: &Name) -> Result<Message, Error> {
    recursor
        .resolve(
            Query::query(name.clone(), RecordType::A),
            TokioTime::Instant::now().into(),
            false,
        )
        .await
}

fn validate_response(response: Message, name: &Name, ip: IpAddr) -> bool {
    response.response_code() == ResponseCode::NoError
        && response.answers() == [Record::from_rdata(name.clone(), 0, ip.into())]
}

fn test_fixture() -> Result<(MockProvider, RecursorBuilder<MockProvider>), ProtoError> {
    let query_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let dup_query_name = Name::from_ascii("host.hickory-dns-dup.testing.")?;

    let tld_zone = Name::from_ascii("testing.")?;
    let tld_ns = Name::from_ascii("testing.testing.")?;
    let leaf_zone = Name::from_ascii("hickory-dns.testing.")?;
    let leaf_ns = Name::from_ascii("ns.hickory-dns.testing.")?;
    let dup_leaf_zone = Name::from_ascii("hickory-dns-dup.testing.")?;
    let dup_leaf_ns = Name::from_ascii("ns.hickory-dns-dup.testing.")?;

    let responses = vec![
        MockRecord::ns(ROOT_IP, &tld_zone, &tld_ns),
        MockRecord::a(ROOT_IP, &tld_ns, TLD_IP)
            .with_query_name(&tld_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::ns(TLD_IP, &leaf_zone, &leaf_ns),
        MockRecord::a(TLD_IP, &leaf_ns, LEAF_IP)
            .with_query_name(&leaf_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::ns(TLD_IP, &dup_leaf_zone, &dup_leaf_ns),
        MockRecord::a(TLD_IP, &dup_leaf_ns, LEAF_IP)
            .with_query_name(&dup_leaf_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::a(LEAF_IP, &query_name, LEAF_IP),
        MockRecord::a(LEAF_IP, &dup_query_name, LEAF_IP),
    ];

    let handler = MockNetworkHandler::new(responses).with_mutation(Box::new(
        |_destination: IpAddr, protocol: ProtocolConfig, msg: &mut Message| {
            if protocol == ProtocolConfig::Udp {
                msg.set_truncated(true);
            }
        },
    ));

    let provider = MockProvider::new(handler);
    let recursor = Recursor::builder_with_provider(provider.clone()).clear_deny_servers(); // We use addresses in the default deny filters.

    Ok((provider, recursor))
}

const ROOT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
const TLD_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
const LEAF_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 3, 1));
const DELEGATED_LEAF_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 4, 1));
const ENT_DELEGATED_LEAF_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 5, 1));
