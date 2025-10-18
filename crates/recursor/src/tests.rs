use std::{
    net::{IpAddr, Ipv4Addr},
    time::Instant,
};

use hickory_proto::{
    ProtoError,
    op::{Message, Query, ResponseCode},
    rr::{Name, RecordType},
};
use hickory_resolver::config::ProtocolConfig;
use test_support::{MockNetworkHandler, MockProvider, MockRecord, MockResponseSection, subscribe};

use crate::{Recursor, RecursorBuilder};

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
