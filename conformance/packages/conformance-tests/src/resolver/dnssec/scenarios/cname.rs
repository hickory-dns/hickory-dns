use std::net::Ipv4Addr;

use dns_test::{
    FQDN, Network, PEER, Resolver, Result,
    client::{Client, DigSettings, DigStatus},
    name_server::{Graph, NameServer, Sign},
    record::{A, CNAME, RRSIG, Record, RecordType},
    zone_file::SignSettings,
};

#[test]
#[ignore = "hickory duplicates some records"]
fn dnssec_ok() -> Result<()> {
    let (_network, _graph, resolver, client) = setup_cname()?;
    let output = client.dig(
        *DigSettings::default().recurse().dnssec().authentic_data(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("alias2"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert!(output.flags.authenticated_data);
    assert_eq!(output.answer.len(), 6, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("host")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::RRSIG(RRSIG { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("host")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::RRSIG(RRSIG { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias2")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::RRSIG(RRSIG { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias2")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    Ok(())
}

#[test]
#[ignore = "hickory duplicates some records"]
fn dnssec_ok_cached() -> Result<()> {
    let (_network, _graph, resolver, client) = setup_cname()?;
    client.dig(
        *DigSettings::default().recurse().dnssec().authentic_data(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("alias2"),
    )?;
    let output = client.dig(
        *DigSettings::default().recurse().dnssec().authentic_data(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("alias2"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert!(output.flags.authenticated_data);
    assert_eq!(output.answer.len(), 6, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("host")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::RRSIG(RRSIG { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("host")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::RRSIG(RRSIG { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias2")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::RRSIG(RRSIG { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias2")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    Ok(())
}

#[test]
#[ignore = "hickory duplicates some records"]
fn checking_disabled() -> Result<()> {
    let (_network, _graph, resolver, client) = setup_cname()?;
    let output = client.dig(
        *DigSettings::default()
            .recurse()
            .dnssec()
            .checking_disabled(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("alias2"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 6, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("host")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::RRSIG(RRSIG { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("host")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::RRSIG(RRSIG { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias2")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::RRSIG(RRSIG { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias2")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    Ok(())
}

#[test]
#[ignore = "hickory duplicates some records"]
fn checking_disabled_cached() -> Result<()> {
    let (_network, _graph, resolver, client) = setup_cname()?;
    client.dig(
        *DigSettings::default()
            .recurse()
            .dnssec()
            .checking_disabled(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("alias2"),
    )?;
    let output = client.dig(
        *DigSettings::default()
            .recurse()
            .dnssec()
            .checking_disabled(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("alias2"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 6, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("host")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::RRSIG(RRSIG { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("host")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::RRSIG(RRSIG { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias2")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::RRSIG(RRSIG { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias2")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    Ok(())
}

#[test]
#[ignore = "hickory duplicates some records"]
fn no_dnssec() -> Result<()> {
    let (_network, _graph, resolver, client) = setup_cname()?;
    let output = client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("alias2"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert!(!output.flags.authenticated_data);
    assert_eq!(output.answer.len(), 3, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("host")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias2")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    Ok(())
}

#[test]
#[ignore = "hickory duplicates some records"]
fn no_dnssec_cached() -> Result<()> {
    let (_network, _graph, resolver, client) = setup_cname()?;
    client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("alias2"),
    )?;
    let output = client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("alias2"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert!(!output.flags.authenticated_data);
    assert_eq!(output.answer.len(), 3, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("host")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias2")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    Ok(())
}

fn setup_cname() -> Result<(Network, Graph, Resolver, Client)> {
    let network = Network::new()?;
    let mut leaf_ns = NameServer::new(&PEER, FQDN::TEST_DOMAIN, &network)?;
    leaf_ns.add(A {
        fqdn: FQDN::TEST_DOMAIN.push_label("host"),
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 168, 1, 1),
    });
    leaf_ns.add(CNAME {
        fqdn: FQDN::TEST_DOMAIN.push_label("alias"),
        ttl: 3600,
        target: FQDN::TEST_DOMAIN.push_label("host"),
    });
    leaf_ns.add(CNAME {
        fqdn: FQDN::TEST_DOMAIN.push_label("alias2"),
        ttl: 3600,
        target: FQDN::TEST_DOMAIN.push_label("alias"),
    });

    let graph = Graph::build(
        leaf_ns,
        Sign::Yes {
            settings: SignSettings::default(),
        },
    )?;

    let resolver = Resolver::new(&network, graph.root.clone())
        .trust_anchor(graph.trust_anchor.as_ref().unwrap())
        .start()?;
    let client = Client::new(&network)?;

    Ok((network, graph, resolver, client))
}
