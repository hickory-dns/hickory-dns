use std::net::Ipv4Addr;

use dns_test::{
    Error, FQDN, Network, PEER, Resolver,
    client::{Client, DigSettings, DigStatus},
    name_server::{Graph, NameServer, Running, Sign},
    record::{A, CNAME, Record, RecordType},
};

#[test]
fn basic() -> Result<(), Error> {
    let (_network, _graph, resolver, client) = setup_cname()?;
    let output = client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("alias"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 2, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output.answer.iter().any(|record| {
            if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("host")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    assert!(
        output.answer.iter().any(|record| {
            if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    Ok(())
}

#[test]
fn longer_chain() -> Result<(), Error> {
    let (_network, _graph, resolver, client) = setup_cname()?;
    let output = client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("alias2"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 3, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output.answer.iter().any(|record| {
            if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("host")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    assert!(
        output.answer.iter().any(|record| {
            if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    assert!(
        output.answer.iter().any(|record| {
            if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias2")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    Ok(())
}

#[test]
fn basic_cached() -> Result<(), Error> {
    let (_network, _graph, resolver, client) = setup_cname()?;
    client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("alias"),
    )?;
    let output = client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("alias"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 2, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output.answer.iter().any(|record| {
            if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("host")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    assert!(
        output.answer.iter().any(|record| {
            if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    Ok(())
}

#[test]
fn longer_chain_cached() -> Result<(), Error> {
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
    assert_eq!(output.answer.len(), 3, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output.answer.iter().any(|record| {
            if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("host")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    assert!(
        output.answer.iter().any(|record| {
            if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    assert!(
        output.answer.iter().any(|record| {
            if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias2")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    Ok(())
}

fn setup_cname() -> Result<(Network, Graph, Resolver, Client), Error> {
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

    let graph = Graph::build(leaf_ns, Sign::No)?;

    let resolver = Resolver::new(&network, graph.root.clone()).start()?;
    let client = Client::new(&network)?;

    Ok((network, graph, resolver, client))
}

#[test]
fn basic_cross_zone() -> Result<(), Error> {
    let (_network, _nameservers, resolver, client) = setup_cname_cross_zone()?;
    let output = client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::EXAMPLE_SUBDOMAIN.push_label("alias"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 2, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output.answer.iter().any(|record| {
            if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("other").push_label("host")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    assert!(
        output.answer.iter().any(|record| {
            if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::EXAMPLE_SUBDOMAIN.push_label("alias")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    Ok(())
}

#[test]
fn basic_cross_zone_cached() -> Result<(), Error> {
    let (_network, _nameservers, resolver, client) = setup_cname_cross_zone()?;
    client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::EXAMPLE_SUBDOMAIN.push_label("alias"),
    )?;
    let output = client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::EXAMPLE_SUBDOMAIN.push_label("alias"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 2, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output.answer.iter().any(|record| {
            if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("other").push_label("host")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    assert!(
        output.answer.iter().any(|record| {
            if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::EXAMPLE_SUBDOMAIN.push_label("alias")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    Ok(())
}

#[allow(clippy::type_complexity)]
fn setup_cname_cross_zone() -> Result<(Network, Vec<NameServer<Running>>, Resolver, Client), Error>
{
    let network = Network::new()?;
    let mut leaf_1_ns = NameServer::new(&PEER, FQDN::EXAMPLE_SUBDOMAIN, &network)?;
    leaf_1_ns.add(CNAME {
        fqdn: FQDN::EXAMPLE_SUBDOMAIN.push_label("alias"),
        ttl: 3600,
        target: FQDN::TEST_DOMAIN.push_label("other").push_label("host"),
    });
    let mut leaf_2_ns = NameServer::new(&PEER, FQDN::TEST_DOMAIN.push_label("other"), &network)?;
    leaf_2_ns.add(A {
        fqdn: FQDN::TEST_DOMAIN.push_label("other").push_label("host"),
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 168, 1, 1),
    });

    let mut domain_ns = NameServer::new(&PEER, FQDN::TEST_DOMAIN, &network)?;
    domain_ns.referral_nameserver(&leaf_1_ns);
    domain_ns.referral_nameserver(&leaf_2_ns);

    let mut tld_ns = NameServer::new(&PEER, FQDN::TEST_TLD, &network)?;
    tld_ns.referral_nameserver(&domain_ns);

    let mut root_ns = NameServer::new(&PEER, FQDN::ROOT, &network)?;
    root_ns.referral_nameserver(&tld_ns);
    let root = root_ns.root_hint();

    let nameservers = vec![
        leaf_1_ns.start()?,
        leaf_2_ns.start()?,
        domain_ns.start()?,
        tld_ns.start()?,
        root_ns.start()?,
    ];

    let resolver = Resolver::new(&network, root).start()?;
    let client = Client::new(&network)?;

    Ok((network, nameservers, resolver, client))
}
