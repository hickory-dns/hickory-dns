use std::net::Ipv4Addr;

use dns_test::{
    Error, FQDN, Network, PEER, Resolver,
    client::{Client, DigSettings, DigStatus},
    name_server::{Graph, NameServer, Running, Sign},
    record::{A, CNAME, RRSIG, Record, RecordType},
    zone_file::SignSettings,
};

#[test]
fn dnssec_ok() -> Result<(), Error> {
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
fn dnssec_ok_cached() -> Result<(), Error> {
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
fn checking_disabled() -> Result<(), Error> {
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
fn checking_disabled_cached() -> Result<(), Error> {
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
fn no_dnssec() -> Result<(), Error> {
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
fn no_dnssec_cached() -> Result<(), Error> {
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

#[test]
fn dnssec_ok_cross_zone() -> Result<(), Error> {
    let (_network, _nameservers, resolver, client) = setup_cname_cross_zone()?;
    let output = client.dig(
        *DigSettings::default().recurse().dnssec().authentic_data(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::EXAMPLE_SUBDOMAIN.push_label("alias"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert!(output.flags.authenticated_data);
    assert_eq!(output.answer.len(), 4, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("other").push_label("host")
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
                fqdn == &FQDN::TEST_DOMAIN.push_label("other").push_label("host")
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
                fqdn == &FQDN::EXAMPLE_SUBDOMAIN.push_label("alias")
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
                fqdn == &FQDN::EXAMPLE_SUBDOMAIN.push_label("alias")
            } else {
                false
            }),
        "{:?}",
        output.answer
    );
    Ok(())
}

#[test]
fn dnssec_ok_cross_zone_cached() -> Result<(), Error> {
    let (_network, _nameservers, resolver, client) = setup_cname_cross_zone()?;
    client.dig(
        *DigSettings::default().recurse().dnssec().authentic_data(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::EXAMPLE_SUBDOMAIN.push_label("alias"),
    )?;
    let output = client.dig(
        *DigSettings::default().recurse().dnssec().authentic_data(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::EXAMPLE_SUBDOMAIN.push_label("alias"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert!(output.flags.authenticated_data);
    assert_eq!(output.answer.len(), 4, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output
            .answer
            .iter()
            .any(|record| if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("other").push_label("host")
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
                fqdn == &FQDN::TEST_DOMAIN.push_label("other").push_label("host")
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
                fqdn == &FQDN::EXAMPLE_SUBDOMAIN.push_label("alias")
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
                fqdn == &FQDN::EXAMPLE_SUBDOMAIN.push_label("alias")
            } else {
                false
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
    let settings = SignSettings::default();

    let mut leaf_1_ns = NameServer::new(&PEER, FQDN::EXAMPLE_SUBDOMAIN, &network)?;
    leaf_1_ns.add(CNAME {
        fqdn: FQDN::EXAMPLE_SUBDOMAIN.push_label("alias"),
        ttl: 3600,
        target: FQDN::TEST_DOMAIN.push_label("other").push_label("host"),
    });
    let leaf_1_ns = leaf_1_ns.sign(settings.clone())?;

    let mut leaf_2_ns = NameServer::new(&PEER, FQDN::TEST_DOMAIN.push_label("other"), &network)?;
    leaf_2_ns.add(A {
        fqdn: FQDN::TEST_DOMAIN.push_label("other").push_label("host"),
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 168, 1, 1),
    });
    let leaf_2_ns = leaf_2_ns.sign(settings.clone())?;

    let mut domain_ns = NameServer::new(&PEER, FQDN::TEST_DOMAIN, &network)?;
    domain_ns.referral_nameserver(&leaf_1_ns);
    domain_ns.add(leaf_1_ns.ds().ksk.clone());
    domain_ns.referral_nameserver(&leaf_2_ns);
    domain_ns.add(leaf_2_ns.ds().ksk.clone());
    let domain_ns = domain_ns.sign(settings.clone())?;

    let mut tld_ns = NameServer::new(&PEER, FQDN::TEST_TLD, &network)?;
    tld_ns.referral_nameserver(&domain_ns);
    tld_ns.add(domain_ns.ds().ksk.clone());
    let tld_ns = tld_ns.sign(settings.clone())?;

    let mut root_ns = NameServer::new(&PEER, FQDN::ROOT, &network)?;
    root_ns.referral_nameserver(&tld_ns);
    root_ns.add(tld_ns.ds().ksk.clone());
    let root_ns = root_ns.sign(settings.clone())?;
    let root = root_ns.root_hint();
    let trust_anchor = root_ns.trust_anchor();

    let nameservers = vec![
        leaf_1_ns.start()?,
        leaf_2_ns.start()?,
        domain_ns.start()?,
        tld_ns.start()?,
        root_ns.start()?,
    ];

    let resolver = Resolver::new(&network, root)
        .trust_anchor(&trust_anchor)
        .start()?;
    let client = Client::new(&network)?;

    Ok((network, nameservers, resolver, client))
}
