use std::net::Ipv4Addr;

use dns_test::{
    Error, FQDN, Forwarder, Network, Resolver,
    client::{Client, DigSettings},
    name_server::{Graph, NameServer, Sign},
    record::{Record, RecordType},
    zone_file::{Nsec, SignSettings},
};

mod bogus;

/// Test DNSSEC-signed zone query WITHOUT DO bit set
///
/// When the DO (DNSSEC OK) bit is not set, the forwarder should strip DNSSEC records
/// from the response per RFC 4035 section 3.2.1
#[test]
fn noerror_without_dnssec_ok() -> Result<(), Error> {
    let network = Network::new()?;

    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let mut leaf_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_DOMAIN, &network)?;
    leaf_ns.add(Record::a(FQDN::EXAMPLE_SUBDOMAIN, expected_ipv4_addr));

    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::Yes {
            settings: SignSettings::default(),
        },
    )?;
    let trust_anchor = trust_anchor.unwrap();

    let resolver = Resolver::new(&network, root)
        .trust_anchor(&trust_anchor)
        .start_with_subject(&dns_test::PEER)?;
    let forwarder = Forwarder::new(&network, &resolver)
        .trust_anchor(&trust_anchor)
        .start()?;
    let client = Client::new(&network)?;

    // Query WITHOUT DO bit - DNSSEC records should be stripped
    let settings = *DigSettings::default().recurse();
    let output = client.dig(
        settings,
        forwarder.ipv4_addr(),
        RecordType::A,
        &FQDN::EXAMPLE_SUBDOMAIN,
    )?;

    assert!(output.status.is_noerror(), "{:?}", output.status);

    // There should only be the singular A record present, no RRSIG
    let [answer] = output.answer.try_into().unwrap();
    let a = answer.try_into_a().unwrap();

    assert_eq!(a.fqdn, FQDN::EXAMPLE_SUBDOMAIN);
    assert_eq!(a.ipv4_addr, expected_ipv4_addr);

    Ok(())
}

/// Test DNSSEC-signed zone query WITH DO bit set
///
/// When the DO (DNSSEC OK) bit is set, the forwarder should return DNSSEC records
/// in the response per RFC 4035 section 3.2.1
#[test]
fn noerror_with_dnssec_ok() -> Result<(), Error> {
    let network = Network::new()?;

    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let mut leaf_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_DOMAIN, &network)?;
    leaf_ns.add(Record::a(FQDN::EXAMPLE_SUBDOMAIN, expected_ipv4_addr));

    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::Yes {
            settings: SignSettings::default(),
        },
    )?;
    let trust_anchor = trust_anchor.unwrap();

    let resolver = Resolver::new(&network, root)
        .trust_anchor(&trust_anchor)
        .start_with_subject(&dns_test::PEER)?;
    let forwarder = Forwarder::new(&network, &resolver)
        .trust_anchor(&trust_anchor)
        .start()?;
    let client = Client::new(&network)?;

    // Query WITH DO bit - DNSSEC records should be included
    let settings = *DigSettings::default().recurse().dnssec();
    let output = client.dig(
        settings,
        forwarder.ipv4_addr(),
        RecordType::A,
        &FQDN::EXAMPLE_SUBDOMAIN,
    )?;

    assert!(output.status.is_noerror(), "{:?}", output.status);

    // Both the A record and RRSIG should be present
    let [a_record, rrsig_record] = output.answer.try_into().unwrap();
    let a = a_record.try_into_a().unwrap();

    assert_eq!(a.fqdn, FQDN::EXAMPLE_SUBDOMAIN);
    assert_eq!(a.ipv4_addr, expected_ipv4_addr);

    let _rrsig = rrsig_record.try_into_rrsig().unwrap();

    Ok(())
}

#[test]
fn nxdomain_nsec3() -> Result<(), Error> {
    let network = Network::new()?;

    let leaf_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_DOMAIN, &network)?;

    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::Yes {
            settings: SignSettings::default(),
        },
    )?;
    let trust_anchor = trust_anchor.unwrap();

    let resolver = Resolver::new(&network, root)
        .trust_anchor(&trust_anchor)
        .start_with_subject(&dns_test::PEER)?;
    let forwarder = Forwarder::new(&network, &resolver)
        .trust_anchor(&trust_anchor)
        .start()?;
    let client = Client::new(&network)?;

    let settings = *DigSettings::default().recurse();
    let output = client.dig(
        settings,
        forwarder.ipv4_addr(),
        RecordType::A,
        &FQDN::EXAMPLE_SUBDOMAIN,
    )?;

    assert!(output.status.is_nxdomain(), "{:?}", output.status);
    assert!(output.answer.is_empty(), "{:?}", output.answer);

    Ok(())
}

#[test]
fn nxdomain_nsec() -> Result<(), Error> {
    let network = Network::new()?;

    let leaf_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_DOMAIN, &network)?;

    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::Yes {
            settings: SignSettings::default().nsec(Nsec::_1),
        },
    )?;
    let trust_anchor = trust_anchor.unwrap();

    let resolver = Resolver::new(&network, root)
        .trust_anchor(&trust_anchor)
        .start_with_subject(&dns_test::PEER)?;
    let forwarder = Forwarder::new(&network, &resolver)
        .trust_anchor(&trust_anchor)
        .start()?;
    let client = Client::new(&network)?;

    let settings = *DigSettings::default().recurse();
    let output = client.dig(
        settings,
        forwarder.ipv4_addr(),
        RecordType::A,
        &FQDN::EXAMPLE_SUBDOMAIN,
    )?;

    assert!(output.status.is_nxdomain(), "{:?}", output.status);
    assert!(output.answer.is_empty(), "{:?}", output.answer);

    Ok(())
}
