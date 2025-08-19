use std::net::Ipv4Addr;

use dns_test::{
    Error, FQDN, Forwarder, Network, Resolver,
    client::{Client, DigSettings},
    name_server::{Graph, NameServer, Sign},
    record::{Record, RecordType},
};

#[test]
fn noerror() -> Result<(), Error> {
    let network = Network::new()?;

    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let mut leaf_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_DOMAIN, &network)?;
    leaf_ns.add(Record::a(FQDN::EXAMPLE_SUBDOMAIN, expected_ipv4_addr));

    let Graph {
        nameservers: _nameservers,
        root,
        ..
    } = Graph::build(leaf_ns, Sign::No)?;

    let resolver = Resolver::new(&network, root).start_with_subject(&dns_test::PEER)?;
    let forwarder = Forwarder::new(&network, &resolver).start()?;
    let client = Client::new(&network)?;

    let settings = *DigSettings::default().recurse();
    let output = client.dig(
        settings,
        forwarder.ipv4_addr(),
        RecordType::A,
        &FQDN::EXAMPLE_SUBDOMAIN,
    )?;

    assert!(output.status.is_noerror(), "{:?}", output.status);

    let [answer] = output.answer.try_into().unwrap();
    let a = answer.try_into_a().unwrap();

    assert_eq!(a.fqdn, FQDN::EXAMPLE_SUBDOMAIN);
    assert_eq!(a.ipv4_addr, expected_ipv4_addr);

    Ok(())
}

#[test]
fn nxdomain() -> Result<(), Error> {
    let network = Network::new()?;

    let leaf_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_DOMAIN, &network)?;

    let Graph {
        nameservers: _nameservers,
        root,
        ..
    } = Graph::build(leaf_ns, Sign::No)?;

    let resolver = Resolver::new(&network, root).start_with_subject(&dns_test::PEER)?;
    let forwarder = Forwarder::new(&network, &resolver).start()?;
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
