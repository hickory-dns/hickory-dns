use dns_test::{
    Error, FQDN, Network, PEER, Resolver,
    client::{Client, DigSettings},
    name_server::{Graph, NameServer, Sign},
    record::{Record, RecordType},
};

/// Regression test for https://github.com/hickory-dns/hickory-dns/issues/3125
#[test]
fn ns_query() -> Result<(), Error> {
    let network = Network::new()?;
    let leaf_ns = NameServer::new(&PEER, FQDN::TEST_DOMAIN, &network)?;
    let Graph {
        nameservers: _nameservers,
        root,
        ..
    } = Graph::build(leaf_ns, Sign::No)?;

    let resolver = Resolver::new(&network, root).start()?;
    let client = Client::new(&network)?;

    let output = client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::NS,
        &FQDN::TEST_TLD,
    )?;

    assert!(output.status.is_noerror());
    assert_eq!(output.answer.len(), 1, "{:?}", output.answer);
    assert!(
        matches!(output.answer[0], Record::NS(_)),
        "{:?}",
        output.answer[0]
    );

    Ok(())
}
