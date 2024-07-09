use dns_test::{
    client::{Client, DigSettings},
    name_server::{Graph, NameServer, Sign},
    record::{Record, RecordType},
    zone_file::SignSettings,
    Network, Resolver, Result, FQDN,
};

/// regression test for https://github.com/hickory-dns/hickory-dns/issues/2299
#[test]
fn includes_rrsig_record_in_ns_query() -> Result<()> {
    let network = Network::new()?;
    let leaf_ns = NameServer::new(&dns_test::PEER, FQDN::NAMESERVERS, &network)?;

    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor: _trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::Yes {
            settings: SignSettings::default(),
        },
    )?;

    // NOTE this is a security-aware, *non*-validating resolver
    let resolver = Resolver::new(&network, root).start()?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;

    let output = client.dig(
        *DigSettings::default().dnssec().recurse(),
        resolver_addr,
        RecordType::NS,
        &FQDN::NAMESERVERS,
    )?;

    assert!(output.status.is_noerror());

    // bug: this answer was missing the `rrsig` record
    let [ns, rrsig] = output.answer.try_into().unwrap();

    // check that we got the expected record types
    assert!(matches!(ns, Record::NS(_)));
    let rrsig = rrsig.try_into_rrsig().unwrap();
    assert_eq!(RecordType::NS, rrsig.type_covered);

    Ok(())
}

/// This is a regression test for https://github.com/hickory-dns/hickory-dns/issues/2285
#[test]
fn can_validate_ns_query() -> Result<()> {
    let network = Network::new()?;
    let leaf_ns = NameServer::new(&dns_test::PEER, FQDN::NAMESERVERS, &network)?;

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

    // NOTE this is a security-aware, *validating* resolver
    let resolver = Resolver::new(&network, root)
        .trust_anchor(&trust_anchor.unwrap())
        .start()?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;

    let output = client.dig(
        *DigSettings::default().authentic_data().recurse(),
        resolver_addr,
        RecordType::NS,
        &FQDN::NAMESERVERS,
    )?;

    // bug: this returned SERVFAIL instead of NOERROR with AD=1
    assert!(output.status.is_noerror());
    assert!(output.flags.authenticated_data);

    // check that the record type is what we expect
    let [ns] = output.answer.try_into().unwrap();
    assert!(matches!(ns, Record::NS(_)));

    Ok(())
}
