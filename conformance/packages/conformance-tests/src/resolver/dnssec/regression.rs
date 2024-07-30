use dns_test::{
    client::{Client, DigSettings},
    name_server::{Graph, NameServer, Sign},
    record::{Record, RecordType},
    tshark::{Capture, Direction},
    zone_file::SignSettings,
    Implementation, Network, Resolver, Result, FQDN,
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

/// regression test for https://github.com/hickory-dns/hickory-dns/issues/2306
#[test]
fn single_node_dns_graph_with_bind_as_peer() -> Result<()> {
    let network = Network::new()?;
    let peer = Implementation::Bind;
    let nameserver = NameServer::new(&peer, FQDN::ROOT, &network)?
        .sign(SignSettings::default())?
        .start()?;

    let client = Client::new(&network)?;

    let nameserver_addr = nameserver.ipv4_addr();
    let ans = client.dig(
        DigSettings::default(),
        nameserver_addr,
        RecordType::NS,
        &FQDN::ROOT,
    )?;

    // sanity check
    assert!(ans.status.is_noerror());
    let [ns] = ans.answer.try_into().unwrap();
    assert!(matches!(ns, Record::NS(_)));

    // pre-condition: BIND does NOT include a glue record (A record) in the additional section
    assert!(ans.additional.is_empty());

    let resolver = Resolver::new(&network, nameserver.root_hint()).start()?;

    let mut tshark = resolver.eavesdrop()?;

    let ans = client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::SOA,
        &FQDN::ROOT,
    )?;

    tshark.wait_for_capture()?;
    let captures = tshark.terminate()?;

    dbg!(captures.len());

    assert!(ans.status.is_noerror());

    let [soa] = ans.answer.try_into().unwrap();
    assert!(matches!(soa, Record::SOA(_)));

    // bug: hickory-dns goes into an infinite loop until it exhausts its network resources
    assert!(captures.len() < 20);

    for Capture { message, direction } in captures {
        if let Direction::Outgoing { destination } = direction {
            if destination == nameserver_addr {
                eprintln!("{message:#?}\n");
            }
        }
    }

    Ok(())
}
