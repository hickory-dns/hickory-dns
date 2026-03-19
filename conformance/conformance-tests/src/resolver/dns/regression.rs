use dns_test::{
    Error, FQDN, Network, PEER, Resolver, SUBJECT,
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

/// NS hostname resolution producing only NXDOMAIN should return SERVFAIL
///
/// This test reproduces issue https://github.com/hickory-dns/hickory-dns/issues/3503:
/// a zone with only out-of-bailiwick NS hostnames that all produce NXDOMAIN.
/// In this case the resolver should return SERVFAIL (not NXDOMAIN).
///
/// An NXDOMAIN for the NS hostname does not prove that the queried domain
/// doesn't exist, it only means the resolver cannot reach the authoritative
/// server.
#[test]
fn unresolvable_ns_returns_servfail() -> Result<(), Error> {
    let network = Network::new()?;

    // Delegate to an out-of-bailiwick NS in a TLD that doesn't exist at the root.
    // No glue is provided, forcing the resolver to look up the NS hostname.
    let mut tld_ns = NameServer::new(&PEER, FQDN::TEST_TLD, &network)?;
    tld_ns.add(Record::ns(
        FQDN("example.testing.")?,
        FQDN("ns.nonexistent.")?,
    ));

    // Root only knows about `testing.` so queries for `nonexistent.` will return NXDOMAIN.
    let mut root_ns = NameServer::new(&PEER, FQDN::ROOT, &network)?;
    root_ns.referral(
        FQDN::TEST_TLD,
        FQDN("primary.tld-server.testing.")?,
        tld_ns.ipv4_addr(),
    );

    let resolver = Resolver::new(&network, root_ns.root_hint()).start_with_subject(&SUBJECT)?;

    let _root_ns = root_ns.start()?;
    let _tld_ns = tld_ns.start()?;

    let res = Client::new(resolver.network())?.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN("www.example.testing.")?,
    )?;

    assert_eq!(res.answer.len(), 0);
    assert!(
        res.status.is_servfail(),
        "expected SERVFAIL, got {:?};",
        res.status
    );

    Ok(())
}
