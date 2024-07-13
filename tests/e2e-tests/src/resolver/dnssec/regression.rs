use std::net::Ipv4Addr;

use dns_test::{
    client::{Client, DigSettings},
    name_server::{Graph, NameServer, Sign},
    record::{Record, RecordType},
    zone_file::SignSettings,
    Implementation, Network, Resolver, Result, FQDN,
};

/// regression test for https://github.com/hickory-dns/hickory-dns/issues/2252
#[test]
fn infinite_recursion_with_deprecated_algorithm() -> Result<()> {
    let needle_fqdn = FQDN("example.nameservers.com.")?;
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let network = Network::new()?;

    let mut leaf_ns = NameServer::new(&Implementation::test_peer(), FQDN::NAMESERVERS, &network)?;
    leaf_ns.add(Record::a(needle_fqdn.clone(), expected_ipv4_addr));

    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::Yes {
            settings: SignSettings::rsasha1_nsec3(),
        },
    )?;

    let trust_anchor = trust_anchor.unwrap();
    let resolver = Resolver::new(&network, root)
        .trust_anchor(&trust_anchor)
        .start_with_subject(&Implementation::hickory())?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;

    // pre-condition: `DS .` must return an empty answer section
    let ds_settings = *DigSettings::default().recurse();
    let output = client.dig(ds_settings, resolver_addr, RecordType::DS, &FQDN::ROOT)?;

    assert!(output.answer.is_empty());

    // bug: this triggers infinite recursion
    let a_settings = *DigSettings::default().recurse().authentic_data();
    let res = client.dig(a_settings, resolver_addr, RecordType::A, &needle_fqdn);

    // we are not interested in the actual answer; just that the server does not crash
    assert!(res.is_ok(), "server did not answer query");

    let res = resolver.terminate();

    assert!(res.is_ok(), "server process not found");

    let logs = res.unwrap();
    assert!(!logs.contains("stack overflow"));

    Ok(())
}
