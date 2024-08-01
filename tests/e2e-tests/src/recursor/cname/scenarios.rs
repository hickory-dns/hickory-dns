use std::net::Ipv4Addr;

use dns_test::{
    client::{Client, DigSettings},
    name_server::{Graph, NameServer, Sign},
    record::{Record, RecordType},
    zone_file::SignSettings,
    Implementation, Network, Resolver, Result, FQDN,
};

/// Basic CNAME tests
#[test]
fn basic_cname_tests() -> Result<()> {
    let cname_fqdn = FQDN("www.example.com.")?;
    let cname_target = FQDN("www2.example.com.")?;

    let target_a_fqdn = FQDN("www2.example.com.")?;
    let target_a_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);

    let network = Network::new()?;

    let mut leaf_ns = NameServer::new(&Implementation::test_peer(), FQDN::NAMESERVERS, &network)?;
    leaf_ns.add(Record::cname(cname_fqdn.clone(), cname_target.clone()));
    leaf_ns.add(Record::a(target_a_fqdn.clone(), target_a_ipv4_addr.clone()));

    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::No
    )?;

    let resolver = Resolver::new(&network, root)
        .start_with_subject(&Implementation::hickory())?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;

    // bug: this triggers infinite recursion
    let a_settings = *DigSettings::default().recurse().authentic_data();
    let res = client.dig(a_settings, resolver_addr, RecordType::A, &cname_fqdn);

    // we are not interested in the actual answer; just that the server does not crash
    println!("Got answer: {res:?}");
    assert!(res.is_ok(), "server did not answer query");

    let res = resolver.terminate();

    assert!(res.is_ok(), "server process not found");

    let logs = res.unwrap();
    assert!(!logs.contains("stack overflow"));

    Ok(())
}
