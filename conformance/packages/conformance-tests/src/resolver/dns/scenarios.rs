use std::net::Ipv4Addr;

use dns_test::client::{Client, DigSettings};
use dns_test::name_server::{Graph, NameServer, Sign};
use dns_test::record::{Record, RecordType};
use dns_test::{Network, Resolver, Result, FQDN};

#[test]
fn can_resolve() -> Result<()> {
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let needle_fqdn = FQDN("example.nameservers.com.")?;

    let network = Network::new()?;

    let mut leaf_ns = NameServer::new(&dns_test::PEER, FQDN::NAMESERVERS, &network)?;
    leaf_ns.add(Record::a(needle_fqdn.clone(), expected_ipv4_addr));

    let Graph {
        nameservers: _nameservers,
        root,
        ..
    } = Graph::build(leaf_ns, Sign::No)?;

    let resolver = Resolver::new(&network, root).start()?;
    let resolver_ip_addr = resolver.ipv4_addr();

    let client = Client::new(&network)?;

    let settings = *DigSettings::default().recurse();
    let output = client.dig(settings, resolver_ip_addr, RecordType::A, &needle_fqdn)?;

    assert!(output.status.is_noerror());

    let [answer] = output.answer.try_into().unwrap();
    let a = answer.try_into_a().unwrap();

    assert_eq!(needle_fqdn, a.fqdn);
    assert_eq!(expected_ipv4_addr, a.ipv4_addr);

    Ok(())
}

#[ignore]
#[test]
fn nxdomain() -> Result<()> {
    let needle_fqdn = FQDN("unicorn.nameservers.com.")?;

    let network = Network::new()?;

    let leaf_ns = NameServer::new(&dns_test::PEER, FQDN::NAMESERVERS, &network)?;

    let Graph {
        nameservers: _nameservers,
        root,
        ..
    } = Graph::build(leaf_ns, Sign::No)?;

    let resolver = Resolver::new(&network, root).start()?;
    let resolver_ip_addr = resolver.ipv4_addr();

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse();
    let output = client.dig(settings, resolver_ip_addr, RecordType::A, &needle_fqdn)?;

    assert!(dbg!(output).status.is_nxdomain());

    Ok(())
}
