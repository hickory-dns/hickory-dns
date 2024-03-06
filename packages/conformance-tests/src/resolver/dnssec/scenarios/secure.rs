use std::net::Ipv4Addr;

use dns_test::client::{Client, DigSettings};
use dns_test::name_server::{Graph, NameServer, Sign};
use dns_test::record::{Record, RecordType};
use dns_test::zone_file::Root;
use dns_test::{Network, Resolver, Result, TrustAnchor, FQDN};

// no DS records are involved; this is a single-link chain of trust
#[ignore]
#[test]
fn can_validate_without_delegation() -> Result<()> {
    let network = Network::new()?;
    let mut ns = NameServer::new(&dns_test::peer(), FQDN::ROOT, &network)?;
    ns.add(Record::a(ns.fqdn().clone(), ns.ipv4_addr()));
    let ns = ns.sign()?;

    let root_ksk = ns.key_signing_key().clone();
    let root_zsk = ns.zone_signing_key().clone();

    eprintln!("root.zone.signed:\n{}", ns.signed_zone_file());

    let ns = ns.start()?;

    eprintln!("root.zone:\n{}", ns.zone_file());

    let trust_anchor = &TrustAnchor::from_iter([root_ksk.clone(), root_zsk.clone()]);
    let resolver = Resolver::new(&network, Root::new(ns.fqdn().clone(), ns.ipv4_addr()))
        .trust_anchor(trust_anchor)
        .start(&dns_test::subject())?;
    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver_addr, RecordType::SOA, &FQDN::ROOT)?;

    assert!(output.status.is_noerror());
    assert!(output.flags.authenticated_data);

    let output = client.delv(resolver_addr, RecordType::SOA, &FQDN::ROOT, trust_anchor)?;
    assert!(output.starts_with("; fully validated"));

    Ok(())
}

#[ignore]
#[test]
fn can_validate_with_delegation() -> Result<()> {
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let needle_fqdn = FQDN("example.nameservers.com.")?;

    let peer = dns_test::peer();
    let network = Network::new()?;

    let mut leaf_ns = NameServer::new(&peer, FQDN::NAMESERVERS, &network)?;
    leaf_ns.add(Record::a(needle_fqdn.clone(), expected_ipv4_addr));

    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(leaf_ns, Sign::Yes)?;

    let trust_anchor = &trust_anchor.unwrap();
    let resolver = Resolver::new(&network, root)
        .trust_anchor(trust_anchor)
        .start(&dns_test::subject())?;
    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver_addr, RecordType::A, &needle_fqdn)?;

    assert!(output.status.is_noerror());

    assert!(output.flags.authenticated_data);

    let [a] = output.answer.try_into().unwrap();
    let a = a.try_into_a().unwrap();

    assert_eq!(needle_fqdn, a.fqdn);
    assert_eq!(expected_ipv4_addr, a.ipv4_addr);

    let output = client.delv(resolver_addr, RecordType::A, &needle_fqdn, trust_anchor)?;
    assert!(output.starts_with("; fully validated"));

    Ok(())
}

// TODO nxdomain with NSEC records
// TODO nxdomain with NSEC3 records
