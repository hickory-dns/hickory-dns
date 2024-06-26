use std::net::Ipv4Addr;

use dns_test::client::{Client, DigSettings};
use dns_test::name_server::NameServer;
use dns_test::record::RecordType;
use dns_test::{Network, Resolver, Result, TrustAnchor, FQDN};

use crate::resolver::dnssec::fixtures;

// no DS records are involved; this is a single-link chain of trust
#[test]
fn can_validate_without_delegation() -> Result<()> {
    let network = Network::new()?;
    let mut ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, &network)?;
    ns.add(ns.a());
    let ns = ns.sign()?;

    let root_ksk = ns.key_signing_key().clone();
    let root_zsk = ns.zone_signing_key().clone();

    eprintln!("root.zone.signed:\n{}", ns.signed_zone_file());

    let ns = ns.start()?;

    eprintln!("root.zone:\n{}", ns.zone_file());

    let trust_anchor = &TrustAnchor::from_iter([root_ksk.clone(), root_zsk.clone()]);
    let resolver = Resolver::new(&network, ns.root_hint())
        .trust_anchor(trust_anchor)
        .start(&dns_test::SUBJECT)?;
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

#[test]
fn can_validate_with_delegation() -> Result<()> {
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let needle_fqdn = FQDN("example.nameservers.com.")?;

    let (resolver, _nameservers, trust_anchor) =
        fixtures::minimally_secure(needle_fqdn.clone(), expected_ipv4_addr)?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;
    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver_addr, RecordType::A, &needle_fqdn)?;

    assert!(output.status.is_noerror());

    assert!(output.flags.authenticated_data);

    let [a] = output.answer.try_into().unwrap();
    let a = a.try_into_a().unwrap();

    assert_eq!(needle_fqdn, a.fqdn);
    assert_eq!(expected_ipv4_addr, a.ipv4_addr);

    let output = client.delv(resolver_addr, RecordType::A, &needle_fqdn, &trust_anchor)?;
    assert!(output.starts_with("; fully validated"));

    Ok(())
}

// TODO nxdomain with NSEC records
// TODO nxdomain with NSEC3 records
