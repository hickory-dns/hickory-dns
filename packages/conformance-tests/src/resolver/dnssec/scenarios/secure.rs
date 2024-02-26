use std::net::Ipv4Addr;

use dns_test::client::{Client, DigSettings};
use dns_test::name_server::NameServer;
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

    let roots = &[Root::new(ns.fqdn().clone(), ns.ipv4_addr())];

    let trust_anchor = TrustAnchor::from_iter([root_ksk.clone(), root_zsk.clone()]);
    let resolver = Resolver::start(&dns_test::subject(), roots, &trust_anchor, &network)?;
    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver_addr, RecordType::SOA, &FQDN::ROOT)?;

    assert!(output.status.is_noerror());
    assert!(output.flags.authenticated_data);

    let output = client.delv(resolver_addr, RecordType::SOA, &FQDN::ROOT, &trust_anchor)?;
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
    let mut root_ns = NameServer::new(&peer, FQDN::ROOT, &network)?;
    let mut com_ns = NameServer::new(&peer, FQDN::COM, &network)?;

    let mut nameservers_ns = NameServer::new(&peer, FQDN("nameservers.com.")?, &network)?;
    nameservers_ns
        .add(Record::a(root_ns.fqdn().clone(), root_ns.ipv4_addr()))
        .add(Record::a(com_ns.fqdn().clone(), com_ns.ipv4_addr()))
        .add(Record::a(needle_fqdn.clone(), expected_ipv4_addr));
    let nameservers_ns = nameservers_ns.sign()?;
    let nameservers_ds = nameservers_ns.ds().clone();
    let nameservers_ns = nameservers_ns.start()?;

    eprintln!("nameservers.com.zone:\n{}", nameservers_ns.zone_file());

    com_ns
        .referral(
            nameservers_ns.zone().clone(),
            nameservers_ns.fqdn().clone(),
            nameservers_ns.ipv4_addr(),
        )
        .add(nameservers_ds);
    let com_ns = com_ns.sign()?;
    let com_ds = com_ns.ds().clone();
    let com_ns = com_ns.start()?;

    eprintln!("com.zone:\n{}", com_ns.zone_file());

    root_ns
        .referral(FQDN::COM, com_ns.fqdn().clone(), com_ns.ipv4_addr())
        .add(com_ds);
    let root_ns = root_ns.sign()?;
    let root_ksk = root_ns.key_signing_key().clone();
    let root_zsk = root_ns.zone_signing_key().clone();

    eprintln!("root.zone.signed:\n{}", root_ns.signed_zone_file());

    let root_ns = root_ns.start()?;

    eprintln!("root.zone:\n{}", root_ns.zone_file());

    let roots = &[Root::new(root_ns.fqdn().clone(), root_ns.ipv4_addr())];

    let trust_anchor = TrustAnchor::from_iter([root_ksk.clone(), root_zsk.clone()]);
    let resolver = Resolver::start(&dns_test::subject(), roots, &trust_anchor, &network)?;
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

    let output = client.delv(resolver_addr, RecordType::A, &needle_fqdn, &trust_anchor)?;
    assert!(output.starts_with("; fully validated"));

    Ok(())
}

// TODO nxdomain with NSEC records
// TODO nxdomain with NSEC3 records
