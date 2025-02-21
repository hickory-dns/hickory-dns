//! NSEC and NSEC3 denial of existence tests

use std::net::Ipv4Addr;

use dns_test::{
    FQDN, Network, Resolver, Result,
    client::{Client, DigSettings},
    name_server::{Graph, NameServer, Sign},
    record::{Record, RecordType},
    zone_file::{Nsec, SignSettings},
};

#[test]
fn zone_exist_domain_does_not_nsec3() -> Result<()> {
    zone_exist_domain_does_not(Nsec::_3 {
        opt_out: false,
        salt: None,
    })
}

#[test]
fn zone_exist_domain_does_not_nsec() -> Result<()> {
    zone_exist_domain_does_not(Nsec::_1)
}

#[test]
fn zone_does_not_exist_nsec3() -> Result<()> {
    zone_does_not_exist(Nsec::_3 {
        opt_out: false,
        salt: None,
    })
}

#[test]
fn zone_does_not_exist_nsec() -> Result<()> {
    zone_does_not_exist(Nsec::_1)
}

#[test]
fn domain_exists_record_type_does_not_nsec3() -> Result<()> {
    domain_exists_record_type_does_not(Nsec::_3 {
        opt_out: false,
        salt: None,
    })
}

#[test]
fn domain_exists_record_type_does_not_nsec() -> Result<()> {
    domain_exists_record_type_does_not(Nsec::_1)
}

fn zone_exist_domain_does_not(nsec: Nsec) -> Result<()> {
    let leaf_zone = FQDN::TEST_TLD.push_label("exists");
    let needle_fqdn = leaf_zone.push_label("unicorn");

    let network = Network::new()?;
    let leaf_ns = NameServer::new(&dns_test::PEER, leaf_zone.clone(), &network)?;

    let mut settings = SignSettings::default();
    settings = settings.nsec(nsec);
    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(leaf_ns, Sign::Yes { settings })?;

    let trust_anchor = trust_anchor.unwrap();
    let resolver = Resolver::new(&network, root)
        .trust_anchor(&trust_anchor)
        .start()?;

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &needle_fqdn)?;

    dbg!(&output);

    assert!(output.status.is_nxdomain());
    assert!(output.flags.authenticated_data);

    let [record] = output.authority.try_into().unwrap();
    let soa = record.try_into_soa().unwrap();

    assert_eq!(leaf_zone, soa.zone);

    Ok(())
}

fn zone_does_not_exist(nsec: Nsec) -> Result<()> {
    let parent_zone = FQDN::TEST_DOMAIN;
    let leaf_zone = parent_zone.push_label("does-not-exist");
    let needle_fqdn = leaf_zone.push_label("unicorn");

    let network = Network::new()?;
    let parent_ns = NameServer::new(&dns_test::PEER, parent_zone, &network)?;

    let mut settings = SignSettings::default();
    settings = settings.nsec(nsec);
    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(parent_ns, Sign::Yes { settings })?;

    let trust_anchor = trust_anchor.unwrap();
    let resolver = Resolver::new(&network, root)
        .trust_anchor(&trust_anchor)
        .start()?;

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &needle_fqdn)?;

    dbg!(&output);

    assert!(output.status.is_nxdomain());
    assert!(output.flags.authenticated_data);

    let [record] = output.authority.try_into().unwrap();
    let soa = record.try_into_soa().unwrap();

    assert_eq!(FQDN::TEST_DOMAIN, soa.zone);

    Ok(())
}

fn domain_exists_record_type_does_not(nsec: Nsec) -> Result<()> {
    let leaf_zone = FQDN::TEST_TLD.push_label("exists");
    let needle_fqdn = leaf_zone.push_label("example");

    let network = Network::new()?;
    let mut leaf_ns = NameServer::new(&dns_test::PEER, leaf_zone.clone(), &network)?;
    leaf_ns.add(Record::a(needle_fqdn.clone(), Ipv4Addr::new(1, 2, 3, 4)));

    let mut settings = SignSettings::default();
    settings = settings.nsec(nsec);
    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(leaf_ns, Sign::Yes { settings })?;

    let trust_anchor = trust_anchor.unwrap();
    let resolver = Resolver::new(&network, root)
        .trust_anchor(&trust_anchor)
        .start()?;

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(
        settings,
        resolver.ipv4_addr(),
        RecordType::AAAA,
        &needle_fqdn,
    )?;

    dbg!(&output);

    assert!(output.status.is_noerror());
    assert!(output.flags.authenticated_data);

    let [record] = output.authority.try_into().unwrap();
    let soa = record.try_into_soa().unwrap();

    assert_eq!(leaf_zone, soa.zone);

    Ok(())
}
