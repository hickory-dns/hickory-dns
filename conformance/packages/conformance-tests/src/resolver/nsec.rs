//! NSEC and NSEC3 denial of existence tests

use std::net::Ipv4Addr;

use dns_test::{
    Error, FQDN, Network, PEER, Resolver,
    client::{Client, DigSettings, DigStatus},
    name_server::{Graph, NameServer, Sign},
    record::{A, Record, RecordType},
    zone_file::{Nsec, SignSettings},
};

#[test]
fn zone_exist_domain_does_not_nsec3() -> Result<(), Error> {
    zone_exist_domain_does_not(Nsec::_3 {
        iterations: 0,
        opt_out: false,
        salt: None,
    })
}

#[test]
fn zone_exist_domain_does_not_nsec() -> Result<(), Error> {
    zone_exist_domain_does_not(Nsec::_1)
}

#[test]
fn zone_does_not_exist_nsec3() -> Result<(), Error> {
    zone_does_not_exist(Nsec::_3 {
        iterations: 0,
        opt_out: false,
        salt: None,
    })
}

#[test]
fn zone_does_not_exist_nsec() -> Result<(), Error> {
    zone_does_not_exist(Nsec::_1)
}

#[test]
fn domain_exists_record_type_does_not_nsec3() -> Result<(), Error> {
    domain_exists_record_type_does_not(Nsec::_3 {
        iterations: 0,
        opt_out: false,
        salt: None,
    })
}

#[test]
fn domain_exists_record_type_does_not_nsec() -> Result<(), Error> {
    domain_exists_record_type_does_not(Nsec::_1)
}

#[test]
fn wildcard_exists_record_type_does_not_nsec_middle_chain() -> Result<(), Error> {
    wildcard_exists_record_type_does_not(Nsec::_1, "aaaaaa")
}

#[test]
fn wildcard_exists_record_type_does_not_nsec_end_chain() -> Result<(), Error> {
    wildcard_exists_record_type_does_not(Nsec::_1, "zzzzzz")
}

#[test]
fn wildcard_exists_record_type_does_not_nsec3() -> Result<(), Error> {
    wildcard_exists_record_type_does_not(
        Nsec::_3 {
            iterations: 0,
            opt_out: false,
            salt: None,
        },
        "query",
    )
}

fn zone_exist_domain_does_not(nsec: Nsec) -> Result<(), Error> {
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

fn zone_does_not_exist(nsec: Nsec) -> Result<(), Error> {
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

fn domain_exists_record_type_does_not(nsec: Nsec) -> Result<(), Error> {
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

fn wildcard_exists_record_type_does_not(nsec: Nsec, label: &str) -> Result<(), Error> {
    let network = Network::new()?;

    let record_name = FQDN::TEST_DOMAIN.push_label("record");
    let wildcard_name = FQDN::TEST_DOMAIN.push_label("*");
    let query_name = FQDN::TEST_DOMAIN.push_label(label);

    let mut leaf_ns = NameServer::new(&PEER, FQDN::TEST_DOMAIN, &network)?;
    leaf_ns.add(Record::A(A {
        fqdn: record_name,
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(10, 0, 0, 1),
    }));
    leaf_ns.add(Record::A(A {
        fqdn: wildcard_name,
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(10, 0, 0, 2),
    }));

    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::Yes {
            settings: SignSettings::default().nsec(nsec),
        },
    )?;
    let trust_anchor = trust_anchor.unwrap();

    let resolver = Resolver::new(&network, root)
        .trust_anchor(&trust_anchor)
        .start()?;
    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().authentic_data();

    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::TXT, &query_name)?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert!(output.answer.is_empty(), "{:?}", output.answer);

    Ok(())
}
