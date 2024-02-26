use std::net::Ipv4Addr;

use dns_test::client::{Client, DigSettings};
use dns_test::name_server::NameServer;
use dns_test::record::{Record, RecordType};
use dns_test::zone_file::Root;
use dns_test::{Network, Resolver, Result, TrustAnchor, FQDN};

#[test]
fn can_resolve() -> Result<()> {
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let needle_fqdn = FQDN("example.nameservers.com.")?;

    let network = Network::new()?;
    let peer = dns_test::peer();
    let mut root_ns = NameServer::new(&peer, FQDN::ROOT, &network)?;
    let mut com_ns = NameServer::new(&peer, FQDN::COM, &network)?;

    let mut nameservers_ns = NameServer::new(&peer, FQDN("nameservers.com.")?, &network)?;
    nameservers_ns
        .add(Record::a(root_ns.fqdn().clone(), root_ns.ipv4_addr()))
        .add(Record::a(com_ns.fqdn().clone(), com_ns.ipv4_addr()))
        .add(Record::a(needle_fqdn.clone(), expected_ipv4_addr));
    let nameservers_ns = nameservers_ns.start()?;

    eprintln!("nameservers.com.zone:\n{}", nameservers_ns.zone_file());

    com_ns.referral(
        nameservers_ns.zone().clone(),
        nameservers_ns.fqdn().clone(),
        nameservers_ns.ipv4_addr(),
    );
    let com_ns = com_ns.start()?;

    eprintln!("com.zone:\n{}", com_ns.zone_file());

    root_ns.referral(FQDN::COM, com_ns.fqdn().clone(), com_ns.ipv4_addr());
    let root_ns = root_ns.start()?;

    eprintln!("root.zone:\n{}", root_ns.zone_file());

    let roots = &[Root::new(root_ns.fqdn().clone(), root_ns.ipv4_addr())];
    let resolver = Resolver::start(&dns_test::subject(), roots, &TrustAnchor::empty(), &network)?;
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
    let peer = dns_test::peer();
    let mut root_ns = NameServer::new(&peer, FQDN::ROOT, &network)?;
    let mut com_ns = NameServer::new(&peer, FQDN::COM, &network)?;

    let mut nameservers_ns = NameServer::new(&peer, FQDN("nameservers.com.")?, &network)?;
    nameservers_ns
        .add(Record::a(root_ns.fqdn().clone(), root_ns.ipv4_addr()))
        .add(Record::a(com_ns.fqdn().clone(), com_ns.ipv4_addr()));
    let nameservers_ns = nameservers_ns.start()?;

    com_ns.referral(
        nameservers_ns.zone().clone(),
        nameservers_ns.fqdn().clone(),
        nameservers_ns.ipv4_addr(),
    );
    let com_ns = com_ns.start()?;

    root_ns.referral(FQDN::COM, com_ns.fqdn().clone(), com_ns.ipv4_addr());
    let root_ns = root_ns.start()?;

    let roots = &[Root::new(root_ns.fqdn().clone(), root_ns.ipv4_addr())];
    let resolver = Resolver::start(&dns_test::subject(), roots, &TrustAnchor::empty(), &network)?;
    let resolver_ip_addr = resolver.ipv4_addr();

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse();
    let output = client.dig(settings, resolver_ip_addr, RecordType::A, &needle_fqdn)?;

    assert!(dbg!(output).status.is_nxdomain());

    Ok(())
}
