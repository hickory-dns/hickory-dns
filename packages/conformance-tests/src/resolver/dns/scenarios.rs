use std::net::Ipv4Addr;

use dns_test::client::{Client, Dnssec, Recurse};
use dns_test::name_server::NameServer;
use dns_test::record::RecordType;
use dns_test::zone_file::Root;
use dns_test::{RecursiveResolver, Result, TrustAnchor, FQDN};

#[test]
fn can_resolve() -> Result<()> {
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let needle_fqdn = FQDN("example.nameservers.com.")?;

    let mut root_ns = NameServer::new(FQDN::ROOT)?;
    let mut com_ns = NameServer::new(FQDN::COM)?;

    let mut nameservers_ns = NameServer::new(FQDN("nameservers.com.")?)?;
    nameservers_ns
        .a(root_ns.fqdn().clone(), root_ns.ipv4_addr())
        .a(com_ns.fqdn().clone(), com_ns.ipv4_addr())
        .a(needle_fqdn.clone(), expected_ipv4_addr);
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
    let resolver = RecursiveResolver::start(dns_test::subject(), roots, &TrustAnchor::empty())?;
    let resolver_ip_addr = resolver.ipv4_addr();

    let client = Client::new()?;
    let output = client.dig(
        Recurse::Yes,
        Dnssec::No,
        resolver_ip_addr,
        RecordType::A,
        &needle_fqdn,
    )?;

    assert!(output.status.is_noerror());

    let [answer] = output.answer.try_into().unwrap();
    let a = answer.try_into_a().unwrap();

    assert_eq!(needle_fqdn, a.fqdn);
    assert_eq!(expected_ipv4_addr, a.ipv4_addr);

    Ok(())
}
