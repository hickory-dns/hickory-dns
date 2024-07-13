use std::net::Ipv4Addr;

use dns_test::{
    client::{Client, DigSettings},
    name_server::NameServer,
    record::RecordType,
    Network, Resolver, Result, FQDN,
};

use crate::resolver::dnssec::fixtures;

#[test]
fn copies_cd_bit_from_query_to_response() -> Result<()> {
    let network = &Network::new()?;
    let ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, network)?.start()?;
    let resolver = Resolver::new(network, ns.root_hint()).start()?;

    let client = Client::new(network)?;
    let settings = *DigSettings::default().checking_disabled().recurse();
    let ans = client.dig(settings, resolver.ipv4_addr(), RecordType::SOA, &FQDN::ROOT)?;

    assert!(ans.flags.checking_disabled);

    Ok(())
}

#[test]
fn if_cd_bit_is_set_then_respond_with_data_that_fails_authentication() -> Result<()> {
    let needle_fqdn = FQDN("example.nameservers.com.")?;
    let needle_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);

    let (resolver, _graph) =
        fixtures::bad_signature_in_leaf_nameserver(&needle_fqdn, needle_ipv4_addr)?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;

    let settings = *DigSettings::default()
        .recurse()
        .authentic_data()
        .checking_disabled();
    let output = client.dig(settings, resolver_addr, RecordType::A, &needle_fqdn)?;

    assert!(output.status.is_noerror());
    assert!(!output.flags.authenticated_data);

    let [record] = output.answer.try_into().unwrap();
    let record = record.try_into_a().unwrap();

    assert_eq!(needle_fqdn, record.fqdn);
    assert_eq!(needle_ipv4_addr, record.ipv4_addr);

    Ok(())
}

#[test]
fn if_cd_bit_is_clear_and_data_is_not_authentic_then_respond_with_servfail() -> Result<()> {
    let needle_fqdn = FQDN("example.nameservers.com.")?;
    let needle_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);

    let (resolver, _graph) =
        fixtures::bad_signature_in_leaf_nameserver(&needle_fqdn, needle_ipv4_addr)?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;

    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver_addr, RecordType::A, &needle_fqdn)?;

    assert!(output.status.is_servfail());

    Ok(())
}
