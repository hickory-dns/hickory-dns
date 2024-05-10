use dns_test::{
    client::{Client, DigSettings},
    name_server::NameServer,
    record::RecordType,
    zone_file::Root,
    Network, Resolver, Result, FQDN,
};

#[test]
fn copies_cd_bit_from_query_to_response() -> Result<()> {
    let network = &Network::new()?;
    let ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, network)?.start()?;
    let resolver = Resolver::new(network, Root::new(ns.fqdn().clone(), ns.ipv4_addr()))
        .start(&dns_test::SUBJECT)?;

    let client = Client::new(network)?;
    let settings = *DigSettings::default().checking_disabled().recurse();
    let ans = client.dig(settings, resolver.ipv4_addr(), RecordType::SOA, &FQDN::ROOT)?;

    assert!(ans.flags.checking_disabled);

    Ok(())
}
