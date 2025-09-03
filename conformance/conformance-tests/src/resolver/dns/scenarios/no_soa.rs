use dns_test::{
    Error, FQDN, Implementation, Network, PEER, Resolver,
    client::{Client, DigSettings, DigStatus},
    name_server::NameServer,
    record::RecordType,
};

#[test]
fn no_soa() -> Result<(), Error> {
    let target_fqdn = FQDN::TEST_DOMAIN;
    let network = Network::new()?;

    let mut root_ns = NameServer::new(&PEER, FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(
        &Implementation::test_server("empty_response", "both"),
        FQDN::TEST_TLD,
        &network,
    )?;

    root_ns.referral_nameserver(&leaf_ns);

    let root_hint = root_ns.root_hint();
    let resolver = Resolver::new(&network, root_hint).start()?;
    let client = Client::new(resolver.network())?;
    let dig_settings = *DigSettings::default().recurse();

    let _root_ns = root_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;

    let response = client.dig(
        dig_settings,
        resolver.ipv4_addr(),
        RecordType::A,
        &target_fqdn,
    )?;

    assert_eq!(response.status, DigStatus::NOERROR);
    assert!(response.answer.is_empty());

    Ok(())
}
