use dns_test::{
    Error, FQDN, Implementation, Network, PEER, Resolver,
    client::{Client, DigSettings, DigStatus},
    name_server::NameServer,
    record::RecordType,
    zone_file::SignSettings,
};

#[test]
#[ignore = "hickory fails to correctly find a zone cut in the face of a lame delegation with no NS apex RRset"]
fn no_soa_insecure() -> Result<(), Error> {
    let target_fqdn = FQDN::TEST_DOMAIN;
    let network = Network::new()?;

    let mut root_ns = NameServer::new(&PEER, FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(
        &Implementation::test_server("empty_response", "both"),
        FQDN::TEST_TLD,
        &network,
    )?;

    root_ns.referral_nameserver(&leaf_ns);

    let root_ns = root_ns.sign(SignSettings::default())?;

    let root_hint = root_ns.root_hint();
    let resolver = Resolver::new(&network, root_hint)
        .trust_anchor(&root_ns.trust_anchor())
        .start()?;
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
