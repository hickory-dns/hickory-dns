use std::fs;

use dns_test::{
    FQDN, Implementation, Network, PEER, Resolver, Result,
    client::{Client, DigSettings, DigStatus},
    name_server::NameServer,
    record::RecordType,
};

#[test]
#[ignore = "hickory returns SERVFAIL due to the absence of an NS or SOA record"]
fn no_soa() -> Result<()> {
    let target_fqdn = FQDN::TEST_DOMAIN;
    let network = Network::new()?;

    let mut root_ns = NameServer::new(&PEER, FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(&Implementation::Dnslib, FQDN::TEST_TLD, &network)?;
    let script = fs::read_to_string("src/resolver/dns/scenarios/empty_response.py")?;
    leaf_ns.cp("/script.py", &script)?;

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
