//! Test how resolvers respond to packet loss.

use std::{fs, net::Ipv4Addr};

use dns_test::{
    FQDN, Implementation, Network, Resolver, Result,
    client::{Client, DigSettings, DigStatus},
    name_server::NameServer,
    record::RecordType,
};

#[test]
#[ignore = "hickory-recursor does not have a retransmission policy"]
fn packet_loss_udp() -> Result<()> {
    let target_fqdn = FQDN("example.testing.")?;
    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(&Implementation::Dnslib, FQDN::TEST_TLD, &network)?;
    let script = fs::read_to_string("src/resolver/dns/scenarios/packet_loss.py")?;
    leaf_ns.cp("/script.py", &script)?;

    root_ns.referral_nameserver(&leaf_ns);

    let root_hint = root_ns.root_hint();
    let resolver = Resolver::new(&network, root_hint).start()?;
    let client = Client::new(resolver.network())?;
    let dig_settings = *DigSettings::default().recurse().timeout(10);

    let _root_ns = root_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;

    let result = client.dig(
        dig_settings,
        resolver.ipv4_addr(),
        RecordType::A,
        &target_fqdn,
    );
    let response = result
        .unwrap_or_else(|e| panic!("error {e:?} resolver logs: {}", resolver.logs().unwrap()));

    assert_eq!(response.status, DigStatus::NOERROR);
    assert_eq!(response.answer.len(), 1, "{:?}", response.answer);
    assert_eq!(
        response.answer[0].clone().try_into_a().unwrap().ipv4_addr,
        Ipv4Addr::new(192, 0, 2, 1)
    );

    Ok(())
}
