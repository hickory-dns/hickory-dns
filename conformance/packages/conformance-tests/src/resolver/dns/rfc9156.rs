use std::net::Ipv4Addr;

use dns_test::{
    FQDN, Network, PEER, Resolver, Result,
    client::{Client, DigSettings, DigStatus},
    name_server::NameServer,
    record::{CNAME, Record, RecordType},
};

#[test]
fn cname_between_zone_cuts() -> Result<()> {
    let network = Network::new()?;
    let leaf_zone = FQDN::TEST_TLD.push_label("a").push_label("b");
    let needle_fqdn = leaf_zone.push_label("www");

    let mut root_ns = NameServer::new(&PEER, FQDN::ROOT, &network)?;
    let mut tld_ns = NameServer::new(&PEER, FQDN::TEST_TLD, &network)?;
    let mut leaf_ns = NameServer::new(&PEER, leaf_zone, &network)?;

    leaf_ns.add(Record::a(needle_fqdn.clone(), Ipv4Addr::new(1, 2, 3, 4)));

    tld_ns.referral_nameserver(&leaf_ns);
    // Add an extra CNAME record which the first minimized query will match.
    tld_ns.add(CNAME {
        fqdn: FQDN::TEST_TLD.push_label("a"),
        ttl: 86400,
        target: FQDN::TEST_TLD.push_label("other"),
    });

    root_ns.referral_nameserver(&tld_ns);

    let root_hint = root_ns.root_hint();

    let _root_ns = root_ns.start()?;
    let _tld_ns = tld_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;

    let resolver = Resolver::new(&network, root_hint).start()?;

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse();
    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &needle_fqdn)?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(
        output.answer.len(),
        1,
        "wrong number of answer records: {output:?}"
    );
    let record = output.answer[0].clone().try_into_a().unwrap();
    assert_eq!(record.ipv4_addr, Ipv4Addr::new(1, 2, 3, 4));

    Ok(())
}
