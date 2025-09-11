use std::net::Ipv4Addr;

use dns_test::{
    Error, FQDN, Implementation, Network, PEER, Resolver,
    client::{Client, DigSettings, DigStatus},
    name_server::NameServer,
    record::{A, RecordType},
    zone_file::SignSettings,
};

#[test]
fn does_not_cover() -> Result<(), Error> {
    let network = Network::new()?;
    let sign_settings = SignSettings::default();

    let mut leaf_ns = NameServer::new(
        &Implementation::test_server("nsec3_nocover", "both"),
        FQDN::TEST_DOMAIN,
        &network,
    )?;

    for i in 0..4 {
        leaf_ns.add(A {
            fqdn: FQDN::TEST_DOMAIN.push_label(&format!("subdomain-{i}")),
            ttl: 86400,
            ipv4_addr: Ipv4Addr::LOCALHOST,
        });
    }

    let leaf_ns = leaf_ns.sign(sign_settings.clone())?;

    let mut tld_ns = NameServer::new(&PEER, FQDN::TEST_TLD, &network)?;
    tld_ns.referral_nameserver(&leaf_ns);
    tld_ns.add(leaf_ns.ds().ksk.clone());
    let tld_ns = tld_ns.sign(sign_settings.clone())?;

    let mut root_ns = NameServer::new(&PEER, FQDN::ROOT, &network)?;
    root_ns.referral_nameserver(&tld_ns);
    root_ns.add(tld_ns.ds().ksk.clone());
    let root_ns = root_ns.sign(sign_settings)?;
    let root_hint = root_ns.root_hint();
    let trust_anchor = root_ns.trust_anchor();

    let _leaf_ns = leaf_ns.start()?;
    let _tld_ns = tld_ns.start()?;
    let _root_ns = root_ns.start()?;

    let resolver = Resolver::new(&network, root_hint)
        .trust_anchor(&trust_anchor)
        .start()?;
    let client = Client::new(&network)?;
    let dig_settings = *DigSettings::default().recurse().dnssec().tcp();

    // This record should be NoError/AD
    let response = client.dig(
        dig_settings,
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("subdomain-0"),
    )?;
    assert_eq!(response.status, DigStatus::NOERROR);
    assert!(response.flags.authenticated_data);

    // This record doesn't exist in the zone file and has a valid covering NSEC3 proof
    let response = client.dig(
        dig_settings,
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("validnx"),
    )?;
    assert_eq!(response.status, DigStatus::NXDOMAIN);
    assert!(response.flags.authenticated_data);

    // These subdomains exist in the zone file, but the test server has been configured to return
    // NXDOMAIN for any A record queries along with NSEC3 and RRSIG records.  Since these names
    // do exist, the NSEC3 records will not cover those names.
    for i in 1..4 {
        let response = client.dig(
            dig_settings,
            resolver.ipv4_addr(),
            RecordType::A,
            &FQDN::TEST_DOMAIN.push_label(&format!("subdomain-{i}")),
        )?;

        assert_eq!(response.status, DigStatus::SERVFAIL);
    }

    Ok(())
}
