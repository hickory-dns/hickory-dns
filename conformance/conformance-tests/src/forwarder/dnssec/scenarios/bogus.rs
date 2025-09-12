use std::net::Ipv4Addr;

use dns_test::{
    Error, FQDN, Forwarder, Implementation, Network, PEER, Resolver, TrustAnchor,
    client::{Client, DigSettings, DigStatus},
    name_server::NameServer,
    record::{A, RecordType},
    zone_file::SignSettings,
};

#[test]
fn wrong_key() -> Result<(), Error> {
    let network = Network::new()?;
    let sign_settings = SignSettings::default();
    let leaf_zone = FQDN::TEST_TLD.push_label("wrong-key");
    let peer = &dns_test::PEER;

    let wrong_key_ns = NameServer::new(peer, leaf_zone.clone(), &network)?;
    let wrong_key_ns = wrong_key_ns.sign(sign_settings.clone())?;
    let wrong_ds = wrong_key_ns.ds().ksk.clone();
    drop(wrong_key_ns);

    let mut root_ns = NameServer::new(peer, FQDN::ROOT, &network)?;
    let mut tld_ns = NameServer::new(peer, FQDN::TEST_TLD, &network)?;
    let mut nameservers_ns = NameServer::new(peer, FQDN::TEST_DOMAIN, &network)?;
    let leaf_ns = NameServer::new(peer, leaf_zone.clone(), &network)?;

    root_ns.referral_nameserver(&tld_ns);
    tld_ns.referral_nameserver(&nameservers_ns);
    tld_ns.referral_nameserver(&leaf_ns);

    nameservers_ns.add(root_ns.a());
    nameservers_ns.add(tld_ns.a());

    let nameservers_ns = nameservers_ns.sign(sign_settings.clone())?;
    let leaf_ns = leaf_ns.sign(sign_settings.clone())?;

    tld_ns.add(nameservers_ns.ds().ksk.clone());
    tld_ns.add(wrong_ds);

    let tld_ns = tld_ns.sign(sign_settings.clone())?;
    root_ns.add(tld_ns.ds().ksk.clone());

    let root_ns = root_ns.sign(sign_settings)?;
    let mut trust_anchor = TrustAnchor::empty();
    trust_anchor.add(root_ns.key_signing_key().clone());
    let root_hint = root_ns.root_hint();

    let _root_ns = root_ns.start()?;
    let _tld_ns = tld_ns.start()?;
    let _nameservers_ns = nameservers_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;

    let resolver = Resolver::new(&network, root_hint).start_with_subject(peer)?;
    let forwarder = Forwarder::new(&network, &resolver)
        .trust_anchor(&trust_anchor)
        .start()?;

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().authentic_data();

    let output = client.dig(settings, forwarder.ipv4_addr(), RecordType::SOA, &leaf_zone)?;
    assert!(output.status.is_servfail());

    Ok(())
}

#[test]
fn nsec3_does_not_cover() -> Result<(), Error> {
    let network = Network::new()?;
    let sign_settings = SignSettings::default();

    let mut leaf_ns = NameServer::new(
        &Implementation::test_server("nsec3_nocover", "both"),
        FQDN::TEST_DOMAIN,
        &network,
    )?;

    // Add many records with different owner names to reduce the range covered by each NSEC3 record
    // in the chain.
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

    let resolver = Resolver::new(&network, root_hint).start_with_subject(&PEER)?;
    let forwarder = Forwarder::new(&network, &resolver)
        .trust_anchor(&trust_anchor)
        .start()?;
    let client = Client::new(&network)?;
    let dig_settings = *DigSettings::default().recurse().dnssec().tcp();

    let response = client.dig(
        dig_settings,
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("subdomain-0"),
    )?;
    assert_eq!(response.status, DigStatus::NOERROR);

    // These subdomains exist in the zone file, but the test server has been configured to return
    // NXDOMAIN for any A record queries along with NSEC3 and RRSIG records.  Since these names
    // do exist, the NSEC3 records will not cover those names.
    for i in 1..4 {
        let response = client.dig(
            dig_settings,
            forwarder.ipv4_addr(),
            RecordType::A,
            &FQDN::TEST_DOMAIN.push_label(&format!("subdomain-{i}")),
        )?;

        assert_eq!(response.status, DigStatus::SERVFAIL);
    }

    Ok(())
}
