use dns_test::{
    FQDN, Forwarder, Network, Resolver, Result, TrustAnchor,
    client::{Client, DigSettings},
    name_server::NameServer,
    record::RecordType,
    zone_file::SignSettings,
};

#[test]
fn wrong_key() -> Result<()> {
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
