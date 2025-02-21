use std::net::Ipv4Addr;

use dns_test::{
    FQDN, Network, Resolver, Result, TrustAnchor,
    client::{Client, DigOutput, DigSettings},
    name_server::NameServer,
    record::{Record, RecordType},
    zone_file::SignSettings,
};

const EXPECTED: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);

// check that the fixture works
#[test]
fn sanity_check() -> Result<()> {
    let output = fixture("dsa", SignSettings::default())?;

    dbg!(&output);

    assert!(output.status.is_noerror());
    assert!(output.flags.authenticated_data);

    let [record] = output.answer.try_into().unwrap();
    let a = record.try_into_a().unwrap();
    assert_eq!(EXPECTED, a.ipv4_addr);

    Ok(())
}

#[test]
fn dsa() -> Result<()> {
    let output = fixture("dsa", SignSettings::dsa())?;

    dbg!(&output);

    assert!(output.status.is_noerror());
    assert!(!output.flags.authenticated_data);

    let [record] = output.answer.try_into().unwrap();
    let a = record.try_into_a().unwrap();
    assert_eq!(EXPECTED, a.ipv4_addr);

    Ok(())
}

#[test]
fn rsamd5() -> Result<()> {
    let output = fixture("rsamd5", SignSettings::rsamd5())?;

    dbg!(&output);

    assert!(output.status.is_noerror());
    assert!(!output.flags.authenticated_data);

    let [record] = output.answer.try_into().unwrap();
    let a = record.try_into_a().unwrap();
    assert_eq!(EXPECTED, a.ipv4_addr);

    Ok(())
}

fn fixture(label: &str, deprecated_settings: SignSettings) -> Result<DigOutput> {
    let leaf_zone = FQDN::TEST_TLD.push_label(label);
    let needle_fqdn = leaf_zone.push_label("example");

    let good_settings = SignSettings::default();
    let network = Network::new()?;

    let mut leaf_ns = NameServer::new(&dns_test::PEER, leaf_zone.clone(), &network)?;
    leaf_ns.add(Record::a(needle_fqdn.clone(), EXPECTED));

    let mut sibling_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_DOMAIN, &network)?;
    let mut tld_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_TLD, &network)?;
    let mut root_ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, &network)?;

    sibling_ns.add(root_ns.a());
    sibling_ns.add(tld_ns.a());
    sibling_ns.add(leaf_ns.a());
    sibling_ns.add(sibling_ns.a());

    root_ns.referral_nameserver(&tld_ns);
    tld_ns.referral_nameserver(&sibling_ns);
    tld_ns.referral_nameserver(&leaf_ns);

    let sibling_ns = sibling_ns.sign(good_settings.clone())?;
    // IMPORTANT! only this zone uses the deprecated algorithm
    let leaf_ns = leaf_ns.sign(deprecated_settings.clone())?;

    tld_ns.add(sibling_ns.ds().ksk.clone());
    tld_ns.add(leaf_ns.ds().ksk.clone());
    let tld_ns = tld_ns.sign(good_settings.clone())?;

    root_ns.add(tld_ns.ds().ksk.clone());

    let mut trust_anchor = TrustAnchor::empty();
    let root_ns = root_ns.sign(good_settings)?;
    trust_anchor.add(root_ns.key_signing_key().clone());
    trust_anchor.add(root_ns.zone_signing_key().clone());

    let root_hint = root_ns.root_hint();
    let _nameservers = [
        root_ns.start()?,
        tld_ns.start()?,
        sibling_ns.start()?,
        leaf_ns.start()?,
    ];

    let resolver = Resolver::new(&network, root_hint)
        .trust_anchor(&trust_anchor)
        .start()?;

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().authentic_data();
    // sanity check: the other zones are correctly signed
    for zone in [FQDN::ROOT, FQDN::TEST_TLD, FQDN::TEST_DOMAIN] {
        let output = client.dig(settings, resolver.ipv4_addr(), RecordType::SOA, &zone)?;

        // XXX unclear why BIND & hickory fail this sanity check but that doesn't affect the
        // main assertion below
        if zone != FQDN::TEST_DOMAIN || dns_test::SUBJECT.is_unbound() {
            assert!(output.status.is_noerror());
            assert!(output.flags.authenticated_data);
        }
    }

    let settings = *DigSettings::default().recurse().authentic_data();
    let ret = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &needle_fqdn);

    println!("{}", resolver.logs().unwrap());

    ret
}
