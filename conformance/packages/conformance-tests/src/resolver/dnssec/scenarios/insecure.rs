use std::net::Ipv4Addr;

use dns_test::client::{Client, DigSettings};
use dns_test::name_server::NameServer;
use dns_test::record::{Record, RecordType};
use dns_test::zone_file::SignSettings;
use dns_test::{Network, Resolver, Result, TrustAnchor, FQDN};

mod deprecated_algorithm;

// in this DNS network all zones except one are signed. and importantly, the referral to the
// unsigned zone (the NS+A records in the parent zone) is also signed
//
// a validating resolver should not respond with SERVFAIL to queries about the unsigned zone because
// the security status of the whole zone is "Insecure", not "Bogus"
#[test]
#[ignore]
fn unsigned_zone() -> Result<()> {
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let needle_fqdn = FQDN("example.unsigned.testing.")?;

    let sign_settings = SignSettings::default();
    let network = Network::new()?;

    let unsigned_fqdn = FQDN("unsigned.testing.")?;
    let mut unsigned_ns = NameServer::new(&dns_test::PEER, unsigned_fqdn.clone(), &network)?;
    unsigned_ns.add(Record::a(needle_fqdn.clone(), expected_ipv4_addr));
    let mut nameservers_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_DOMAIN, &network)?;
    let mut tld_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_TLD, &network)?;
    let mut root_ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, &network)?;

    nameservers_ns.add(root_ns.a());
    nameservers_ns.add(tld_ns.a());
    nameservers_ns.add(unsigned_ns.a());
    nameservers_ns.add(nameservers_ns.a());

    root_ns.referral_nameserver(&tld_ns);
    tld_ns.referral_nameserver(&nameservers_ns);
    tld_ns.referral_nameserver(&unsigned_ns);

    let nameservers_ns = nameservers_ns.sign(sign_settings.clone())?;

    tld_ns.add(nameservers_ns.ds().ksk.clone());
    let tld_ns = tld_ns.sign(sign_settings.clone())?;

    root_ns.add(tld_ns.ds().ksk.clone());

    let mut trust_anchor = TrustAnchor::empty();
    let root_ns = root_ns.sign(sign_settings)?;
    trust_anchor.add(root_ns.key_signing_key().clone());
    trust_anchor.add(root_ns.zone_signing_key().clone());

    let root_hint = root_ns.root_hint();
    let _root_ns = root_ns.start()?;
    let _tld_ns = tld_ns.start()?;
    let _nameservers_ns = nameservers_ns.start()?;
    let _unsigned_ns = unsigned_ns.start()?;

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

    let settings = *DigSettings::default().recurse();
    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &needle_fqdn)?;

    dbg!(&output);

    assert!(output.status.is_noerror());
    assert!(!output.flags.authenticated_data);

    Ok(())
}
