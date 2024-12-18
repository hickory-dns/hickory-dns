use std::net::Ipv4Addr;

use dns_test::client::{Client, DigOutput, DigSettings};
use dns_test::name_server::NameServer;
use dns_test::record::{Record, RecordType};
use dns_test::zone_file::{Nsec, SignSettings};
use dns_test::{FQDN, Network, Resolver, Result, TrustAnchor};

mod deprecated_algorithm;

// in this DNS network all zones except one are signed. and importantly, the referral to the
// unsigned zone (the NS+A records in the parent zone) is also signed
//
// a validating resolver should not respond with SERVFAIL to queries about the unsigned zone because
// the security status of the whole zone is "Insecure", not "Bogus"
#[test]
fn unsigned_zone_nsec3() -> Result<()> {
    unsigned_zone_fixture(Nsec::_3 {
        opt_out: false,
        salt: None,
    })
}

#[test]
fn unsigned_zone_nsec() -> Result<()> {
    unsigned_zone_fixture(Nsec::_1)
}

fn unsigned_zone_fixture(nsec: Nsec) -> Result<()> {
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let unsigned_zone = FQDN::TEST_TLD.push_label("unsigned");
    let needle_fqdn = unsigned_zone.push_label("example");

    let mut sign_settings = SignSettings::default();
    sign_settings = sign_settings.nsec(nsec);
    let network = Network::new()?;

    let mut unsigned_ns = NameServer::new(&dns_test::PEER, unsigned_zone.clone(), &network)?;
    unsigned_ns.add(Record::a(needle_fqdn.clone(), expected_ipv4_addr));
    let mut sibling_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_DOMAIN, &network)?;
    let mut tld_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_TLD, &network)?;
    let mut root_ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, &network)?;

    sibling_ns.add(sibling_ns.a());

    root_ns.referral_nameserver(&tld_ns);
    tld_ns.referral_nameserver(&sibling_ns);
    tld_ns.referral_nameserver(&unsigned_ns);

    let sibling_ns = sibling_ns.sign(sign_settings.clone())?;

    tld_ns.add(sibling_ns.ds().ksk.clone());
    let tld_ns = tld_ns.sign(sign_settings.clone())?;

    root_ns.add(tld_ns.ds().ksk.clone());

    let mut trust_anchor = TrustAnchor::empty();
    let root_ns = root_ns.sign(sign_settings)?;
    trust_anchor.add(root_ns.key_signing_key().clone());
    trust_anchor.add(root_ns.zone_signing_key().clone());

    let root_hint = root_ns.root_hint();
    let _nameservers = [
        root_ns.start()?,
        tld_ns.start()?,
        sibling_ns.start()?,
        unsigned_ns.start()?,
    ];

    let resolver = Resolver::new(&network, root_hint)
        .trust_anchor(&trust_anchor)
        .start()?;

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().authentic_data();
    // sanity check: the other zones are correctly signed
    for zone in [FQDN::ROOT, FQDN::TEST_TLD, FQDN::TEST_DOMAIN] {
        let output = client.dig(settings, resolver.ipv4_addr(), RecordType::SOA, &zone)?;

        assert!(output.status.is_noerror());
        assert!(output.flags.authenticated_data);
    }

    let settings = *DigSettings::default().recurse();
    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &needle_fqdn)?;

    dbg!(&output);

    assert!(output.status.is_noerror());
    assert!(!output.flags.authenticated_data);

    Ok(())
}

#[test]
fn no_ds_record_nsec1() -> Result<()> {
    let (output, _logs) = no_ds_record_fixture(SignSettings::default().nsec(Nsec::_1), false)?;

    dbg!(&output);

    assert!(output.status.is_noerror());
    assert!(!output.flags.authenticated_data);

    Ok(())
}

#[test]
fn no_ds_record_nsec3() -> Result<()> {
    let (output, _logs) = no_ds_record_fixture(
        SignSettings::default().nsec(Nsec::_3 {
            salt: None,
            opt_out: false,
        }),
        false,
    )?;

    dbg!(&output);

    assert!(output.status.is_noerror());
    assert!(!output.flags.authenticated_data);

    Ok(())
}

#[test]
fn no_ds_record_nsec3_case_randomization() -> Result<()> {
    let (output, _logs) = no_ds_record_fixture(
        SignSettings::default().nsec(Nsec::_3 {
            salt: None,
            opt_out: false,
        }),
        true,
    )?;

    dbg!(&output);

    assert!(output.status.is_noerror());
    assert!(!output.flags.authenticated_data);

    Ok(())
}

#[test]
fn no_ds_record_nsec3_opt_out() -> Result<()> {
    let (output, logs) = no_ds_record_fixture(SignSettings::rsasha256_nsec3_optout(), false)?;

    dbg!(&output);

    assert!(output.status.is_noerror());
    assert!(!output.flags.authenticated_data);

    if dns_test::SUBJECT.is_hickory() {
        assert!(logs.contains("DS query covered by opt-out proof"));
    }

    Ok(())
}

// the `no-ds.testing.` zone is signed but no DS record exists in the parent `testing.` zone.
// importantly, the `testing.` zone must contain NSEC/NSEC3 records to deny the existence of
// `no-ds.testing./DS` (which is why we cannot use `Graph::build` + `Sign::AndAmend` to produce
// this network)
fn no_ds_record_fixture(
    sign_settings: SignSettings,
    case_randomization: bool,
) -> Result<(DigOutput, String)> {
    let network = Network::new()?;

    let no_ds_zone = FQDN::TEST_TLD.push_label("no-ds");
    let needle_fqdn = no_ds_zone.push_label("example");
    let needle_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);

    let mut no_ds_ns = NameServer::new(&dns_test::PEER, no_ds_zone.clone(), &network)?;
    no_ds_ns.add(Record::a(needle_fqdn.clone(), needle_ipv4_addr));

    let mut sibling_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_DOMAIN, &network)?;
    let mut tld_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_TLD, &network)?;
    let mut root_ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, &network)?;

    sibling_ns.add(root_ns.a());
    sibling_ns.add(tld_ns.a());
    sibling_ns.add(no_ds_ns.a());
    sibling_ns.add(sibling_ns.a());

    root_ns.referral_nameserver(&tld_ns);
    tld_ns.referral_nameserver(&sibling_ns);
    tld_ns.referral_nameserver(&no_ds_ns);

    let no_ds_ns = no_ds_ns.sign(sign_settings.clone())?;
    let sibling_ns = sibling_ns.sign(sign_settings.clone())?;

    tld_ns.add(sibling_ns.ds().ksk.clone());
    // IMPORTANT omit this! this is the DS that connects `testing.` to `no-ds.testing.` in
    // the chain of trust. `no-ds.testing.` is correctly signed but the lack of the DS record turns
    // it into an "island of security"
    if false {
        tld_ns.add(no_ds_ns.ds().ksk.clone());
    }
    let tld_ns = tld_ns.sign(sign_settings.clone())?;

    root_ns.add(tld_ns.ds().ksk.clone());

    let mut trust_anchor = TrustAnchor::empty();
    let root_ns = root_ns.sign(sign_settings)?;

    trust_anchor.add(root_ns.key_signing_key().clone());
    trust_anchor.add(root_ns.zone_signing_key().clone());

    let root_hint = root_ns.root_hint();
    let _root_ns = root_ns.start()?;
    let _com_ns = tld_ns.start()?;
    let _sibling_ns = sibling_ns.start()?;
    let _no_ds_ns = no_ds_ns.start()?;

    let mut resolver_settings = Resolver::new(&network, root_hint);
    resolver_settings.trust_anchor(&trust_anchor);
    if case_randomization {
        resolver_settings.case_randomization();
    }
    let resolver = resolver_settings.start()?;

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &needle_fqdn)?;

    Ok((output, resolver.logs()?))
}
