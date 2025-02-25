use std::net::Ipv4Addr;

use dns_test::client::{Client, DigSettings};
use dns_test::name_server::NameServer;
use dns_test::record::{Record, RecordType};
use dns_test::tshark::Capture;
use dns_test::zone_file::{Nsec, SignSettings};
use dns_test::{FQDN, Network, Resolver, Result, TrustAnchor};

use crate::resolver::dnssec::fixtures;

// no DS records are involved; this is a single-link chain of trust
#[test]
fn can_validate_without_delegation() -> Result<()> {
    let network = Network::new()?;
    let mut ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, &network)?;
    ns.add(ns.a());
    let ns = ns.sign(SignSettings::default())?;

    let root_ksk = ns.key_signing_key().clone();
    let root_zsk = ns.zone_signing_key().clone();

    eprintln!("root.zone.signed:\n{}", ns.signed_zone_file());

    let ns = ns.start()?;

    eprintln!("root.zone:\n{}", ns.zone_file());

    let trust_anchor = &TrustAnchor::from_iter([root_ksk.clone(), root_zsk.clone()]);
    let resolver = Resolver::new(&network, ns.root_hint())
        .trust_anchor(trust_anchor)
        .start()?;
    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver_addr, RecordType::SOA, &FQDN::ROOT)?;

    assert!(output.status.is_noerror());
    assert!(output.flags.authenticated_data);

    Ok(())
}

#[test]
fn can_validate_with_delegation() -> Result<()> {
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let needle_fqdn = FQDN::EXAMPLE_SUBDOMAIN;

    let (resolver, _nameservers, _trust_anchor) = fixtures::minimally_secure(
        needle_fqdn.clone(),
        expected_ipv4_addr,
        SignSettings::default(),
    )?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;
    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver_addr, RecordType::A, &needle_fqdn)?;

    assert!(output.status.is_noerror());

    assert!(output.flags.authenticated_data);

    let [a] = output.answer.try_into().unwrap();
    let a = a.try_into_a().unwrap();

    assert_eq!(needle_fqdn, a.fqdn);
    assert_eq!(expected_ipv4_addr, a.ipv4_addr);

    Ok(())
}

// the inclusion of RRSIGs records in the answer should not change the outcome of validation
// if the chain of trust was valid then the RRSIGs, which are part of the chain, must also be secure
#[test]
fn also_secure_when_do_is_set() -> Result<()> {
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let needle_fqdn = FQDN::EXAMPLE_SUBDOMAIN;

    let (resolver, _nameservers, _trust_anchor) = fixtures::minimally_secure(
        needle_fqdn.clone(),
        expected_ipv4_addr,
        SignSettings::default(),
    )?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;
    let settings = *DigSettings::default()
        .recurse()
        .dnssec() // DO = 1
        .authentic_data();
    let output = client.dig(settings, resolver_addr, RecordType::A, &needle_fqdn)?;

    assert!(output.status.is_noerror());

    // main assertion
    assert!(output.flags.authenticated_data);

    let [a, rrsig] = output.answer.try_into().unwrap();
    let a = a.try_into_a().unwrap();

    assert_eq!(needle_fqdn, a.fqdn);
    assert_eq!(expected_ipv4_addr, a.ipv4_addr);

    // sanity check that the RRSIG makes sense
    let rrsig = rrsig.try_into_rrsig().unwrap();
    assert_eq!(RecordType::A, rrsig.type_covered);

    Ok(())
}

#[test]
fn caches_answer() -> Result<()> {
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let needle_fqdn = FQDN::EXAMPLE_SUBDOMAIN;

    let (resolver, nameservers, _trust_anchor) = fixtures::minimally_secure(
        needle_fqdn.clone(),
        expected_ipv4_addr,
        SignSettings::default(),
    )?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;
    let settings = *DigSettings::default().recurse().authentic_data();

    let mut tshark = None;
    for i in 0..2 {
        if i == 1 {
            tshark = Some(resolver.eavesdrop()?);
        }

        let output = client.dig(settings, resolver_addr, RecordType::A, &needle_fqdn)?;

        assert!(output.status.is_noerror());
        assert!(output.flags.authenticated_data);

        let [a] = output.answer.try_into().unwrap();
        let a = a.try_into_a().unwrap();

        assert_eq!(needle_fqdn, a.fqdn);
        assert_eq!(expected_ipv4_addr, a.ipv4_addr);
    }

    let mut tshark = tshark.unwrap();
    tshark.wait_for_capture()?;
    let captures = tshark.terminate()?;

    // we validate caching behavior by eavesdropping on the second query and expecting no
    // communication between the resolver and the nameservers
    let ns_addrs = nameservers
        .iter()
        .map(|ns| ns.ipv4_addr())
        .collect::<Vec<_>>();
    for Capture { direction, .. } in captures {
        assert!(!ns_addrs.contains(&direction.peer_addr()));
    }

    Ok(())
}

// all the zones are correctly signed but the parent of the leaf zone contains a DS record that
// corresponds to the child's ZSK. usually, the DS record contains the digest of the KSK and the
// KSK is used to sign the ZSK, which is the key used to sign the records in the child zone.
// however, it appears to also be fine to have the parent zone directly vouch for the child's ZSK,
// eliminating the need for a KSK, so long the ZSK is self-signed in the child zone
#[test]
fn ds_of_zsk() -> Result<()> {
    let sign_settings = SignSettings::default();

    let network = Network::new()?;

    let no_ds_zone = FQDN::TEST_TLD.push_label("ds-of-zsk");
    let needle_fqdn = no_ds_zone.push_label("example");
    let needle_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);

    let mut leaf_ns = NameServer::new(&dns_test::PEER, no_ds_zone.clone(), &network)?;
    leaf_ns.add(Record::a(needle_fqdn.clone(), needle_ipv4_addr));

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

    let mut leaf_ns = leaf_ns.sign(sign_settings.clone())?;
    let sibling_ns = sibling_ns.sign(sign_settings.clone())?;

    tld_ns.add(sibling_ns.ds().ksk.clone());
    let ds2 = leaf_ns.ds();
    let ksk_tag = ds2.ksk.key_tag;
    let zsk_tag = ds2.zsk.key_tag;
    dbg!(&ds2);
    // sanity checks
    assert_ne!(ds2.zsk.key_tag, ds2.ksk.key_tag, "DS records are equal");
    assert_ne!(ds2.zsk.digest, ds2.ksk.digest, "DS records are equal");
    // IMPORTANT here we use the DS that corresponds to the _Zone_ Signing Key (ZSK)
    tld_ns.add(ds2.zsk.clone());

    // remove the RRSIG over DNSKEY that was produced using the KSK
    // check that there's a RRSIG over DNSKEY produced with the ZSK
    let zone_file_records = &mut leaf_ns.signed_zone_file_mut().records;
    let mut remove_count = 0;
    let mut dnskey_signed_with_zsk = false;
    for index in (0..zone_file_records.len()).rev() {
        if let Record::RRSIG(rrsig) = &zone_file_records[index] {
            if rrsig.key_tag == ksk_tag {
                assert_eq!(RecordType::DNSKEY, rrsig.type_covered);
                remove_count += 1;
                zone_file_records.remove(index);
            } else if rrsig.key_tag == zsk_tag && rrsig.type_covered == RecordType::DNSKEY {
                dnskey_signed_with_zsk = true;
            }
        }
    }
    assert_eq!(1, remove_count);
    assert!(dnskey_signed_with_zsk);

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
    let _no_ds_ns = leaf_ns.start()?;

    let resolver = Resolver::new(&network, root_hint)
        .trust_anchor(&trust_anchor)
        .start()?;

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &needle_fqdn)?;

    dbg!(&output);

    assert!(output.status.is_noerror());
    assert!(output.flags.authenticated_data);

    Ok(())
}

#[test]
fn nxdomain_nsec() -> Result<()> {
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let needle_fqdn = FQDN::EXAMPLE_SUBDOMAIN;

    let (resolver, _nameservers, _trust_anchor) = fixtures::minimally_secure(
        needle_fqdn.clone(),
        expected_ipv4_addr,
        SignSettings::default().nsec(Nsec::_1),
    )?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;
    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(
        settings,
        resolver_addr,
        RecordType::A,
        &needle_fqdn.push_label("nonexistent"),
    )?;

    assert!(output.status.is_nxdomain());

    assert!(output.flags.authenticated_data);

    Ok(())
}

#[test]
fn nxdomain_nsec3() -> Result<()> {
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let needle_fqdn = FQDN::EXAMPLE_SUBDOMAIN;

    let (resolver, _nameservers, _trust_anchor) = fixtures::minimally_secure(
        needle_fqdn.clone(),
        expected_ipv4_addr,
        SignSettings::default(),
    )?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;
    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(
        settings,
        resolver_addr,
        RecordType::A,
        &needle_fqdn.push_label("nonexistent"),
    )?;

    assert!(output.status.is_nxdomain());

    assert!(output.flags.authenticated_data);

    Ok(())
}
