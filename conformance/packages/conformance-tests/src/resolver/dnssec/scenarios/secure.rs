use std::net::Ipv4Addr;

use dns_test::client::{Client, DigSettings};
use dns_test::name_server::NameServer;
use dns_test::record::RecordType;
use dns_test::tshark::Capture;
use dns_test::zone_file::SignSettings;
use dns_test::{Network, Resolver, Result, TrustAnchor, FQDN};

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
    let needle_fqdn = FQDN("example.nameservers.com.")?;

    let (resolver, _nameservers, _trust_anchor) =
        fixtures::minimally_secure(needle_fqdn.clone(), expected_ipv4_addr)?;

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
    let needle_fqdn = FQDN("example.nameservers.com.")?;

    let (resolver, _nameservers, _trust_anchor) =
        fixtures::minimally_secure(needle_fqdn.clone(), expected_ipv4_addr)?;

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
    let needle_fqdn = FQDN("example.nameservers.com.")?;

    let (resolver, nameservers, _trust_anchor) =
        fixtures::minimally_secure(needle_fqdn.clone(), expected_ipv4_addr)?;

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

// TODO nxdomain with NSEC records
// TODO nxdomain with NSEC3 records
