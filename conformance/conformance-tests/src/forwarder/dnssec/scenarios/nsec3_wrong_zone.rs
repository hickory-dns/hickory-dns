use std::net::Ipv4Addr;

use dns_test::{
    Error, FQDN, Forwarder, Implementation, Network, PEER, Resolver,
    client::{Client, DigSettings, DigStatus},
    name_server::NameServer,
    record::{Record, RecordType},
    zone_file::{Nsec, SignSettings, Signer},
};

/// This is a regression test for missing checks on the names of NSEC3 records.
///
/// DNSSEC validation was missing a check that NSEC3 record names were constructed correctly, and
/// only the last base32-encoded label was compared against other name hashes. The name of the NSEC3
/// record must be a direct descendant of its zone's apex, and the hashed name must be within the
/// zone.
///
/// For this test, we must create a signature over a maliciously constructed NSEC3 record, so we
/// cannot simply rely on dnssec-signzone or ldns-signzone, which both construct NSEC3 chains and
/// sign them. We will instead pass the attacker zone's ZSK private key to the test server, so it
/// can construct an NSEC3 record and sign it. The NSEC3 record's name will consist of the
/// base32-encoded hash of a name in the victim zone, plus the name of the attacker zone as the base
/// name. The NSEC3 record contents will be attacker controlled. The RRSIG over this crafted NSEC3
/// record will be made with the attacker zone's ZSK.
///
/// Attacking the recursive resolver seems difficult because the crafted record may get removed by
/// out-of-bailiwick checks. We can instead try this against a validating forwarder, which only gets
/// one response, with no distinctions between records from different zones.
///
/// For simplicity, the query under test will be for a record at the victim zone's apex. The forged
/// response will be a NODATA response, though the victim zone does have the requested RRset. Using
/// the zone apex as the QNAME means we don't need to provide a wildcard proof as well.
///
/// Victim zone:
///
/// ```text
/// victim.testing. SOA ...
/// victim.testing. NS ...
/// victim.testing. A 192.168.1.1
/// victim.testing. DNSKEY ...
/// victim.testing. DNSKEY ...
/// victim.testing. NSEC3PARAM 1 0 1 -
/// victim.testing. RRSIG SOA ...
/// victim.testing. RRSIG NS ...
/// victim.testing. RRSIG A ...
/// victim.testing. RRSIG DNSKEY ...
/// victim.testing. RRSIG NSEC3PARAM ...
/// H(victim.testing.).victim.testing. NSEC3 1 0 1 - H(victim.testing.) A NS SOA RRSIG DNSKEY NSEC3PARAM
/// H(victim.testing.).victim.testing. RRSIG NSEC3 ...
/// ```
///
/// Attacker zone:
///
/// ```text
/// attacker.testing. SOA ...
/// attacker.testing. NS ...
/// attacker.testing. DNSKEY ...
/// attacker.testing. DNSKEY ...
/// attacker.testing. NSEC3PARAM 1 0 1 -
/// attacker.testing. RRSIG SOA ...
/// attacker.testing. RRSIG NS ...
/// attacker.testing. RRSIG DNSKEY ...
/// attacker.testing. RRSIG DNSKEY ...
/// attacker.testing. RRSIG NSEC3PARAM ...
/// H(attacker.testing.).attacker.testing. NSEC3 1 0 1 - H(attacker.testing.) NS SOA RRSIG DNSKEY NSEC3PARAM
/// H(attacker.testing.).attacker.testing. RRSIG NSEC3 ...
/// ```
///
/// Forged response:
///
/// ```text
/// ;; QUESTION SECTION:
/// ; victim.testing. IN A
///
/// ;; AUTHORITY SECTION
/// victim.testing. SOA ...
/// victim.testing. RRSIG SOA ...
/// H(victim.testing.).attacker.testing. NSEC3 1 0 1 - H(victim.testing.) NS SOA RRSIG DNSKEY NSEC3PARAM
/// H(victim.testing.).attacker.testing. RRSIG NSEC3 ...
/// ```
#[test]
#[ignore = "hickory lacks checks on names of NSEC3 records"]
fn forged_nsec3_from_wrong_zone() -> Result<(), Error> {
    let network = Network::new()?;
    let sign_settings = SignSettings::default().nsec(Nsec::_3 {
        iterations: 1,
        opt_out: false,
        salt: None,
    });

    let attacker_name = FQDN::TEST_TLD.push_label("attacker");
    let victim_name = FQDN::TEST_TLD.push_label("victim");

    let attacker_ns = NameServer::new(&PEER, attacker_name.clone(), &network)?;
    let attacker_signer = Signer::new(attacker_ns.container(), sign_settings.clone())?;
    let attacker_keys = attacker_signer.generate_keys(&attacker_name)?;
    let attacker_ns = attacker_ns.sign_with_keys(sign_settings.clone(), &attacker_keys)?;

    let private_key_base64 = attacker_keys
        .zsk
        .private
        .split('\n')
        .flat_map(|line| line.strip_prefix("PrivateKey: "))
        .next()
        .unwrap();
    let public_key_base64 = &attacker_keys.zsk.public.rdata().public_key;

    let mut victim_ns = NameServer::new(&PEER, victim_name.clone(), &network)?;
    victim_ns.add(Record::a(
        victim_name.clone(),
        Ipv4Addr::new(192, 168, 1, 1),
    ));
    let victim_ns = victim_ns.sign(sign_settings.clone())?;

    let mut tld_ns = NameServer::new(&PEER, FQDN::TEST_TLD, &network)?;
    tld_ns.referral_nameserver(&attacker_ns);
    tld_ns.add(attacker_ns.ds().ksk.clone());
    tld_ns.referral_nameserver(&victim_ns);
    tld_ns.add(victim_ns.ds().ksk.clone());
    let tld_ns = tld_ns.sign(sign_settings.clone())?;

    let mut root_ns = NameServer::new(&PEER, FQDN::ROOT, &network)?;
    root_ns.referral_nameserver(&tld_ns);
    root_ns.add(tld_ns.ds().ksk.clone());
    let root_ns = root_ns.sign(sign_settings)?;
    let root_hint = root_ns.root_hint();
    let trust_anchor = root_ns.trust_anchor();

    let _attacker_ns = attacker_ns.start()?;
    let _victim_ns = victim_ns.start()?;
    let _tld_ns = tld_ns.start()?;
    let _root_ns = root_ns.start()?;

    let resolver = Resolver::new(&network, root_hint.clone()).start_with_subject(&PEER)?;
    let proxy =
        Resolver::new(&network, root_hint).start_with_subject(&Implementation::test_server(
            "nsec3_wrong_zone",
            vec![
                resolver.ipv4_addr().to_string(),
                private_key_base64.to_owned(),
                public_key_base64.clone(),
            ],
            "both",
        ))?;
    let forwarder = Forwarder::new(&network, &proxy)
        .trust_anchor(&trust_anchor)
        .start()?;
    let client = Client::new(&network)?;

    // Make the request without the involvement of the proxy.
    let settings = *DigSettings::default().recurse().dnssec();
    let honest_response =
        client.dig(settings, resolver.ipv4_addr(), RecordType::A, &victim_name)?;
    assert_eq!(honest_response.status, DigStatus::NOERROR);
    assert!(!honest_response.answer.is_empty(), "{honest_response:?}");

    // Confirm the proxy is working.
    let attacker_response = client.dig(settings, proxy.ipv4_addr(), RecordType::A, &victim_name)?;
    assert_eq!(attacker_response.status, DigStatus::NOERROR);
    assert!(attacker_response.answer.is_empty(), "{attacker_response:?}");
    // $ nsec3hash -r 1 0 1 - victim.testing.
    // victim.testing. NSEC3 1 0 1 - GTR6F74IERHONNKRCH3QDNUNNDVR2OF1
    assert!(
        attacker_response.authority.iter().any(|r| r
            .name()
            .as_str()
            .eq_ignore_ascii_case("GTR6F74IERHONNKRCH3QDNUNNDVR2OF1.attacker.testing.")),
        "{attacker_response:?}"
    );

    // Test the forwarder.
    let forwarder_response =
        client.dig(settings, forwarder.ipv4_addr(), RecordType::A, &victim_name)?;
    assert_eq!(forwarder_response.status, DigStatus::SERVFAIL);

    Ok(())
}
