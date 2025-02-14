use std::{fs, net::Ipv4Addr};

use dns_test::{
    FQDN, Implementation, Network, Resolver, Result,
    client::{Client, DigSettings, DigStatus},
    name_server::NameServer,
    record::{A, RecordType},
    zone_file::SignSettings,
};

#[test]
fn does_not_cover() -> Result<()> {
    let network = Network::new()?;
    let sign_settings = SignSettings::default();

    let mut leaf_ns = NameServer::new(&Implementation::Dnslib, FQDN::TEST_DOMAIN, &network)?;
    let script =
        fs::read_to_string("src/resolver/dnssec/scenarios/nsec3/does_not_cover/server.py")?;
    leaf_ns.cp("/script.py", &script)?;

    // Add many records with different owner names to reduce the range covered by each NSEC3 record
    // in the chain.
    for i in 0..100 {
        leaf_ns.add(A {
            fqdn: FQDN::TEST_DOMAIN.push_label(&format!("subdomain-{i}")),
            ttl: 86400,
            ipv4_addr: Ipv4Addr::LOCALHOST,
        });
    }

    let leaf_ns = leaf_ns.sign(sign_settings.clone())?;

    let mut tld_ns = NameServer::new(&Implementation::test_peer(), FQDN::TEST_TLD, &network)?;
    tld_ns.referral_nameserver(&leaf_ns);
    tld_ns.add(leaf_ns.ds().ksk.clone());
    let tld_ns = tld_ns.sign(sign_settings.clone())?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    root_ns.referral_nameserver(&tld_ns);
    root_ns.add(tld_ns.ds().ksk.clone());
    let root_ns = root_ns.sign(sign_settings)?;
    let root_hint = root_ns.root_hint();
    let trust_anchor = root_ns.trust_anchor();

    let leaf_ns = leaf_ns.start()?;
    let _tld_ns = tld_ns.start()?;
    let _root_ns = root_ns.start()?;

    let resolver = Resolver::new(&network, root_hint)
        .trust_anchor(&trust_anchor)
        .start()?;
    let client = Client::new(&network)?;
    let dig_settings = *DigSettings::default().recurse().dnssec().tcp();

    // These subdomains are not covered by the arbitrary NSEC3 record chosen by the server. This
    // will be stable so long as the subdomains, NSEC3 algorithms, iterations, salt, and software
    // versions are held constant. If the hashed names change, this test is unlikely to break,
    // since there are so many more NSEC3 records in the chain than probed subdomains below.
    for subdomain in 'a'..='d' {
        let response = client.dig(
            dig_settings,
            resolver.ipv4_addr(),
            RecordType::A,
            &FQDN::TEST_DOMAIN.push_label(&subdomain.to_string()),
        )?;

        if subdomain == 'a' {
            println!("{}", resolver.logs()?);
            println!("{}", leaf_ns.logs()?);
        }

        assert_eq!(response.status, DigStatus::SERVFAIL);
    }

    Ok(())
}
