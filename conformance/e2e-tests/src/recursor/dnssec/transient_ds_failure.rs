use dns_test::{
    Error, FQDN, Implementation, Network, PEER, Resolver, TrustAnchor,
    client::{Client, DigSettings, DigStatus},
    name_server::NameServer,
    record::{A, RecordType},
    zone_file::SignSettings,
};
use std::net::Ipv4Addr;

/// Test a transient parent-side failure on a leaf zone's DS query.
///
/// This must not poison the validation cache for the leaf zone's DNSKEY rrset. After the
/// parent recovers, a fresh qname under the leaf zone must validate successfully.
///
/// Setup: root → tld_proxy → real_tld → leaf. The proxy forwards all queries to the real tld,
/// except it returns SERVFAIL the first time it sees `leaf.testing./DS`. Subsequent matches
/// are forwarded unmodified.
///
/// Phase 1: query a name under the leaf zone while the parent is "broken". We expect SERVFAIL.
///
/// Phase 2: query a *different* name under the same leaf zone after the parent has recovered.
/// The bug is that the validation cache holds a poisoned Bogus entry for the leaf's DNSKEY
/// rrset and returns SERVFAIL without re-asking the parent. After the fix, the cache miss
/// forces a fresh DS fetch, validation succeeds, and the client gets NOERROR with AD=1.
#[test]
fn transient_ds_servfail_does_not_poison_leaf_zone() -> Result<(), Error> {
    let network = Network::new()?;
    let sign_settings = SignSettings::default();

    let leaf_zone = FQDN("leaf.testing.")?;
    let leaf_a_1 = FQDN("a.leaf.testing.")?;
    let leaf_a_2 = FQDN("b.leaf.testing.")?;

    let mut leaf_ns = NameServer::new(&PEER, leaf_zone.clone(), &network)?;
    leaf_ns.add(A {
        fqdn: leaf_a_1.clone(),
        ttl: 60,
        ipv4_addr: Ipv4Addr::new(192, 0, 2, 10),
    });
    leaf_ns.add(A {
        fqdn: leaf_a_2.clone(),
        ttl: 60,
        ipv4_addr: Ipv4Addr::new(192, 0, 2, 11),
    });
    let leaf_ns = leaf_ns.sign(sign_settings.clone())?;

    let mut real_tld_ns = NameServer::new(&PEER, FQDN::TEST_TLD, &network)?;
    real_tld_ns.referral_nameserver(&leaf_ns);
    real_tld_ns.add(leaf_ns.ds().ksk.clone());
    let real_tld_ns = real_tld_ns.sign(sign_settings.clone())?;

    let proxy_tld_ns = NameServer::builder(
        Implementation::test_server(
            "servfail_rrset",
            vec![
                real_tld_ns.ipv4_addr().to_string(),
                leaf_zone.as_str().to_string(),
                "DS".to_string(),
                "1".to_string(),
            ],
            "both",
        ),
        FQDN::TEST_TLD,
        network.clone(),
    )
    .nameserver_fqdn(real_tld_ns.zone_file().soa.nameserver.clone())
    .rname_fqdn(real_tld_ns.zone_file().soa.admin.clone())
    .build()?;

    let mut root_ns = NameServer::new(&PEER, FQDN::ROOT, &network)?;
    root_ns.referral_nameserver(&proxy_tld_ns);
    root_ns.add(real_tld_ns.ds().ksk.clone());
    let root_ns = root_ns.sign(sign_settings)?;

    let mut trust_anchor = TrustAnchor::empty();
    trust_anchor.add(root_ns.key_signing_key().clone());

    let root_hint = root_ns.root_hint();
    let _root_ns = root_ns.start()?;
    let _proxy_tld_ns = proxy_tld_ns.start()?;
    let _real_tld_ns = real_tld_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;

    let resolver = Resolver::new(&network, root_hint)
        .trust_anchor(&trust_anchor)
        .start_with_subject(&Implementation::hickory())?;
    let client = Client::new(&network)?;
    let dig_settings = *DigSettings::default().recurse().authentic_data();

    let phase1 = client.dig(dig_settings, resolver.ipv4_addr(), RecordType::A, &leaf_a_1)?;
    assert_eq!(
        phase1.status,
        DigStatus::SERVFAIL,
        "expected phase 1 response to be SERVFAIL, got {phase1:#?}\nresolver logs:\n{}",
        resolver.logs()?,
    );

    let phase2 = client.dig(dig_settings, resolver.ipv4_addr(), RecordType::A, &leaf_a_2)?;
    assert_eq!(
        phase2.status,
        DigStatus::NOERROR,
        "expected phase 2 response to be NOERROR, got {phase2:#?}\nresolver logs:\n{}",
        resolver.logs()?,
    );
    assert!(
        phase2.flags.authenticated_data,
        "expected phase 2 response to be AD=1; got {phase2:#?}",
    );

    Ok(())
}
