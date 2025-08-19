use std::net::Ipv4Addr;

use dns_test::{
    Error, FQDN, Implementation, Network, Resolver, TrustAnchor,
    client::{Client, DigOutput, DigSettings},
    name_server::{Graph, NameServer, Sign},
    record::{Record, RecordType},
    zone_file::{Nsec, SignSettings},
};

/// This tests that the server will return an insecure answer when receiving NSEC3 records with
/// an iteration count exceeding the default soft limit, but below the hard limit.
#[test]
fn soft_nsec3_iteration_failure() -> Result<(), Error> {
    let (output, logs) = insecure_record_fixture(
        FQDN("noexist.insecure.testing.")?,
        SignSettings::default().nsec(Nsec::_3 {
            iterations: 101,
            salt: None,
            opt_out: false,
        }),
        None,
    )?;

    dbg!(&output);

    assert!(output.status.is_nxdomain());
    assert!(!output.flags.authenticated_data);
    assert!(logs.contains("iteration count 101 is over 100"));

    Ok(())
}

/// This tests that the server will return SERVFAIL when receiving NSEC3 records with
/// an iteration count exceeding the default hard limit.
#[test]
fn hard_nsec3_iteration_failure() -> Result<(), Error> {
    let (output, logs) = insecure_record_fixture(
        FQDN("noexist.insecure.testing.")?,
        SignSettings::default().nsec(Nsec::_3 {
            iterations: 501,
            salt: None,
            opt_out: false,
        }),
        None,
    )?;

    dbg!(&output);

    assert!(output.status.is_servfail());
    assert!(logs.contains("iteration count 501 is over 500"));

    Ok(())
}

/// This tests the nsec3_soft_iteration_limit and nsec3_hard_iteration_limit configuration settings
#[test]
fn nsec3_custom_iteration_count() -> Result<(), Error> {
    let (output, logs) = insecure_record_fixture(
        FQDN("noexist.insecure.testing.")?,
        SignSettings::default().nsec(Nsec::_3 {
            iterations: 11,
            salt: None,
            opt_out: false,
        }),
        Some(minijinja::render!(include_str!(
            "custom_nsec3_iterations.toml.jinja"
        ))),
    )?;

    dbg!(&output);

    assert!(output.status.is_nxdomain());
    assert!(!output.flags.authenticated_data);
    assert!(logs.contains("iteration count 11 is over 10"));

    let (output, logs) = insecure_record_fixture(
        FQDN("noexist.insecure.testing.")?,
        SignSettings::default().nsec(Nsec::_3 {
            iterations: 21,
            salt: None,
            opt_out: false,
        }),
        Some(minijinja::render!(include_str!(
            "custom_nsec3_iterations.toml.jinja"
        ))),
    )?;

    dbg!(&output);

    assert!(output.status.is_servfail());
    assert!(logs.contains("iteration count 21 is over 20"));

    Ok(())
}

/// This test verifies the server will verify NSEC3 RRSIGs before rejecting high iteration counts.
#[test]
fn hard_nsec3_iteration_invalid_rrsig() -> Result<(), Error> {
    let network = Network::new()?;
    let leaf_zone = FQDN::TEST_DOMAIN;
    let mut leaf_ns = NameServer::new(&Implementation::test_peer(), leaf_zone.clone(), &network)?;

    leaf_ns.add(Record::a(
        leaf_zone.push_label("host"),
        Ipv4Addr::new(1, 2, 3, 4),
    ));

    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::AndAmend {
            settings: SignSettings::default().nsec(Nsec::_3 {
                iterations: 501,
                salt: None,
                opt_out: false,
            }),
            mutate: &|zone, records| {
                if zone == &leaf_zone {
                    let mut did_remove = false;
                    for record in records.iter_mut() {
                        if let Record::RRSIG(rrsig) = record {
                            if rrsig.type_covered == RecordType::NSEC3 {
                                let mut rrsig = rrsig.clone();
                                rrsig.signature = "bm90YXJlYWxycnNpZ3JlY29yZA==".to_string();
                                *record = Record::RRSIG(rrsig);
                                did_remove = true;
                            }
                        }
                    }
                    assert!(did_remove, "did not find an RRSIG covering an NSEC3 record");
                }
            },
        },
    )?;

    let mut resolver = Resolver::new(&network, root);

    let resolver = resolver
        .trust_anchor(&trust_anchor.unwrap())
        .start_with_subject(&Implementation::hickory())?;

    let client = Client::new(resolver.network())?;
    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(
        settings,
        resolver.ipv4_addr(),
        RecordType::A,
        &leaf_zone.push_label("noexist"),
    )?;

    let logs = resolver.logs()?;

    dbg!(&output);

    assert!(output.status.is_servfail());
    assert!(!logs.contains("iteration count 501 is over 500"));
    assert!(logs.contains("response does not contain NSEC or NSEC3 records."));

    Ok(())
}

pub fn insecure_record_fixture(
    query_fqdn: FQDN,
    sign_settings: SignSettings,
    custom_config: Option<String>,
) -> Result<(DigOutput, String), Error> {
    let network = Network::new()?;

    let insecure_zone = FQDN::TEST_TLD.push_label("insecure");
    let needle_fqdn = FQDN("example.insecure.testing.")?;
    let needle_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);

    let mut leaf_ns = NameServer::new(
        &Implementation::test_peer(),
        insecure_zone.clone(),
        &network,
    )?;
    leaf_ns.add(Record::a(needle_fqdn.clone(), needle_ipv4_addr));

    let mut sibling_ns =
        NameServer::new(&Implementation::test_peer(), FQDN::TEST_DOMAIN, &network)?;
    let mut tld_ns = NameServer::new(&Implementation::test_peer(), FQDN::TEST_TLD, &network)?;
    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;

    sibling_ns.add(root_ns.a());
    sibling_ns.add(tld_ns.a());
    sibling_ns.add(leaf_ns.a());
    sibling_ns.add(sibling_ns.a());

    root_ns.referral_nameserver(&tld_ns);
    tld_ns.referral_nameserver(&sibling_ns);
    tld_ns.referral_nameserver(&leaf_ns);

    let leaf_ns = leaf_ns.sign(sign_settings.clone())?;
    let sibling_ns = sibling_ns.sign(sign_settings.clone())?;

    tld_ns.add(sibling_ns.ds().ksk.clone());
    tld_ns.add(leaf_ns.ds().ksk.clone());

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
    let _leaf_ns = leaf_ns.start()?;

    let mut resolver_settings = Resolver::new(&network, root_hint);
    resolver_settings.trust_anchor(&trust_anchor);
    let resolver = if let Some(config) = custom_config {
        resolver_settings
            .custom_config(config)
            .start_with_subject(&Implementation::hickory())?
    } else {
        resolver_settings.start_with_subject(&Implementation::hickory())?
    };

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &query_fqdn)?;

    Ok((output, resolver.logs()?))
}
