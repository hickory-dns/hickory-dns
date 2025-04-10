/// These scenarios use a Dnslib-based server which returns invalid answers that should be dropped
use std::{fs, net::Ipv4Addr, thread, time::Duration};

use dns_test::{
    FQDN, Implementation, Network, Resolver, Result,
    client::{Client, DigSettings, DigStatus},
    name_server::NameServer,
    record::RecordType,
    zone_file::Root,
};

/// Transaction ID check - verify that Hickory will drop an invalidate transaction id.
#[test]
fn tx_id_validation_test() -> Result<()> {
    let target_fqdn = FQDN("www.example.testing.")?;

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(&Implementation::Dnslib, FQDN::TEST_TLD, &network)?;

    let script = fs::read_to_string("src/recursor/security/bad_txid.py")?;

    leaf_ns.cp("/script.py", &script[..])?;

    root_ns.referral(
        FQDN::TEST_TLD,
        FQDN("primary.tld-server.testing.")?,
        leaf_ns.ipv4_addr(),
    );

    let root_hint: Root = root_ns.root_hint();

    let resolver =
        Resolver::new(&network, root_hint).start_with_subject(&Implementation::hickory())?;

    let client = Client::new(resolver.network())?;

    let _root_ns = root_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;

    thread::sleep(Duration::from_secs(2));
    let a_settings = *DigSettings::default().recurse().timeout(7);
    let res = client.dig(
        a_settings,
        resolver.ipv4_addr(),
        RecordType::A,
        &target_fqdn,
    );

    match res {
        Ok(res) => {
            assert!(res.status.is_servfail());
            assert_eq!(res.answer.len(), 0);
        }
        Err(e) => panic!("error {e:?} resolver logs: {}", resolver.logs().unwrap()),
    }

    assert!(resolver.logs().unwrap().contains("expected message id:"));

    Ok(())
}

/// Check that enabling the case randomization setting causes Hickory to drop responses that do not
/// exactly preserve the QNAME.
#[test]
fn case_randomization_enabled() -> Result<()> {
    let target_fqdn = FQDN("example-123.testing.").unwrap();
    let target_fqdn_compression = FQDN("testing.testing.").unwrap();

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(&Implementation::Dnslib, FQDN::TEST_TLD, &network)?;

    let script = fs::read_to_string("src/recursor/security/bad_case.py")?;
    leaf_ns.cp("/script.py", &script[..])?;

    root_ns.referral(
        FQDN::TEST_TLD,
        FQDN("primary.tld-server.testing.")?,
        leaf_ns.ipv4_addr(),
    );

    let root_hint = root_ns.root_hint();
    let resolver = Resolver::new(&network, root_hint)
        .custom_config(fs::read_to_string(
            "src/recursor/security/case_randomization.toml",
        )?)
        .start_with_subject(&Implementation::hickory())?;
    let client = Client::new(&network)?;

    let _root_ns = root_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;

    let settings = *DigSettings::default().recurse().timeout(7);
    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &target_fqdn)?;

    assert_eq!(output.status, DigStatus::SERVFAIL);
    assert!(output.answer.is_empty());

    assert!(
        resolver
            .logs()?
            .contains("case of question section did not match")
    );

    // Repeat with a name that exercises DNS label compression.
    let output = client.dig(
        settings,
        resolver.ipv4_addr(),
        RecordType::A,
        &target_fqdn_compression,
    )?;
    assert_eq!(output.status, DigStatus::SERVFAIL);
    assert!(output.answer.is_empty());

    Ok(())
}

/// Test resolving against the same dnslib server, but without enabling the case randomization setting.
#[test]
fn case_randomization_disabled() -> Result<()> {
    let target_fqdn = FQDN("example-123.testing.").unwrap();
    let target_fqdn_compression = FQDN("testing.testing.").unwrap();

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(&Implementation::Dnslib, FQDN::TEST_TLD, &network)?;

    let script = fs::read_to_string("src/recursor/security/bad_case.py")?;
    leaf_ns.cp("/script.py", &script[..])?;

    root_ns.referral(
        FQDN::TEST_TLD,
        FQDN("primary.tld-server.testing.")?,
        leaf_ns.ipv4_addr(),
    );

    let root_hint = root_ns.root_hint();
    let resolver =
        Resolver::new(&network, root_hint).start_with_subject(&Implementation::hickory())?;
    let client = Client::new(&network)?;

    let _root_ns = root_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;

    let settings = *DigSettings::default().recurse().timeout(7);
    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &target_fqdn)?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 1);
    assert_eq!(
        output.answer[0].clone().try_into_a().unwrap().ipv4_addr,
        Ipv4Addr::new(192, 0, 2, 1)
    );

    // Repeat with a name that exercises DNS label compression.
    let output = client.dig(
        settings,
        resolver.ipv4_addr(),
        RecordType::A,
        &target_fqdn_compression,
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 1);
    assert_eq!(
        output.answer[0].clone().try_into_a().unwrap().ipv4_addr,
        Ipv4Addr::new(192, 0, 2, 1)
    );

    Ok(())
}

/// Check that enabling the case randomization setting causes Hickory to fall back to TCP when
/// talking to incompatible servers.
#[test]
fn case_randomization_tcp_fallback() -> Result<()> {
    let target_fqdn = FQDN("example-123.testing.").unwrap();

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(&Implementation::Dnslib, FQDN::TEST_TLD, &network)?;

    let script = fs::read_to_string("src/recursor/security/bad_case_with_tcp.py")?;
    leaf_ns.cp("/script.py", &script[..])?;

    root_ns.referral(
        FQDN::TEST_TLD,
        FQDN("primary.tld-server.testing.")?,
        leaf_ns.ipv4_addr(),
    );

    let root_hint = root_ns.root_hint();
    let resolver = Resolver::new(&network, root_hint)
        .custom_config(fs::read_to_string(
            "src/recursor/security/case_randomization.toml",
        )?)
        .start_with_subject(&Implementation::hickory())?;
    let client = Client::new(&network)?;

    let _root_ns = root_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;

    let settings = *DigSettings::default().recurse().timeout(7);
    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &target_fqdn)?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 1);
    // this IP is only returned over TCP, not UDP
    assert_eq!(
        output.answer[0].clone().try_into_a().unwrap().ipv4_addr,
        Ipv4Addr::new(192, 0, 2, 2)
    );

    assert!(
        resolver
            .logs()?
            .contains("case of question section did not match")
    );

    Ok(())
}
