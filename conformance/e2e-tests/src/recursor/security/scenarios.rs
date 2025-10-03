/// These scenarios use the TestServer which returns invalid answers that should be dropped
use std::{fs, net::Ipv4Addr, thread, time::Duration};

use dns_test::{
    Error, FQDN, Implementation, Network, Resolver,
    client::{Client, DigSettings, DigStatus},
    name_server::NameServer,
    record::{Record, RecordType},
    zone_file::Root,
};

/// Transaction ID check - verify that Hickory will drop an invalid transaction id.
#[test]
fn tx_id_validation_test() -> Result<(), Error> {
    let target_fqdn = FQDN("www.example.testing.")?;

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(
        &Implementation::test_server("bad_txid", "udp"),
        FQDN::TEST_TLD,
        &network,
    )?;

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
fn case_randomization_enabled() -> Result<(), Error> {
    let target_fqdn = FQDN("example-123.testing.").unwrap();
    let target_fqdn_compression = FQDN("testing.testing.").unwrap();

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(
        &Implementation::test_server("bad_case", "udp"),
        FQDN::TEST_TLD,
        &network,
    )?;

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

/// Test resolving against the same TestServer, but without enabling the case randomization setting.
#[test]
fn case_randomization_disabled() -> Result<(), Error> {
    let target_fqdn = FQDN("example-123.testing.").unwrap();
    let target_fqdn_compression = FQDN("testing.testing.").unwrap();

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(
        &Implementation::test_server("bad_case", "udp"),
        FQDN::TEST_TLD,
        &network,
    )?;

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

    println!("Resolver logs: {}", resolver.logs().unwrap());
    println!("Test server logs: {}", _leaf_ns.logs().unwrap());
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

/*
Commenting this out since it is flaky. It usually works locally but often fails in CI.
Notably, it does not always fail in CI, and ignored tests are supposed to always fail
(we check for this in our CI setup).

In my investigation, it seems that the dnslib server allows only request per TCP connection
which means the second connection to a TCP server will fail. This then triggers fallback in
the resolver name server pool which doesn't entirely make sense. It seems to vary whether
the TCP stream fails with `Busy` or `Message("stream closed")`, which we handle differently
(for what seem like good reasons).

/// Check that enabling the case randomization setting causes Hickory to fall back to TCP when
/// talking to incompatible servers.
#[test]
fn case_randomization_tcp_fallback() -> Result<(), Error> {
    let target_fqdn = FQDN("example-123.testing.").unwrap();

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(
        &Implementation::test_server("bad_case", "both"),
        FQDN::TEST_TLD,
        &network,
    )?;

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
*/

/// Test that Hickory rejects out-of-bailiwick records
#[test]
fn out_of_bailiwick_rejection() -> Result<(), Error> {
    let target_fqdn = FQDN("example-123.valid.testing.")?;
    let target_out_of_bailiwick = FQDN("host.invalid.testing.")?;

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(
        &Implementation::test_server("bailiwick", "udp"),
        FQDN::TEST_TLD.push_label("valid"),
        &network,
    )?;

    let invalid_ns = NameServer::new(
        &Implementation::test_peer(),
        FQDN::TEST_TLD.push_label("invalid"),
        &network,
    )?;

    root_ns.referral(
        FQDN::TEST_TLD.push_label("valid"),
        FQDN("primary.tld-server.testing.")?,
        leaf_ns.ipv4_addr(),
    );

    root_ns.referral(
        FQDN::TEST_TLD.push_label("invalid"),
        FQDN("primary.tld-server.invalid.")?,
        invalid_ns.ipv4_addr(),
    );

    let root_hint = root_ns.root_hint();
    let resolver =
        Resolver::new(&network, root_hint).start_with_subject(&Implementation::hickory())?;
    let client = Client::new(&network)?;

    let _root_ns = root_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;
    let _invalid_ns = invalid_ns.start()?;

    let settings = *DigSettings::default().recurse().timeout(7);
    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &target_fqdn)?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 1);
    assert_eq!(
        output.answer[0].clone().try_into_a().unwrap().ipv4_addr,
        Ipv4Addr::new(192, 0, 2, 1)
    );

    // Try to lookup the poisoned record from the cache
    let output = client.dig(
        settings,
        resolver.ipv4_addr(),
        RecordType::A,
        &target_out_of_bailiwick,
    )?;
    assert_eq!(output.status, DigStatus::NXDOMAIN);
    assert_eq!(output.answer.len(), 0);

    assert!(
        resolver
            .logs()?
            .contains("dropping out of bailiwick record record=host.invalid.testing.")
    );

    Ok(())
}

/// Test that Hickory rejects out-of-bailiwick records for records that are part of a CNAME chain
#[test]
fn cname_out_of_bailiwick_rejection() -> Result<(), Error> {
    let target_fqdn = FQDN("cname.example.testing.")?;

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(
        &Implementation::test_server("bailiwick", "udp"),
        FQDN::TEST_TLD.push_label("example"),
        &network,
    )?;

    let mut other_ns = NameServer::new(
        &Implementation::test_peer(),
        FQDN::TEST_TLD.push_label("otherdomain"),
        &network,
    )?;

    // The out-of-bailiwick record from the test server is 192.0.2.1
    other_ns.add(Record::a(
        FQDN("host.otherdomain.testing.")?,
        Ipv4Addr::new(192, 0, 2, 2),
    ));

    root_ns.referral(
        FQDN::TEST_TLD.push_label("example"),
        FQDN("primary.tld-server.testing.")?,
        leaf_ns.ipv4_addr(),
    );

    root_ns.referral(
        FQDN::TEST_TLD.push_label("otherdomain"),
        FQDN("primary.tld-server.invalid.")?,
        other_ns.ipv4_addr(),
    );

    let root_hint = root_ns.root_hint();
    let resolver =
        Resolver::new(&network, root_hint).start_with_subject(&Implementation::hickory())?;
    let client = Client::new(&network)?;

    let _root_ns = root_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;
    let _other_ns = other_ns.start()?;

    let settings = *DigSettings::default().recurse().timeout(7);
    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &target_fqdn)?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 2);
    assert_eq!(
        output.answer[1].clone().try_into_a().unwrap().ipv4_addr,
        Ipv4Addr::new(192, 0, 2, 2)
    );

    assert!(
        resolver
            .logs()?
            .contains("dropping out of bailiwick record record=host.otherdomain.testing.")
    );

    Ok(())
}
