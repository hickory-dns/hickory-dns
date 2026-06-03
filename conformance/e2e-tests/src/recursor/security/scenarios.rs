//! These scenarios use the TestServer which returns invalid answers that should be dropped
use std::{fs, net::Ipv4Addr, thread, time::Duration};

use dns_test::{
    Error, FQDN, Implementation, Network, Resolver,
    client::{Client, DigSettings, DigStatus},
    name_server::NameServer,
    record::{Record, RecordType},
    tshark::Direction,
    zone_file::Root,
};

/// Transaction ID check - verify that Hickory will drop an invalid transaction id.
#[test]
fn tx_id_validation_test() -> Result<(), Error> {
    let target_fqdn = FQDN("www.example.testing.")?;

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(
        &Implementation::test_server("bad_txid", Vec::new(), "udp"),
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
        &Implementation::test_server("bad_case", Vec::new(), "udp"),
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
        &Implementation::test_server("bad_case", Vec::new(), "udp"),
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
        &Implementation::test_server("bailiwick", Vec::new(), "udp"),
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
        &Implementation::test_server("bailiwick", Vec::new(), "udp"),
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

#[test]
#[ignore = "hickory does not do out-of-bailiwick filtering on negative responses"]
fn nxdomain_out_of_bailiwick_rejection_authority_section() -> Result<(), Error> {
    let target_fqdn = FQDN("nxdomain-1.example.testing.")?;
    let target_out_of_bailiwick = FQDN("host.invalid.testing.")?;

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(
        &Implementation::test_server("bailiwick", Vec::new(), "udp"),
        FQDN::TEST_TLD.push_label("example"),
        &network,
    )?;

    root_ns.referral(
        leaf_ns.zone().clone(),
        FQDN("primary.tld-server.testing.")?,
        leaf_ns.ipv4_addr(),
    );

    let root_hint = root_ns.root_hint();
    let resolver =
        Resolver::new(&network, root_hint).start_with_subject(&Implementation::hickory())?;
    let client = Client::new(&network)?;

    let _root_ns = root_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;

    let settings = *DigSettings::default().recurse();
    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &target_fqdn)?;

    assert_eq!(output.status, DigStatus::NXDOMAIN);
    assert!(
        output.authority.iter().any(|record| record.is_soa()),
        "{output:?}"
    );
    assert!(
        output
            .authority
            .iter()
            .all(|record| record.name() != &target_out_of_bailiwick),
        "{output:?}"
    );

    let logs = resolver.logs()?;
    assert!(logs.contains("dropping out of bailiwick record record=host.invalid.testing."));

    Ok(())
}

#[test]
#[ignore = "hickory does not do out-of-bailiwick filtering on negative responses"]
fn nxdomain_out_of_bailiwick_rejection_soa() -> Result<(), Error> {
    let target_fqdn = FQDN("nxdomain-2.example.testing.")?;

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(
        &Implementation::test_server("bailiwick", Vec::new(), "udp"),
        FQDN::TEST_TLD.push_label("example"),
        &network,
    )?;

    root_ns.referral(
        leaf_ns.zone().clone(),
        FQDN("primary.tld-server.testing.")?,
        leaf_ns.ipv4_addr(),
    );

    let root_hint = root_ns.root_hint();
    let resolver =
        Resolver::new(&network, root_hint).start_with_subject(&Implementation::hickory())?;
    let client = Client::new(&network)?;

    let _root_ns = root_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;

    let settings = *DigSettings::default().recurse();
    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &target_fqdn)?;

    assert_eq!(output.status, DigStatus::NXDOMAIN);
    assert!(output.authority.is_empty(), "{output:?}");

    let logs = resolver.logs()?;
    assert!(logs.contains("dropping out of bailiwick SOA record record=host.invalid.testing."));

    Ok(())
}

/// Verify that Hickory rejects responses with QR=0 (Query type) over UDP
#[test]
fn qr_validation_test_udp() -> Result<(), Error> {
    qr_validation_test_impl("qr_not_response", "udp")
}

/// Verify that Hickory rejects responses with QR=0 (Query type) over TCP
#[test]
fn qr_validation_test_tcp() -> Result<(), Error> {
    qr_validation_test_impl("qr_not_response_force_tcp", "both")
}

fn qr_validation_test_impl(handler: &'static str, proto: &'static str) -> Result<(), Error> {
    let network = Network::new()?;

    let leaf_ns = NameServer::new(
        &Implementation::test_server(handler, Vec::new(), proto),
        FQDN::TEST_TLD,
        &network,
    )?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    root_ns.referral(
        FQDN::TEST_TLD,
        FQDN("primary.tld-server.testing.")?,
        leaf_ns.ipv4_addr(),
    );

    let resolver = Resolver::new(&network, root_ns.root_hint())
        .start_with_subject(&Implementation::hickory())?;

    let _root_ns = root_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;

    let res = Client::new(resolver.network())?.dig(
        *DigSettings::default().recurse().timeout(10),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN("www.example.testing.")?,
    );

    let resolver_logs = resolver.logs()?;

    match res {
        Ok(res) => {
            assert!(res.status.is_servfail());
            assert_eq!(res.answer.len(), 0);
        }
        Err(e) => panic!("unexpected error {e:?} resolver logs: {resolver_logs}"),
    }

    assert!(resolver_logs.contains("response received with incorrect QR flag"));
    Ok(())
}

/// Verify that an upstream answer containing a foreign-class record alongside a
/// legitimate IN record is rejected.
#[test]
fn foreign_class_record_rejected() -> Result<(), Error> {
    let target_fqdn = FQDN("www.example.testing.")?;

    let network = Network::new()?;

    let leaf_ns = NameServer::new(
        &Implementation::test_server("foreign_class", vec![], "udp"),
        FQDN::TEST_TLD,
        &network,
    )?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    root_ns.referral(
        FQDN::TEST_TLD,
        FQDN("primary.tld-server.testing.")?,
        leaf_ns.ipv4_addr(),
    );

    let resolver = Resolver::new(&network, root_ns.root_hint())
        .start_with_subject(&Implementation::hickory())?;

    let _root_ns = root_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;

    let res = Client::new(resolver.network())?.dig(
        *DigSettings::default().recurse().timeout(7),
        resolver.ipv4_addr(),
        RecordType::A,
        &target_fqdn,
    );

    match res {
        Ok(res) => {
            assert!(res.status.is_servfail());
            assert_eq!(res.answer.len(), 0);
        }
        Err(e) => panic!("error {e:?} resolver logs: {}", resolver.logs()?),
    }

    assert!(
        resolver
            .logs()?
            .contains("rejecting response: record class does not match query class")
    );

    Ok(())
}

/// Test mitigations for NXNSAttack-class amplification via referrall width.
///
/// A referral whose NS targets are out-of-bailiwick and have no glue causes the
/// recursor to fan out one A and one AAAA lookup per target. Without a per-delegation
/// width cap on glueless follow-up, the upstream query count to the third-party
/// authoritative scales linearly with the referral width, turning the recursor
/// into a reflection amplifier.
///
/// Topology:
///   root --> testing. (tld) --> attacker.testing. and victim.testing.
///   attacker.testing.: serves a glueless NS RRset of N targets in victim.testing.
///   victim.testing.:   authoritative; serves an A record (and NODATA for AAAA)
///                      at every nsX.victim.testing.
///
/// One client query for trap.attacker.testing. should produce at most a small,
/// constant number of nsX.victim.testing. lookups at the victim authoritative,
/// independent of the referral width.
#[test]
fn nxns_glueless_referral_width_is_capped() -> Result<(), Error> {
    const N: usize = 20;
    // Per allowed target, the recursor issues an NS lookup (zone-walk for
    // ns_pool_for_name) plus A and AAAA lookups: 3 queries per target.
    // Cap is MAX_GLUELESS_FOLLOW (5) targets * 3 queries.
    const MAX_VICTIM_QUERIES: usize = 15;

    let attacker_zone = FQDN("attacker.testing.")?;
    let victim_zone = FQDN("victim.testing.")?;
    let trap_fqdn = FQDN("trap.attacker.testing.")?;

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let mut tld_ns = NameServer::new(&Implementation::test_peer(), FQDN::TEST_TLD, &network)?;
    let mut attacker_ns = NameServer::new(
        &Implementation::test_peer(),
        attacker_zone.clone(),
        &network,
    )?;
    let mut victim_ns =
        NameServer::new(&Implementation::test_peer(), victim_zone.clone(), &network)?;

    for i in 1..=N {
        victim_ns.add(Record::a(
            FQDN(format!("ns{i}.victim.testing."))?,
            Ipv4Addr::new(192, 0, 2, (i % 254 + 1) as u8),
        ));
    }
    root_ns.referral(
        FQDN::TEST_TLD,
        FQDN("primary.tld-server.testing.")?,
        tld_ns.ipv4_addr(),
    );
    tld_ns.referral(
        attacker_zone.clone(),
        FQDN("ns.attacker.testing.")?,
        attacker_ns.ipv4_addr(),
    );
    tld_ns.referral(
        victim_zone.clone(),
        FQDN("ns.victim.testing.")?,
        victim_ns.ipv4_addr(),
    );

    // Attacker zone delegates trap.attacker.testing. to N glueless out-of-bailiwick
    // targets in victim.testing.
    for i in 1..=N {
        attacker_ns.add(Record::ns(
            trap_fqdn.clone(),
            FQDN(format!("ns{i}.victim.testing."))?,
        ));
    }

    let resolver = Resolver::new(&network, root_ns.root_hint())
        .start_with_subject(&Implementation::hickory())?;

    let _root_ns = root_ns.start()?;
    let _tld_ns = tld_ns.start()?;
    let _attacker_ns = attacker_ns.start()?;
    let victim_ns_running = victim_ns.start()?;

    thread::sleep(Duration::from_secs(2));

    // We snoop on the victim NS with tshark to quantify the reflected query volume.
    let tshark = victim_ns_running.eavesdrop_udp()?;

    let res = Client::new(resolver.network())?.dig(
        *DigSettings::default().recurse().timeout(15),
        resolver.ipv4_addr(),
        RecordType::A,
        &trap_fqdn,
    );

    // Give tshark a moment to flush its capture pipeline before we kill it.
    // Without this, the count is occasionally short by a handful of packets.
    thread::sleep(Duration::from_secs(1));

    let victim_target_hits = tshark
        .terminate()?
        .iter()
        .filter_map(|c| {
            if !matches!(c.direction, Direction::Incoming { .. }) {
                return None;
            }
            let qname = c.message.qname()?;
            let qname = qname.strip_suffix('.').unwrap_or(qname);
            (qname.starts_with("ns") && qname.ends_with(".victim.testing")).then_some(())
        })
        .count();

    match res {
        Ok(res) => assert!(
            res.status.is_servfail(),
            "expected SERVFAIL, got {:?}",
            res.status
        ),
        Err(e) => panic!("dig error {e:?} resolver logs: {}", resolver.logs()?),
    }

    assert!(
        victim_target_hits <= MAX_VICTIM_QUERIES,
        "recursor sent {victim_target_hits} nsX.victim.testing. lookups (expected <= {MAX_VICTIM_QUERIES}); referral width was {N}"
    );

    Ok(())
}

/// NXNSAttack-class amplification, in nested form.
///
/// Builds a chain of glueless wide referrals at each delegation level.
/// Without a global cap on work per req. this produces O(BRANCH^DEPTH) upstream
/// queries even when each individual level is bounded by the per-delegation
/// width cap.
///
/// Topology (BRANCH = MAX_GLUELESS_FOLLOW = 5, DEPTH = 3):
///   attacker.testing.: trap.attacker.testing. delegated to BRANCH glueless
///                      targets nX.l1.testing.
///   l1.testing.:       each nX.l1.testing. is a zone cut whose NS RRs are
///                      BRANCH glueless targets nX_Y.l2.testing.
///   l2.testing.:       each nX_Y.l2.testing. is a zone cut whose NS RRs
///                      are BRANCH glueless targets nX_Y_Z.l3.testing.
///   l3.testing.:       each nX_Y_Z.l3.testing. resolves to an A record.
///
/// Without mitigation the recursor ends up issuing roughly BRANCH^DEPTH * 3
/// upstream queries (NS + A + AAAA per L3 leaf) plus zone-walk overhead.
#[test]
fn nxns_nested_referrals_exceed_per_request_budget() -> Result<(), Error> {
    const BRANCH: usize = 5;
    // Small slack above MAX_QUERIES_PER_REQUEST = 200 to avoid flakes.
    const BUDGET_CEILING: usize = 220;

    let attacker_zone = FQDN("attacker.testing.")?;
    let l1_zone = FQDN("l1.testing.")?;
    let l2_zone = FQDN("l2.testing.")?;
    let l3_zone = FQDN("l3.testing.")?;
    let trap_fqdn = FQDN("trap.attacker.testing.")?;

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let mut tld_ns = NameServer::new(&Implementation::test_peer(), FQDN::TEST_TLD, &network)?;
    let mut attacker_ns = NameServer::new(
        &Implementation::test_peer(),
        attacker_zone.clone(),
        &network,
    )?;
    let mut l1_ns = NameServer::new(&Implementation::test_peer(), l1_zone.clone(), &network)?;
    let mut l2_ns = NameServer::new(&Implementation::test_peer(), l2_zone.clone(), &network)?;
    let mut l3_ns = NameServer::new(&Implementation::test_peer(), l3_zone.clone(), &network)?;

    root_ns.referral(
        FQDN::TEST_TLD,
        FQDN("primary.tld-server.testing.")?,
        tld_ns.ipv4_addr(),
    );
    tld_ns.referral(
        attacker_zone.clone(),
        FQDN("ns.attacker.testing.")?,
        attacker_ns.ipv4_addr(),
    );
    tld_ns.referral(l1_zone.clone(), FQDN("ns.l1.testing.")?, l1_ns.ipv4_addr());
    tld_ns.referral(l2_zone.clone(), FQDN("ns.l2.testing.")?, l2_ns.ipv4_addr());
    tld_ns.referral(l3_zone.clone(), FQDN("ns.l3.testing.")?, l3_ns.ipv4_addr());

    // attacker zone: trap.attacker.testing. delegated to BRANCH glueless L1 targets.
    for x in 1..=BRANCH {
        attacker_ns.add(Record::ns(
            trap_fqdn.clone(),
            FQDN(format!("n{x}.l1.testing."))?,
        ));
    }

    // L1 zone: each nX.l1.testing. is a zone cut with BRANCH glueless L2 NS records.
    for x in 1..=BRANCH {
        let cut = FQDN(format!("n{x}.l1.testing."))?;
        for y in 1..=BRANCH {
            l1_ns.add(Record::ns(
                cut.clone(),
                FQDN(format!("n{x}_{y}.l2.testing."))?,
            ));
        }
    }

    // L2 zone: each nX_Y.l2.testing. is a zone cut with BRANCH glueless L3 NS records.
    for x in 1..=BRANCH {
        for y in 1..=BRANCH {
            let cut = FQDN(format!("n{x}_{y}.l2.testing."))?;
            for z in 1..=BRANCH {
                l2_ns.add(Record::ns(
                    cut.clone(),
                    FQDN(format!("n{x}_{y}_{z}.l3.testing."))?,
                ));
            }
        }
    }

    // L3 zone: terminal A records. Use TEST-NET-1 so the recursor's name_server_filter
    // rejects them, producing a fast "no connections available" SERVFAIL once the
    // fan-out finishes.
    let mut idx = 1;
    for x in 1..=BRANCH {
        for y in 1..=BRANCH {
            for z in 1..=BRANCH {
                l3_ns.add(Record::a(
                    FQDN(format!("n{x}_{y}_{z}.l3.testing."))?,
                    Ipv4Addr::new(192, 0, 2, idx),
                ));
                idx = idx.wrapping_add(1);
            }
        }
    }

    let resolver = Resolver::new(&network, root_ns.root_hint())
        .start_with_subject(&Implementation::hickory())?;

    let _root_ns = root_ns.start()?;
    let _tld_ns = tld_ns.start()?;
    let _attacker_ns = attacker_ns.start()?;
    let _l1_ns = l1_ns.start()?;
    let _l2_ns = l2_ns.start()?;
    let _l3_ns = l3_ns.start()?;

    // Eavesdrop on the resolver itself to measure total upstream work.
    let tshark = resolver.eavesdrop_udp()?;

    let res = Client::new(resolver.network())?.dig(
        *DigSettings::default().recurse().timeout(60),
        resolver.ipv4_addr(),
        RecordType::A,
        &trap_fqdn,
    );

    // Give tshark a moment to flush its capture pipeline before we kill it.
    // Without this, the count is occasionally short by a handful of packets.
    thread::sleep(Duration::from_secs(1));

    let upstream_queries = tshark
        .terminate()?
        .iter()
        .filter_map(|c| {
            if !matches!(c.direction, Direction::Outgoing { .. }) {
                return None;
            }
            let qname = c.message.qname()?;
            (qname.ends_with(".testing") || qname == "testing").then_some(())
        })
        .count();

    match res {
        Ok(res) => assert!(
            res.status.is_servfail(),
            "expected SERVFAIL, got {:?}",
            res.status
        ),
        Err(e) => panic!("dig error {e:?} resolver logs: {}", resolver.logs()?),
    }

    assert!(
        upstream_queries <= BUDGET_CEILING,
        "recursor issued {upstream_queries} upstream queries for one client query (expected <= {BUDGET_CEILING})"
    );

    Ok(())
}

/// Cyclic glueless referral short-circuited by per-request in-flight zone set.
///
/// Two attacker zones each serve a glueless referral pointing at NS hostnames
/// in the peer zone. Resolving the trap name forces the recursor to descend
/// into the peer zone to resolve those NS hostnames, where it encounters the
/// mirror referral pointing back at the original zone, making a cycle.
///
/// Topology:
///   azone.testing.:  cyc.azone.testing. NS RRset -> nsN.cyc.bzone.testing.
///   bzone.testing.:  cyc.bzone.testing. NS RRset -> nsN.cyc.azone.testing.
///
/// The in-flight zone set in `RequestLimits` rejects re-entry into a zone
/// that is already on the current request's resolution stack, short-circuiting
/// the cycle before it can compound. The assertion targets this specific
/// mitigation by matching the cycle-detection log message and verifying the
/// per-request query budget did not engage.
#[test]
fn cyclic_glueless_referral_short_circuited() -> Result<(), Error> {
    // Width must equal MAX_GLUELESS_FOLLOW: smaller widths let the cycle terminate via
    // ns_recursion_limit alone.
    const W: usize = 5;

    let azone = FQDN("azone.testing.")?;
    let bzone = FQDN("bzone.testing.")?;
    let a_cut = FQDN("cyc.azone.testing.")?;
    let b_cut = FQDN("cyc.bzone.testing.")?;
    let trap_fqdn = FQDN("target.cyc.azone.testing.")?;

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let mut tld_ns = NameServer::new(&Implementation::test_peer(), FQDN::TEST_TLD, &network)?;
    let mut azone_ns = NameServer::new(&Implementation::test_peer(), azone.clone(), &network)?;
    let mut bzone_ns = NameServer::new(&Implementation::test_peer(), bzone.clone(), &network)?;

    root_ns.referral(
        FQDN::TEST_TLD,
        FQDN("primary.tld-server.testing.")?,
        tld_ns.ipv4_addr(),
    );
    tld_ns.referral(
        azone.clone(),
        FQDN("ns.azone.testing.")?,
        azone_ns.ipv4_addr(),
    );
    tld_ns.referral(
        bzone.clone(),
        FQDN("ns.bzone.testing.")?,
        bzone_ns.ipv4_addr(),
    );

    for i in 1..=W {
        azone_ns.add(Record::ns(
            a_cut.clone(),
            FQDN(format!("ns{i}.cyc.bzone.testing."))?,
        ));
        bzone_ns.add(Record::ns(
            b_cut.clone(),
            FQDN(format!("ns{i}.cyc.azone.testing."))?,
        ));
    }

    let resolver = Resolver::new(&network, root_ns.root_hint())
        .start_with_subject(&Implementation::hickory())?;

    let _root_ns = root_ns.start()?;
    let _tld_ns = tld_ns.start()?;
    let _azone_ns = azone_ns.start()?;
    let _bzone_ns = bzone_ns.start()?;

    let res = Client::new(resolver.network())?.dig(
        *DigSettings::default().recurse().timeout(30),
        resolver.ipv4_addr(),
        RecordType::A,
        &trap_fqdn,
    );

    match res {
        Ok(res) => assert!(
            res.status.is_servfail(),
            "expected SERVFAIL, got {:?}",
            res.status
        ),
        Err(e) => panic!("dig error {e:?} resolver logs: {}", resolver.logs()?),
    }

    let logs = resolver.logs()?;
    assert!(
        logs.contains("refusing to re-enter zone already on resolution stack"),
        "expected cycle-detection log line; resolver logs:\n{logs}"
    );
    assert!(
        !logs.contains("per-request query budget exceeded"),
        "in-flight zone set should have short-circuited the cycle before the per-request budget engaged; resolver logs:\n{logs}"
    );

    Ok(())
}
