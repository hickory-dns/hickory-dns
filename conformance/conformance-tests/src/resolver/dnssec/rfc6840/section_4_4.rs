//! These tests check if resolvers correctly validate insecure delegation proofs.
//!
//! When determining that a delegation is insecure, validation must check for proof that a
//! delegation is present, or could be present, in addition to checking that no DS record is
//! present.
//!
//! > 4.4.  Insecure Delegation Proofs
//! >
//! >    Section 5.2 of \[RFC4035\] specifies that a validator, when proving a
//! >    delegation is not secure, needs to check for the absence of the DS
//! >    and SOA bits in the NSEC (or NSEC3) type bitmap.  The validator also
//! >    MUST check for the presence of the NS bit in the matching NSEC (or
//! >    NSEC3) RR (proving that there is, indeed, a delegation), or
//! >    alternately make sure that the delegation is covered by an NSEC3 RR
//! >    with the Opt-Out flag set.
//! >
//! >    Without this check, an attacker could reuse an NSEC or NSEC3 RR
//! >    matching a non-delegation name to spoof an unsigned delegation at
//! >    that name.  This would claim that an existing signed RRset (or set of
//! >    signed RRsets) is below an unsigned delegation, thus not signed and
//! >    vulnerable to further attack.
//!
//! These tests use a proxy server sitting in front of an authoritative server. The proxy injects NS
//! records and tampers with the header to turn negative responses into referral responses, as per
//! the second paragraph above.

use std::net::Ipv4Addr;

use dns_test::{
    Error, FQDN, Implementation, Network, PEER, Resolver,
    client::{Client, DigOutput, DigSettings, DigStatus},
    name_server::NameServer,
    record::{Record, RecordType},
    zone_file::{Nsec, SignSettings},
};

#[test]
fn forged_delegation_over_nxdomain_nsec() -> Result<(), Error> {
    let output = forged_delegation_test(
        FQDN("name-doesnt-exist.testing.")?,
        SignSettings::default().nsec(Nsec::_1),
    )?;
    assert_eq!(output.status, DigStatus::SERVFAIL, "{output:?}");
    Ok(())
}

#[test]
fn forged_delegation_over_nodata_nsec() -> Result<(), Error> {
    let output = forged_delegation_test(
        FQDN("name-exists.testing.")?,
        SignSettings::default().nsec(Nsec::_1),
    )?;
    assert_eq!(output.status, DigStatus::SERVFAIL, "{output:?}");
    Ok(())
}

#[test]
fn forged_delegation_over_nxdomain_nsec3() -> Result<(), Error> {
    let output = forged_delegation_test(
        FQDN("name-doesnt-exist.testing.")?,
        SignSettings::default().nsec(Nsec::_3 {
            iterations: 1,
            opt_out: false,
            salt: None,
        }),
    )?;
    assert_eq!(output.status, DigStatus::SERVFAIL, "{output:?}");
    Ok(())
}

#[test]
fn forged_delegation_over_nodata_nsec3() -> Result<(), Error> {
    let output = forged_delegation_test(
        FQDN("name-exists.testing.")?,
        SignSettings::default().nsec(Nsec::_3 {
            iterations: 1,
            opt_out: false,
            salt: None,
        }),
    )?;
    assert_eq!(output.status, DigStatus::SERVFAIL, "{output:?}");
    Ok(())
}

/// In this test, the forged delegation falls within a range covered by an opt out NSEC3 record, so
/// the validator cannot tell the difference between a real and forged insecure delegation.
#[test]
fn forged_delegation_over_nxdomain_nsec3_optout() -> Result<(), Error> {
    let output = forged_delegation_test(
        FQDN("name-doesnt-exist.testing.")?,
        SignSettings::ecdsap256sha256_nsec3_optout().nsec(Nsec::_3 {
            iterations: 1,
            opt_out: true,
            salt: None,
        }),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR, "{output:?}");
    assert!(!output.flags.authenticated_data, "{output:?}");
    assert!(
        output.answer.iter().any(|record| {
            record
                .clone()
                .try_into_a()
                .is_ok_and(|a| a.ipv4_addr == Ipv4Addr::new(192, 168, 0, 1))
        }),
        "unexpected response: {output:?}"
    );
    Ok(())
}

fn forged_delegation_test(
    delegation_name: FQDN,
    sign_settings: SignSettings,
) -> Result<DigOutput, Error> {
    let network = Network::new()?;
    let query_name = delegation_name.push_label("record");

    // Some of these nameservers have domain names that are out-of-zone, so that we don't have to
    // deal with glue records in the proxy as it forges referral responses, or respond to queries
    // for nameserver address records.
    let mut child_ns = NameServer::builder(PEER.clone(), delegation_name.clone(), network.clone())
        .nameserver_fqdn(FQDN("ns2.")?)
        .build()?;
    child_ns.add(Record::a(query_name.clone(), Ipv4Addr::new(192, 168, 0, 1)));

    let mut honest_ns = NameServer::new(&PEER, FQDN::TEST_TLD, &network)?;
    honest_ns.add(Record::a(
        FQDN("name-exists.testing.")?,
        Ipv4Addr::new(192, 168, 0, 1),
    ));
    let honest_ns = honest_ns.sign(sign_settings)?;
    let proxy_ns = NameServer::builder(
        Implementation::test_server(
            "forged_delegation",
            vec![
                honest_ns.ipv4_addr().to_string(),
                delegation_name.to_string(),
                child_ns.fqdn().to_string(),
            ],
            "both",
        ),
        honest_ns.zone().clone(),
        network.clone(),
    )
    .nameserver_fqdn(FQDN("ns1.")?)
    .build()?;

    let mut root_ns = NameServer::new(&PEER, FQDN::ROOT, &network)?;
    root_ns.add(Record::ns(proxy_ns.zone().clone(), proxy_ns.fqdn().clone()));
    root_ns.add(honest_ns.ds().ksk.clone());
    root_ns.add(Record::a(proxy_ns.fqdn().clone(), proxy_ns.ipv4_addr()));
    root_ns.add(Record::a(child_ns.fqdn().clone(), child_ns.ipv4_addr()));

    let root_ns = root_ns.sign(SignSettings::default())?;
    let trust_anchor = root_ns.trust_anchor();
    let hint = root_ns.root_hint();

    let _root_ns = root_ns.start()?;
    let _honest_ns = honest_ns.start()?;
    let _proxy_ns = proxy_ns.start()?;
    let _child_ns = child_ns.start()?;

    let client = Client::new(&network)?;
    let resolver = Resolver::new(&network, hint)
        .trust_anchor(&trust_anchor)
        .start()?;
    let dig_settings = *DigSettings::default().recurse().dnssec().authentic_data();
    let response = client.dig(
        dig_settings,
        resolver.ipv4_addr(),
        RecordType::A,
        &query_name,
    )?;
    Ok(response)
}
