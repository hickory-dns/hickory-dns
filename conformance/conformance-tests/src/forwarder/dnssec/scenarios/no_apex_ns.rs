use std::net::Ipv4Addr;

use dns_test::{
    Error, FQDN, Forwarder, Implementation, Network, PEER, Resolver,
    client::{Client, DigSettings, DigStatus},
    name_server::NameServer,
    record::{Record, RecordType},
    zone_file::SignSettings,
};

/// The child zone has no NS records at its apex. An NS query for the apex gets a NODATA response
/// with the zone's SOA record, while the signed parent zone delegates to it with a secure proof
/// that there is no DS record. Answers from the child zone must validate as insecure.
///
/// Regression test for <https://github.com/hickory-dns/hickory-dns/issues/4027>.
#[test]
fn insecure_delegation_without_apex_ns() -> Result<(), Error> {
    let network = Network::new()?;
    let child_zone = FQDN::TEST_TLD.push_label("child");
    let record_name = child_zone.push_label("record");
    let expected_ipv4_addr = Ipv4Addr::new(192, 168, 0, 1);

    let mut child_ns = NameServer::new(&PEER, child_zone.clone(), &network)?;
    child_ns.add(Record::a(record_name.clone(), expected_ipv4_addr));

    // The proxy name server name is out of zone, so the resolver can only learn its address from
    // the root zone, and never talks to the real child name server directly.
    let proxy_ns = NameServer::builder(
        Implementation::test_server(
            "no_apex_ns",
            vec![child_ns.ipv4_addr().to_string(), child_zone.to_string()],
            "both",
        ),
        child_zone.clone(),
        network.clone(),
    )
    .nameserver_fqdn(FQDN("ns1.")?)
    .build()?;

    let mut tld_ns = NameServer::new(&PEER, FQDN::TEST_TLD, &network)?;
    tld_ns.add(Record::ns(child_zone, proxy_ns.fqdn().clone()));
    let tld_ns = tld_ns.sign(SignSettings::default())?;

    let mut root_ns = NameServer::new(&PEER, FQDN::ROOT, &network)?;
    root_ns.referral_nameserver(&tld_ns);
    root_ns.add(tld_ns.ds().ksk.clone());
    root_ns.add(Record::a(proxy_ns.fqdn().clone(), proxy_ns.ipv4_addr()));
    let root_ns = root_ns.sign(SignSettings::default())?;
    let root_hint = root_ns.root_hint();
    let trust_anchor = root_ns.trust_anchor();

    let _child_ns = child_ns.start()?;
    let _proxy_ns = proxy_ns.start()?;
    let _tld_ns = tld_ns.start()?;
    let _root_ns = root_ns.start()?;

    let resolver = Resolver::new(&network, root_hint).start_with_subject(&PEER)?;
    let forwarder = Forwarder::new(&network, &resolver)
        .trust_anchor(&trust_anchor)
        .start()?;
    let client = Client::new(&network)?;

    let settings = *DigSettings::default().recurse().dnssec().authentic_data();
    let output = client.dig(settings, forwarder.ipv4_addr(), RecordType::A, &record_name)?;

    assert_eq!(output.status, DigStatus::NOERROR, "{output:?}");
    assert!(!output.flags.authenticated_data, "{output:?}");
    assert!(
        output.answer.iter().any(|record| {
            record
                .clone()
                .try_into_a()
                .is_ok_and(|a| a.ipv4_addr == expected_ipv4_addr)
        }),
        "unexpected response: {output:?}"
    );

    Ok(())
}
