use dns_test::{
    client::{Client, DigSettings},
    name_server::NameServer,
    record::{Record, RecordType},
    tshark::Capture,
    Network, Resolver, Result, FQDN,
};

#[test]
fn caches_dnssec_records() -> Result<()> {
    let network = &Network::new()?;
    let ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, network)?
        .sign()?
        .start()?;
    let resolver = Resolver::new(network, ns.root_hint()).start(&dns_test::SUBJECT)?;

    let client = Client::new(network)?;
    let settings = *DigSettings::default().dnssec().recurse();

    // query twice; eavesdrop second query
    let mut tshark = None;
    for i in 0..2 {
        if i == 1 {
            tshark = Some(resolver.eavesdrop()?);
        }

        let ans = client.dig(settings, resolver.ipv4_addr(), RecordType::SOA, &FQDN::ROOT)?;
        let [answer, rrsig] = ans.answer.try_into().unwrap();

        assert!(matches!(answer, Record::SOA(_)));
        assert!(matches!(rrsig, Record::RRSIG(_)));
    }

    let mut tshark = tshark.unwrap();
    tshark.wait_for_capture()?;

    let captures = tshark.terminate()?;

    // second query is cached so no communication between the resolver and the nameserver is
    // expected
    let ns_addr = ns.ipv4_addr();
    for Capture { direction, .. } in captures {
        assert_ne!(ns_addr, direction.peer_addr());
    }

    Ok(())
}

// TODO check expiration case
