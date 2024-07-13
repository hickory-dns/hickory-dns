mod section_3_2_2;

use dns_test::{
    client::{Client, DigSettings},
    name_server::NameServer,
    record::{Record, RecordType},
    tshark::{Capture, Direction},
    zone_file::SignSettings,
    Network, Resolver, Result, FQDN,
};

#[test]
fn do_bit_not_set_in_request() -> Result<()> {
    let network = &Network::new()?;
    let ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, network)?
        .sign(SignSettings::default())?
        .start()?;
    let resolver = Resolver::new(network, ns.root_hint()).start()?;

    let mut tshark = resolver.eavesdrop()?;

    let client = Client::new(network)?;
    let settings = *DigSettings::default().recurse();
    let ans = client.dig(settings, resolver.ipv4_addr(), RecordType::SOA, &FQDN::ROOT)?;

    // "the name server side MUST strip any authenticating DNSSEC RRs from the response"
    let [answer] = ans.answer.try_into().unwrap();

    assert!(matches!(answer, Record::SOA(_)));

    tshark.wait_for_capture()?;

    let captures = tshark.terminate()?;

    let ns_addr = ns.ipv4_addr();
    for Capture { message, direction } in captures {
        if let Direction::Outgoing { destination } = direction {
            if destination == client.ipv4_addr() {
                continue;
            }

            // sanity check
            assert_eq!(ns_addr, destination);

            //  "The resolver side of a security-aware recursive name server MUST set the DO bit
            //  when sending requests"
            if destination == ns_addr {
                assert_eq!(Some(true), message.is_do_bit_set());
            }
        }
    }

    Ok(())
}

// this ensures that even in the presence of a cached (answer+rrsig) we strip the dnssec records as
// per the RFC
#[test]
fn on_do_0_query_strips_dnssec_records_even_if_it_cached_a_previous_do_1_query() -> Result<()> {
    let network = &Network::new()?;
    let ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, network)?
        .sign(SignSettings::default())?
        .start()?;
    let resolver = Resolver::new(network, ns.root_hint()).start()?;

    let client = Client::new(network)?;
    let settings = *DigSettings::default().dnssec().recurse();
    let resolver_addr = resolver.ipv4_addr();
    let ans = client.dig(settings, resolver_addr, RecordType::SOA, &FQDN::ROOT)?;

    let [answer, rrsig] = ans.answer.try_into().unwrap();

    assert!(matches!(answer, Record::SOA(_)));
    assert!(matches!(rrsig, Record::RRSIG(_)));

    let settings = *DigSettings::default().recurse();
    let ans = client.dig(settings, resolver_addr, RecordType::SOA, &FQDN::ROOT)?;

    let [answer] = ans.answer.try_into().unwrap();

    assert!(matches!(answer, Record::SOA(_)));

    Ok(())
}

// this ensures that in the presence of a cached entry (answer), the dnssec records (answer+rrsig) are still
// returned as per the RFC
#[test]
fn on_do_1_query_return_dnssec_records_even_if_it_cached_a_previous_do_0_query() -> Result<()> {
    let network = &Network::new()?;
    let ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, network)?
        .sign(SignSettings::default())?
        .start()?;
    let resolver = Resolver::new(network, ns.root_hint()).start()?;

    let client = Client::new(network)?;
    let settings = *DigSettings::default().recurse();
    let resolver_addr = resolver.ipv4_addr();
    let ans = client.dig(settings, resolver_addr, RecordType::SOA, &FQDN::ROOT)?;

    let [answer] = ans.answer.try_into().unwrap();

    assert!(matches!(answer, Record::SOA(_)));

    let settings = *DigSettings::default().dnssec().recurse();
    let ans = client.dig(settings, resolver_addr, RecordType::SOA, &FQDN::ROOT)?;

    let [answer, rrsig] = ans.answer.try_into().unwrap();

    assert!(matches!(answer, Record::SOA(_)));
    assert!(matches!(rrsig, Record::RRSIG(_)));

    Ok(())
}

#[test]
fn if_do_bit_not_set_in_request_then_requested_dnssec_record_is_not_stripped() -> Result<()> {
    let network = &Network::new()?;
    let ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, network)?
        .sign(SignSettings::default())?
        .start()?;
    let resolver = Resolver::new(network, ns.root_hint()).start()?;

    let client = Client::new(network)?;
    let settings = *DigSettings::default().recurse();
    let ans = client.dig(
        settings,
        resolver.ipv4_addr(),
        RecordType::DNSKEY,
        &FQDN::ROOT,
    )?;

    // "MUST NOT strip any DNSSEC RR types that the initiating query explicitly requested"
    for record in &ans.answer {
        assert!(matches!(record, Record::DNSKEY(_)))
    }

    Ok(())
}

#[test]
fn do_bit_set_in_request() -> Result<()> {
    let network = &Network::new()?;
    let ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, network)?
        .sign(SignSettings::default())?
        .start()?;
    let resolver = Resolver::new(network, ns.root_hint()).start()?;

    let mut tshark = resolver.eavesdrop()?;

    let client = Client::new(network)?;
    let settings = *DigSettings::default().dnssec().recurse();
    let ans = client.dig(settings, resolver.ipv4_addr(), RecordType::SOA, &FQDN::ROOT)?;

    let [answer, rrsig] = ans.answer.try_into().unwrap();

    assert!(matches!(answer, Record::SOA(_)));
    assert!(matches!(rrsig, Record::RRSIG(_)));

    tshark.wait_for_capture()?;

    let captures = tshark.terminate()?;

    let ns_addr = ns.ipv4_addr();
    for Capture { message, direction } in captures {
        if let Direction::Outgoing { destination } = direction {
            if destination == client.ipv4_addr() {
                continue;
            }

            // sanity check
            assert_eq!(ns_addr, destination);

            //  "The resolver side of a security-aware recursive name server MUST set the DO bit
            //  when sending requests"
            if destination == ns_addr {
                assert_eq!(Some(true), message.is_do_bit_set());
            }
        }
    }

    Ok(())
}
