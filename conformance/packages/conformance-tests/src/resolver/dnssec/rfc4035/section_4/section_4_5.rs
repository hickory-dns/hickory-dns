use std::net::Ipv4Addr;

use dns_test::{
    client::{Client, DigSettings},
    name_server::NameServer,
    record::{Record, RecordType},
    tshark::Capture,
    zone_file::SignSettings,
    Network, Resolver, Result, FQDN,
};

use crate::resolver::dnssec::fixtures;

/// Two queries are sent with DNSSEC enabled, the second query should take the answer from the cache.
#[test]
fn caches_dnssec_records() -> Result<()> {
    let network = &Network::new()?;
    let ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, network)?
        .sign(SignSettings::default())?
        .start()?;
    let resolver = Resolver::new(network, ns.root_hint()).start()?;

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

/// Two queries are sent, the first without DNSSEC enabled is put into the cache, the second query with
/// DNSSEC enabled will fetch its result from the cache
#[test]
fn caches_query_without_dnssec_to_return_all_dnssec_records_in_subsequent_query() -> Result<()> {
    let network = &Network::new()?;
    let ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, network)?
        .sign(SignSettings::default())?
        .start()?;
    let resolver = Resolver::new(network, ns.root_hint()).start()?;

    let client = Client::new(network)?;

    // send first query without DNSSEC, fills cache
    let settings = *DigSettings::default().recurse();
    let dig = client.dig(settings, resolver.ipv4_addr(), RecordType::SOA, &FQDN::ROOT)?;
    assert!(dig.status.is_noerror());

    // send second query to fetch all DNSSEC records
    let mut tshark = resolver.eavesdrop()?;
    let settings = *DigSettings::default().dnssec().recurse();
    let dig = client.dig(settings, resolver.ipv4_addr(), RecordType::SOA, &FQDN::ROOT)?;
    assert!(dig.status.is_noerror());

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

/// The chain of trust used to validate `A example.nameservers.com.` includes records within the
/// `nameservers.com.`, `com.` and `.` domains. Those records should be cached in the "Secure"
/// cache as part of the validation of `A example.com.`.
///
/// Therefore, a second query for a record like `DS com.` should be a cache hit.
#[test]
fn caches_intermediate_records() -> Result<()> {
    let leaf_fqdn = FQDN("example.nameservers.com.")?;
    let leaf_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let (resolver, nameservers, _trust_anchor) =
        fixtures::minimally_secure(leaf_fqdn.clone(), leaf_ipv4_addr)?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;
    let settings = *DigSettings::default().recurse().authentic_data();

    let output = client.dig(settings, resolver_addr, RecordType::A, &leaf_fqdn)?;

    assert!(output.status.is_noerror());
    assert!(output.flags.authenticated_data);

    let [a] = output.answer.try_into().unwrap();
    let a = a.try_into_a().unwrap();

    assert_eq!(leaf_fqdn, a.fqdn);
    assert_eq!(leaf_ipv4_addr, a.ipv4_addr);

    let mut tshark = resolver.eavesdrop()?;

    let output = client.dig(settings, resolver_addr, RecordType::DS, &FQDN::COM)?;

    assert!(output.status.is_noerror());
    assert!(output.flags.authenticated_data);

    tshark.wait_for_capture()?;
    let captures = tshark.terminate()?;

    let ns_addrs = nameservers
        .iter()
        .map(|ns| ns.ipv4_addr())
        .collect::<Vec<_>>();
    for Capture { direction, .. } in captures {
        assert!(!ns_addrs.contains(&direction.peer_addr()));
    }

    Ok(())
}

// TODO check expiration case
