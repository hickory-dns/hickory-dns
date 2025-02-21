//! Tests to check DNSSEC validation of the Resolver with invalid signed data.
//! According to RFC 4045 section 5.5 failed validations return `SERVFAIL` (RCODE 2) to the client.
//!
//! See RFC 4035 section 5.3.1 for more details: https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.1
//!
use std::time::{Duration, SystemTime};

use dns_test::{
    FQDN, Network, Resolver, Result,
    client::{Client, DigSettings},
    name_server::NameServer,
    record::{RRSIG, RecordType, SOA},
    zone_file::SignSettings,
};

const ONE_HOUR: Duration = Duration::from_secs(60 * 60);

/// Check that inception > current_time results in an invalid response.
#[test]
fn rrsig_rr_inception_time_is_set_in_the_future() -> Result<()> {
    // `unbound` allows a skew / delta around inception time in `val-sig-skew-min` option
    let inception = SystemTime::now() + 4 * ONE_HOUR;
    let expiration = SystemTime::now() + 10 * ONE_HOUR;
    let settings = SignSettings::default()
        .inception(inception)
        .expiration(expiration);

    // Configure nameserver & sign zonefile
    let network = &Network::new()?;
    let ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, network)?
        .sign(settings)?
        .start()?;

    // Set up Resolver with DNSSEC enabled
    let resolver = Resolver::new(network, ns.root_hint())
        .trust_anchor(ns.trust_anchor().expect("Failed to get trust anchor"))
        .start()?;

    let client = Client::new(network)?;
    let settings = *DigSettings::default().recurse();

    let dig = client.dig(settings, resolver.ipv4_addr(), RecordType::SOA, &FQDN::ROOT)?;

    // validation should fail
    assert!(dig.status.is_servfail());

    Ok(())
}

/// Check that expiration timestamp < current_time results in an invalid lookup.
#[test]
fn rrsig_rr_expiration_time_is_before_current_time() -> Result<()> {
    let expiration = SystemTime::now() - 4 * ONE_HOUR;
    let inception = SystemTime::now() - 10 * ONE_HOUR;

    let settings = SignSettings::default()
        .expiration(expiration)
        .inception(inception);

    // Configure nameserver & sign zonefile
    let network = &Network::new()?;
    let ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, network)?
        .sign(settings)?
        .start()?;

    // Set up Resolver with DNSSEC enabled
    let resolver = Resolver::new(network, ns.root_hint())
        .trust_anchor(ns.trust_anchor().expect("Failed to get trust anchor"))
        .start()?;

    let client = Client::new(network)?;
    let settings = *DigSettings::default().recurse();

    let dig = client.dig(settings, resolver.ipv4_addr(), RecordType::SOA, &FQDN::ROOT)?;

    // validation should fail
    assert!(dig.status.is_servfail());

    Ok(())
}

/// Check that the validating resolver sets the TTL to a value between "now" and expiration time.
/// See Github issue: https://github.com/hickory-dns/hickory-dns/issues/2292
#[test]
fn rrsig_rr_ttl_is_not_greater_than_duration_between_current_time_and_signature_expiration_timestamp()
-> Result<()> {
    let ttl_delta = 4 * ONE_HOUR;
    let settings = SignSettings::default().expiration(SystemTime::now() + ttl_delta);

    let network = &Network::new()?;
    let ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, network)?
        .sign(settings)?
        .start()?;

    let resolver = Resolver::new(network, ns.root_hint())
        .trust_anchor(ns.trust_anchor().expect("Failed to get trust anchor"))
        .start()?;

    let client = Client::new(network)?;
    let settings = *DigSettings::default().recurse();

    let dig = client.dig(settings, resolver.ipv4_addr(), RecordType::SOA, &FQDN::ROOT)?;
    assert!(dig.status.is_noerror());

    let [answer] = dig.answer.try_into().unwrap();
    assert!(answer.is_soa());

    // get TTL from record
    let soa_ttl = answer.try_into_soa().unwrap().ttl as u64;

    assert!(soa_ttl <= ttl_delta.as_secs());

    Ok(())
}

/// Check that both RRSIG and RR use the same TTL, section 5.3.3 of RFC 4035 defines conditions how to adjust the TTL
/// while section 2.2 states "The RRSIG RR's TTL is equal to the TTL of the RRset."
#[test]
fn rrsig_and_rr_return_the_same_adjusted_ttl() -> Result<()> {
    let ttl_delta = 4 * ONE_HOUR;
    let settings = SignSettings::default().expiration(SystemTime::now() + ttl_delta);

    let network = &Network::new()?;
    let ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, network)?
        .sign(settings)?
        .start()?;

    let resolver = Resolver::new(network, ns.root_hint())
        .trust_anchor(ns.trust_anchor().expect("Failed to get trust anchor"))
        .start()?;

    // Fetch RRSIG + RR
    let client = Client::new(network)?;
    let settings = *DigSettings::default().dnssec().recurse();

    let resolver_addr = resolver.ipv4_addr();
    let dig = client.dig(settings, resolver_addr, RecordType::SOA, &FQDN::ROOT)?;

    assert!(dig.status.is_noerror());

    let [soa, rrsig] = dig.answer.try_into().unwrap();
    let soa: SOA = soa.try_into_soa().unwrap();
    let rrsig: RRSIG = rrsig.try_into_rrsig().unwrap();

    assert_eq!(soa.ttl, rrsig.ttl);
    assert!(soa.ttl <= ttl_delta.as_secs() as u32);

    Ok(())
}

/// Check that Serial Number arithemtics support the case where the timesamp is `1 << 31` beyond UNIX_EPOCH.
#[test]
fn rrsig_rr_expiration_time_is_1_to_the_power_of_31_beyond_unix_epoch() -> Result<()> {
    // The representation in the record uses format `YYYYMMDDhhmmss`
    const MAX_UNIX_TIMESTAMP: u64 = 20380119031408;

    let settings = SignSettings::default().expiration_from_u64(1 << 31);

    let network = &Network::new()?;
    let ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, network)?
        .sign(settings)?
        .start()?;

    let resolver = Resolver::new(network, ns.root_hint())
        .trust_anchor(ns.trust_anchor().expect("Failed to get trust anchor"))
        .start()?;

    // Fetch RRSIG + RR
    let client = Client::new(network)?;
    let settings = *DigSettings::default().dnssec().recurse();

    let resolver_addr = resolver.ipv4_addr();
    let dig = client.dig(settings, resolver_addr, RecordType::SOA, &FQDN::ROOT)?;

    // Validation should succeed
    assert!(dig.status.is_noerror());

    let [soa, rrsig] = dig.answer.try_into().unwrap();
    let soa: SOA = soa.try_into_soa().unwrap();
    let rrsig: RRSIG = rrsig.try_into_rrsig().unwrap();

    assert_eq!(soa.ttl, rrsig.ttl);
    assert_eq!(MAX_UNIX_TIMESTAMP, rrsig.signature_expiration);

    Ok(())
}

/// Check that Serial Number arithmetics invalidate the case where the timestamp is `1 << 32` beyond UNIX_EPOCH.
#[test]
fn rrsig_rr_expiration_time_is_1_to_the_power_of_32_beyond_unix_epoch() -> Result<()> {
    let settings = SignSettings::default();

    let network = &Network::new()?;
    let mut ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, network)?.sign(settings)?;

    // `1 << 32` from Unix Epoch results in Sunday, February 7, 2106 6:28:16 AM
    if let Some(rrsig) = ns.signed_zone_file_mut().rrsig_mut(RecordType::SOA) {
        rrsig.signature_expiration = 21060207062816;
    }

    let ns = ns.start()?;

    let resolver = Resolver::new(network, ns.root_hint())
        .trust_anchor(ns.trust_anchor().expect("Failed to get trust anchor"))
        .start()?;

    // Fetch RRSIG + RR
    let client = Client::new(network)?;
    let settings = *DigSettings::default().dnssec().recurse();

    let resolver_addr = resolver.ipv4_addr();
    let dig = client.dig(settings, resolver_addr, RecordType::SOA, &FQDN::ROOT)?;

    // Validation should fail
    assert!(dig.status.is_servfail());

    Ok(())
}
