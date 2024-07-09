//! Tests to check DNSSEC validation of the Resolver with invalid signed data.
//! According to RFC 4045 section 5.5 failed validations return `SERVFAIL` (RCODE 2) to the client.
//!
//! See RFC 4035 section 5.3.1 for more details: https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.1
//!
use std::time::{Duration, SystemTime};

use dns_test::{
    client::{Client, DigSettings},
    name_server::NameServer,
    record::RecordType,
    zone_file::SignSettings,
    Network, Resolver, Result, FQDN,
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
#[ignore]
#[test]
fn rrsig_rr_ttl_is_not_greater_than_duration_between_current_time_and_signature_expiration_timestamp(
) -> Result<()> {
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
