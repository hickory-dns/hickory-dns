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
