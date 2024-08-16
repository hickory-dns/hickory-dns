use std::time::{Duration, SystemTime};

use dns_test::client::{Client, DigSettings, ExtendedDnsError};
use dns_test::name_server::NameServer;
use dns_test::record::{Record, RecordType};
use dns_test::zone_file::SignSettings;
use dns_test::{Network, Resolver, Result, FQDN};

const ONE_DAY: Duration = Duration::from_secs(60 * 60 * 24);

#[test]
#[ignore]
fn ede_not_authoritative() -> Result<()> {
    let settings = SignSettings::default()
        .inception(SystemTime::now() - 30 * ONE_DAY)
        .expiration(SystemTime::now() - 10 * ONE_DAY);

    let network = &Network::new()?;
    let mut ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, network)?;
    ns.add(Record::txt(FQDN::COM, "Something here"));
    let ns = ns.sign(settings)?.start()?;

    let resolver = Resolver::new(network, ns.root_hint())
        .trust_anchor(ns.trust_anchor().expect("Failed to get trust anchor"))
        .extended_dns_errors()
        .start()?;

    let client = Client::new(network)?;
    let settings = *DigSettings::default().dnssec();

    let dig = client.dig(settings, resolver.ipv4_addr(), RecordType::TXT, &FQDN::COM)?;

    assert!(dig.status.is_refused());
    assert_eq!(Some(ExtendedDnsError::NotAuthoritative), dig.ede);

    Ok(())
}
