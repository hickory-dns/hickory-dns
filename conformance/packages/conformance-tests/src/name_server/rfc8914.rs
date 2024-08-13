use std::net::Ipv4Addr;

use dns_test::client::{Client, DigSettings, ExtendedDnsError};
use dns_test::name_server::NameServer;
use dns_test::record::RecordType;
use dns_test::zone_file::SignSettings;
use dns_test::{Network, Result, FQDN};

#[test]
#[ignore]
fn ede_not_authoritative() -> Result<()> {
    // TODO remove these
    let fqdns = (0u8..=32)
        .map(|label| {
            FQDN(format!(
                "{0}abcdefghijklmnopqrstuvwxyz.nameservers.com.",
                label
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    // main name server, add referals to other (non-existent) nameservers
    let origin_fqdn = FQDN::NAMESERVERS;
    let network = Network::new()?;
    let mut ns = NameServer::new(&dns_test::SUBJECT, origin_fqdn.clone(), &network)?;
    fqdns.iter().for_each(|fqdn| {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        ns.referral(origin_fqdn.clone(), fqdn.clone(), ip);
    });

    let ns = ns.sign(SignSettings::default())?.start()?;

    let client = Client::new(&network)?;

    // fetch ALL records for zone '.'
    let answer = client.dig(
        *DigSettings::default().dnssec(),
        ns.ipv4_addr(),
        RecordType::SOA,
        &FQDN::ROOT,
    )?;

    assert_eq!(Some(ExtendedDnsError::NotAuhoritative), answer.ede);

    Ok(())
}
