use dns_test::client::{Client, DigSettings};
use dns_test::name_server::NameServer;
use dns_test::record::RecordType;
use dns_test::{Network, Result, FQDN};

#[test]
fn authoritative_answer() -> Result<()> {
    let network = &Network::new()?;
    let ns = NameServer::new(&dns_test::SUBJECT, FQDN::ROOT, network)?.start()?;

    let client = Client::new(network)?;
    let ans = client.dig(
        DigSettings::default(),
        ns.ipv4_addr(),
        RecordType::SOA,
        &FQDN::ROOT,
    )?;

    assert!(ans.status.is_noerror());
    assert!(ans.flags.authoritative_answer);

    Ok(())
}
