use dns_test::client::{Client, DigSettings};
use dns_test::name_server::NameServer;
use dns_test::record::{Record, RecordType};
use dns_test::zone_file::SignSettings;
use dns_test::{Network, Result, FQDN};

#[test]
#[ignore]
fn rrsig_in_answer_section() -> Result<()> {
    let network = Network::new()?;

    let ns = NameServer::new(&dns_test::SUBJECT, FQDN::ROOT, &network)?
        .sign(SignSettings::default())?
        .start()?;

    let client = Client::new(&network)?;
    let ns_fqdn = ns.fqdn();
    let ans = client.dig(
        *DigSettings::default().dnssec(),
        ns.ipv4_addr(),
        RecordType::A,
        ns_fqdn,
    )?;

    assert!(ans.status.is_noerror());
    let [a, rrsig] = ans.answer.try_into().unwrap();

    assert!(matches!(a, Record::A(..)));
    let rrsig = rrsig.try_into_rrsig().unwrap();
    assert_eq!(RecordType::A, rrsig.type_covered);
    assert_eq!(ns_fqdn, &rrsig.fqdn);

    Ok(())
}

#[test]
#[ignore]
fn rrsig_in_authority_section() -> Result<()> {
    let network = Network::new()?;

    let ns = NameServer::new(&dns_test::SUBJECT, FQDN::ROOT, &network)?
        .sign(SignSettings::default())?
        .start()?;

    let client = Client::new(&network)?;
    let ans = client.dig(
        *DigSettings::default().dnssec(),
        ns.ipv4_addr(),
        RecordType::SOA,
        &FQDN::ROOT,
    )?;

    assert!(ans.status.is_noerror());
    let [ns, rrsig] = ans.authority.try_into().unwrap();

    assert!(matches!(ns, Record::NS(..)));
    let rrsig = rrsig.try_into_rrsig().unwrap();
    assert_eq!(RecordType::NS, rrsig.type_covered);
    assert_eq!(FQDN::ROOT, rrsig.fqdn);

    Ok(())
}

// TODO Additional section
// TODO TC bit
