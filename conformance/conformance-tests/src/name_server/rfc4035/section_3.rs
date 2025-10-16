use std::net::Ipv4Addr;

use dns_test::{
    Error, FQDN, Network, SUBJECT,
    client::{Client, DigSettings},
    name_server::NameServer,
    record::{A, RecordType},
    zone_file::SignSettings,
};

mod section_3_1;

#[test]
fn rrsig_ttl() -> Result<(), Error> {
    let network = Network::new()?;

    let mut ns = NameServer::new(&SUBJECT, FQDN::ROOT, &network)?;
    let zone_a_record = A {
        fqdn: FQDN::TEST_TLD,
        ttl: 120,
        ipv4_addr: Ipv4Addr::BROADCAST,
    };
    ns.add(zone_a_record.clone());
    let ns = ns.sign(SignSettings::default())?.start()?;

    let zone_soa_record = ns.zone_file().soa.clone();

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().dnssec();
    let a_response = client.dig(settings, ns.ipv4_addr(), RecordType::A, &FQDN::TEST_TLD)?;
    let Some(a_record) = a_response
        .answer
        .iter()
        .filter_map(|record| record.clone().try_into_a().ok())
        .next()
    else {
        panic!("No A record in response {a_response:?}");
    };
    assert_eq!(a_record.ttl, zone_a_record.ttl);
    let Some(rrsig_record) = a_response
        .answer
        .iter()
        .filter_map(|record| record.clone().try_into_rrsig().ok())
        .find(|rrsig| rrsig.type_covered == RecordType::A)
    else {
        panic!("No RRSIG record in response {a_response:?}");
    };
    assert_eq!(rrsig_record.ttl, zone_a_record.ttl);

    let nodata_response = client.dig(settings, ns.ipv4_addr(), RecordType::MX, &FQDN::TEST_TLD)?;
    let Some(nsec3_record) = nodata_response
        .authority
        .iter()
        .filter_map(|record| record.clone().try_into_nsec3().ok())
        .next()
    else {
        panic!("No NSEC3 record in response {nodata_response:?}");
    };
    assert_eq!(nsec3_record.ttl, zone_soa_record.settings.minimum);
    let Some(rrsig_record) = nodata_response
        .authority
        .iter()
        .filter_map(|record| record.clone().try_into_rrsig().ok())
        .find(|rrsig| rrsig.type_covered == RecordType::NSEC3)
    else {
        panic!("No RRSIG record in response {nodata_response:?}");
    };
    assert_eq!(rrsig_record.ttl, zone_soa_record.settings.minimum);

    Ok(())
}
