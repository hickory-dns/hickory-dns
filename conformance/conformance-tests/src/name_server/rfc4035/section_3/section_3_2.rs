use dns_test::client::{Client, DigSettings};
use dns_test::name_server::NameServer;
use dns_test::record::RecordType;
use dns_test::zone_file::SignSettings;
use dns_test::{Error, FQDN, Network};

/// RFC 4035 section 3.2.1: DNSSEC OK (DO) Bit
///
/// "The DO bit MUST be clear unless the requester can handle DNSSEC records.
/// If the requester sets the DO bit, it indicates that the requester
/// supports DNSSEC and wants to receive DNSSEC records in the response."
///
/// Test that the DO bit is correctly preserved from request to response.
/// The server should echo back the DO bit value from the request.

#[test]
fn do_bit_not_set_in_request() -> Result<(), Error> {
    let network = Network::new()?;

    let ns = NameServer::new(&dns_test::SUBJECT, FQDN::ROOT, &network)?
        .sign(SignSettings::default())?
        .start()?;

    let client = Client::new(&network)?;

    // Query WITHOUT DO bit set
    let settings = DigSettings::default();
    let ans = client.dig(
        settings,
        ns.ipv4_addr(),
        RecordType::A,
        ns.fqdn(),
    )?;

    assert!(ans.status.is_noerror());

    // The response should NOT have the DO bit set since the request didn't have it
    assert!(!ans.dnssec_ok_flag,
        "Server should not set DO=1 in response when client sent DO=0");

    Ok(())
}

#[test]
fn do_bit_set_in_request() -> Result<(), Error> {
    let network = Network::new()?;

    let ns = NameServer::new(&dns_test::SUBJECT, FQDN::ROOT, &network)?
        .sign(SignSettings::default())?
        .start()?;

    let client = Client::new(&network)?;

    // Query WITH DO bit set
    let settings = *DigSettings::default().dnssec();
    let ans = client.dig(
        settings,
        ns.ipv4_addr(),
        RecordType::A,
        ns.fqdn(),
    )?;

    assert!(ans.status.is_noerror());

    // The response SHOULD have the DO bit set since the request had it
    assert!(ans.dnssec_ok_flag,
        "Server should set DO=1 in response when client sent DO=1");

    Ok(())
}
