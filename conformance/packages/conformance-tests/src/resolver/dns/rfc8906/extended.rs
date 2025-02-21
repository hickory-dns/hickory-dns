use dns_test::{
    FQDN, Result,
    client::{DigSettings, DigStatus},
    record::RecordType,
};

use super::setup;

// Note that expected flag values are different when testing recursive servers, as explained in
// section 8.
//
// * For the QUERY opcode, expect RD=1 instead of RD=0.
// * Expect AA=0 instead of AA=1.
// * If the server is validating responses, and one or both of AD=1 or DO=1 is set in the query,
//   expect AD=1 instead of AD=0.

#[test]
fn test_8_2_1_minimal_edns() -> Result<()> {
    let (_network, _graph, resolver, client) = setup()?;

    let settings = *DigSettings::default().recurse().edns(Some(0)).nocookie();
    let output = client.dig(
        settings,
        resolver.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 1);
    assert!(output.answer[0].is_soa());
    assert!(output.opt);
    assert_eq!(output.edns_version, Some(0));
    assert!(!output.flags.authoritative_answer);
    assert!(!output.flags.authenticated_data);

    Ok(())
}

#[test]
fn test_8_2_2_edns_version_negotiation() -> Result<()> {
    let (_network, _graph, resolver, client) = setup()?;

    let settings = *DigSettings::default()
        .recurse()
        .edns(Some(1))
        .nocookie()
        .noednsneg();
    let output = client.dig(
        settings,
        resolver.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::BADVERS);
    assert!(output.answer.is_empty());
    assert!(output.opt);
    assert_eq!(output.edns_version, Some(0));
    assert!(!output.flags.authoritative_answer);
    assert!(!output.flags.authenticated_data);

    Ok(())
}

#[test]
fn test_8_2_3_unknown_edns_options() -> Result<()> {
    let (_network, _graph, resolver, client) = setup()?;

    let settings = *DigSettings::default().recurse().nocookie().ednsoption(100);
    let output = client.dig(
        settings,
        resolver.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 1);
    assert!(output.answer[0].is_soa());
    assert!(output.opt);
    assert!(output.options.is_empty());
    assert_eq!(output.edns_version, Some(0));
    assert!(!output.flags.authoritative_answer);
    assert!(!output.flags.authenticated_data);

    Ok(())
}

#[test]
fn test_8_2_4_unknown_edns_flags() -> Result<()> {
    let (_network, _graph, resolver, client) = setup()?;

    let settings = *DigSettings::default()
        .recurse()
        .nocookie()
        .set_ednsflags(0x40);
    let output = client.dig(
        settings,
        resolver.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 1);
    assert!(output.answer[0].is_soa());
    assert!(output.opt);
    assert!(!output.edns_must_be_zero);
    assert_eq!(output.edns_version, Some(0));
    assert!(output.options.is_empty());
    assert!(!output.flags.authoritative_answer);
    assert!(!output.flags.authenticated_data);

    Ok(())
}

#[test]
fn test_8_2_5_edns_version_negotiation_with_unknown_edns_flags() -> Result<()> {
    let (_network, _graph, resolver, client) = setup()?;

    let settings = *DigSettings::default()
        .recurse()
        .edns(Some(1))
        .nocookie()
        .noednsneg()
        .set_ednsflags(0x40);
    let output = client.dig(
        settings,
        resolver.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::BADVERS);
    assert!(output.answer.is_empty());
    assert!(output.opt);
    assert!(!output.edns_must_be_zero);
    assert_eq!(output.edns_version, Some(0));
    assert!(!output.flags.authoritative_answer);
    assert!(!output.flags.authenticated_data);

    Ok(())
}

#[test]
fn test_8_2_6_edns_version_negotiation_with_unknown_edns_options() -> Result<()> {
    let (_network, _graph, resolver, client) = setup()?;

    let settings = *DigSettings::default()
        .recurse()
        .nocookie()
        .edns(Some(1))
        .noednsneg()
        .ednsoption(100);
    let output = client.dig(
        settings,
        resolver.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::BADVERS);
    assert!(output.answer.is_empty());
    assert!(output.opt);
    assert!(output.options.is_empty());
    assert_eq!(output.edns_version, Some(0));
    assert!(!output.flags.authoritative_answer);
    assert!(!output.flags.authenticated_data);

    Ok(())
}

#[test]
fn test_8_2_7_truncated_responses() -> Result<()> {
    let (_network, _graph, resolver, client) = setup()?;

    let settings = *DigSettings::default()
        .recurse()
        .nocookie()
        .ignore()
        .bufsize(512)
        .dnssec();
    let output = client.dig(
        settings,
        resolver.ipv4_addr(),
        RecordType::DNSKEY,
        &FQDN::TEST_DOMAIN,
    )?;

    assert!(output.flags.truncation);

    assert_eq!(output.status, DigStatus::NOERROR);
    assert!(output.opt);
    assert_eq!(output.edns_version, Some(0));

    Ok(())
}

#[test]
fn test_8_2_8_do_1() -> Result<()> {
    let (_network, _graph, resolver, client) = setup()?;

    let settings = *DigSettings::default()
        .recurse()
        .nocookie()
        .edns(Some(0))
        .dnssec();
    let output = client.dig(
        settings,
        resolver.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert!(!output.answer.is_empty());
    assert!(output.answer[0].is_soa());
    assert!(output.opt);
    assert!(output.dnssec_ok_flag);
    assert_eq!(output.edns_version, Some(0));
    assert!(!output.flags.authoritative_answer);

    Ok(())
}

#[test]
fn test_8_2_9_edns_version_negotiation_with_do_1() -> Result<()> {
    let (_network, _graph, resolver, client) = setup()?;

    let settings = *DigSettings::default()
        .recurse()
        .nocookie()
        .edns(Some(1))
        .noednsneg()
        .dnssec();
    let output = client.dig(
        settings,
        resolver.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::BADVERS);
    assert!(output.answer.is_empty());
    assert!(output.opt);
    assert!(output.dnssec_ok_flag);
    assert_eq!(output.edns_version, Some(0));
    assert!(!output.flags.authoritative_answer);

    Ok(())
}

#[test]
fn test_8_2_10_multiple_defined_edns_options() -> Result<()> {
    let (_network, _graph, resolver, client) = setup()?;

    let settings = *DigSettings::default()
        .recurse()
        .nsid()
        .expire()
        .subnet_zero();
    let output = client.dig(
        settings,
        resolver.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 1);
    assert!(output.answer[0].is_soa());
    assert!(output.opt);
    assert_eq!(output.edns_version, Some(0));
    assert!(!output.flags.authoritative_answer);
    assert!(!output.flags.authenticated_data);

    Ok(())
}
