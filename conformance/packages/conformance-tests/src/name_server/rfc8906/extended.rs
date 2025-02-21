use dns_test::{
    FQDN, Result,
    client::{DigSettings, DigStatus},
    record::RecordType,
};

use crate::name_server::rfc8906::setup;

#[test]
fn test_8_2_1_minimal_edns() -> Result<()> {
    let (_network, ns, client) = setup()?;

    let settings = *DigSettings::default().edns(Some(0)).nocookie();
    let output = client.dig(
        settings,
        ns.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 1);
    assert!(output.answer[0].is_soa());
    assert!(output.opt);
    assert_eq!(output.edns_version, Some(0));
    assert!(output.flags.authoritative_answer);
    assert!(!output.flags.authenticated_data);

    Ok(())
}

#[test]
fn test_8_2_2_edns_version_negotiation() -> Result<()> {
    let (_network, ns, client) = setup()?;

    let settings = *DigSettings::default().edns(Some(1)).nocookie().noednsneg();
    let output = client.dig(
        settings,
        ns.ipv4_addr(),
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
    let (_network, ns, client) = setup()?;

    let settings = *DigSettings::default().nocookie().ednsoption(100);
    let output = client.dig(
        settings,
        ns.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 1);
    assert!(output.answer[0].is_soa());
    assert!(output.opt);
    assert!(output.options.is_empty());
    assert_eq!(output.edns_version, Some(0));
    assert!(output.flags.authoritative_answer);
    assert!(!output.flags.authenticated_data);

    Ok(())
}

#[test]
fn test_8_2_4_unknown_edns_flags() -> Result<()> {
    let (_network, ns, client) = setup()?;

    let settings = *DigSettings::default().nocookie().set_ednsflags(0x40);
    let output = client.dig(
        settings,
        ns.ipv4_addr(),
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
    assert!(output.flags.authoritative_answer);
    assert!(!output.flags.authenticated_data);

    Ok(())
}

#[test]
fn test_8_2_5_edns_version_negotiation_with_unknown_edns_flags() -> Result<()> {
    let (_network, ns, client) = setup()?;

    let settings = *DigSettings::default()
        .nocookie()
        .edns(Some(1))
        .noednsneg()
        .set_ednsflags(0x40);
    let output = client.dig(
        settings,
        ns.ipv4_addr(),
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
    let (_network, ns, client) = setup()?;

    let settings = *DigSettings::default()
        .nocookie()
        .edns(Some(1))
        .noednsneg()
        .ednsoption(100);
    let output = client.dig(
        settings,
        ns.ipv4_addr(),
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
    let (_network, ns, client) = setup()?;

    let settings = *DigSettings::default()
        .nocookie()
        .ignore()
        .bufsize(512)
        .dnssec();
    let output = client.dig(
        settings,
        ns.ipv4_addr(),
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
    let (_network, ns, client) = setup()?;

    let settings = *DigSettings::default().nocookie().edns(Some(0)).dnssec();
    let output = client.dig(
        settings,
        ns.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert!(!output.answer.is_empty());
    assert!(output.answer[0].is_soa());
    assert!(output.opt);
    assert!(output.dnssec_ok_flag);
    assert_eq!(output.edns_version, Some(0));
    assert!(output.flags.authoritative_answer);

    Ok(())
}

#[test]
fn test_8_2_9_edns_version_negotiation_with_do_1() -> Result<()> {
    let (_network, ns, client) = setup()?;

    let settings = *DigSettings::default()
        .nocookie()
        .edns(Some(1))
        .noednsneg()
        .dnssec();
    let output = client.dig(
        settings,
        ns.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::BADVERS);
    assert!(output.answer.is_empty());
    assert!(output.opt);
    if !dns_test::SUBJECT.is_unbound() {
        // unbound does not set DO=1 in the BADVERS response
        assert!(output.dnssec_ok_flag);
    }
    assert_eq!(output.edns_version, Some(0));
    assert!(!output.flags.authoritative_answer);

    Ok(())
}

#[test]
fn test_8_2_10_multiple_defined_edns_options() -> Result<()> {
    let (_network, ns, client) = setup()?;

    let settings = *DigSettings::default().nsid().expire().subnet_zero();
    let output = client.dig(
        settings,
        ns.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 1);
    assert!(output.answer[0].is_soa());
    assert!(output.opt);
    assert_eq!(output.edns_version, Some(0));
    assert!(output.flags.authoritative_answer);
    assert!(!output.flags.authenticated_data);

    Ok(())
}
