use dns_test::{
    FQDN, Result,
    client::{DigSettings, DigStatus},
    record::RecordType,
};

use crate::name_server::rfc8906::setup;

#[test]
fn test_8_1_1_zone_configured() -> Result<()> {
    let (_network, ns, client) = setup()?;

    let settings = *DigSettings::default().edns(None);
    let output = client.dig(
        settings,
        ns.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 1);
    assert!(output.answer[0].is_soa());
    assert!(output.flags.authoritative_answer);
    assert!(!output.flags.recursion_desired);
    assert!(!output.flags.authenticated_data);
    assert!(!output.opt);

    Ok(())
}

#[test]
fn test_8_1_2_unknown_types() -> Result<()> {
    let (_network, ns, client) = setup()?;

    let settings = *DigSettings::default().edns(None);
    let output = client.dig(
        settings,
        ns.ipv4_addr(),
        RecordType::Unknown(1000),
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert!(output.answer.is_empty());
    assert!(output.flags.authoritative_answer);
    assert!(!output.flags.recursion_desired);
    assert!(!output.flags.authenticated_data);
    assert!(!output.opt);

    Ok(())
}

#[test]
fn test_8_1_3_1_header_bits_cd_1() -> Result<()> {
    let (_network, ns, client) = setup()?;

    let settings = *DigSettings::default().edns(None).checking_disabled();
    let output = client.dig(
        settings,
        ns.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 1);
    assert!(output.answer[0].is_soa());
    assert!(output.flags.authoritative_answer);
    assert!(!output.flags.recursion_desired);
    assert!(!output.flags.authenticated_data);
    assert!(!output.opt);

    Ok(())
}

#[test]
fn test_8_1_3_2_header_bits_ad_1() -> Result<()> {
    let (_network, ns, client) = setup()?;

    let settings = *DigSettings::default().edns(None).authentic_data();
    let output = client.dig(
        settings,
        ns.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 1);
    assert!(output.answer[0].is_soa());
    assert!(output.flags.authoritative_answer);
    assert!(!output.flags.recursion_desired);
    assert!(!output.opt);

    Ok(())
}

#[test]
fn test_8_1_3_3_header_bits_reserved() -> Result<()> {
    let (_network, ns, client) = setup()?;

    let settings = *DigSettings::default().edns(None).set_z_flag();
    let output = client.dig(
        settings,
        ns.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 1);
    assert!(output.answer[0].is_soa());
    assert!(!output.must_be_zero);
    assert!(output.flags.authoritative_answer);
    assert!(!output.flags.recursion_desired);
    assert!(!output.flags.authenticated_data);
    assert!(!output.opt);

    Ok(())
}

#[test]
fn test_8_1_3_4_header_bits_recursive_query() -> Result<()> {
    let (_network, ns, client) = setup()?;

    let settings = *DigSettings::default().edns(None).recurse();
    let output = client.dig(
        settings,
        ns.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 1);
    assert!(output.answer[0].is_soa());
    assert!(output.flags.authoritative_answer);
    assert!(output.flags.recursion_desired);
    assert!(!output.flags.authenticated_data);
    assert!(!output.opt);

    Ok(())
}

#[test]
fn test_8_1_4_unknown_opcodes() -> Result<()> {
    let (_network, ns, client) = setup()?;

    let settings = *DigSettings::default().edns(None).opcode(15).header_only();
    let output = client.dig(
        settings,
        ns.ipv4_addr(),
        RecordType::SOA, // The type will be ignored, since we are specifying +header-only.
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::NOTIMP);
    assert_eq!(output.opcode, "RESERVED15");
    assert!(output.answer.is_empty());
    assert!(output.authority.is_empty());
    assert!(output.additional.is_empty());
    assert!(!output.flags.authoritative_answer);
    assert!(!output.flags.recursion_desired);
    assert!(!output.flags.authenticated_data);
    assert!(!output.opt);

    Ok(())
}

/// This is a variant of test 8.1.4 with +noheader-only.
#[test]
fn test_unknown_opcode_with_query() -> Result<()> {
    let (_network, ns, client) = setup()?;

    let settings = *DigSettings::default().edns(None).opcode(15);
    let output = client.dig(
        settings,
        ns.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::NOTIMP);
    assert_eq!(output.opcode, "RESERVED15");
    assert!(output.answer.is_empty());
    assert!(output.authority.is_empty());
    assert!(output.additional.is_empty());
    assert!(!output.flags.authoritative_answer);
    assert!(!output.flags.recursion_desired);
    assert!(!output.flags.authenticated_data);
    assert!(!output.opt);

    Ok(())
}

#[test]
fn test_8_1_5_tcp() -> Result<()> {
    let (_network, ns, client) = setup()?;

    let settings = *DigSettings::default().edns(None).tcp();
    let output = client.dig(
        settings,
        ns.ipv4_addr(),
        RecordType::SOA,
        &FQDN::TEST_DOMAIN,
    )?;

    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 1);
    assert!(output.answer[0].is_soa());
    assert!(output.flags.authoritative_answer);
    assert!(!output.flags.recursion_desired);
    assert!(!output.flags.authenticated_data);
    assert!(!output.opt);

    Ok(())
}
