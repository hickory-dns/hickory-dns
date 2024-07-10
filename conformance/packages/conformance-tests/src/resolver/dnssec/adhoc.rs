//! sensible, ad-hoc behavior that other DNS servers implement but that do not map to a specific
//! RFC requirement

use std::net::Ipv4Addr;

use dns_test::{
    client::{Client, DigSettings},
    record::RecordType,
    Result, FQDN,
};

use super::fixtures;

#[test]
fn empty_answer_section_on_failed_dnssec_validation_and_cd_flag_unset() -> Result<()> {
    let leaf_fqdn = FQDN("example.nameservers.com.")?;
    let leaf_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);

    let (resolver, _graph) =
        fixtures::bad_signature_in_leaf_nameserver(&leaf_fqdn, leaf_ipv4_addr)?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;

    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver_addr, RecordType::A, &leaf_fqdn)?;

    assert!(output.status.is_servfail());
    assert!(!output.flags.authenticated_data);
    // the records that failed DNSSEC validation should not be returned so that the client does not
    // use them by mistake, e.g. they forget to check the status (RCODE field) and the AD flag
    assert!(output.answer.is_empty());

    Ok(())
}
