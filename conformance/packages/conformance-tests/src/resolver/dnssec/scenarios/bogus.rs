use std::net::Ipv4Addr;

use dns_test::client::{Client, DigSettings};
use dns_test::record::RecordType;
use dns_test::{Result, FQDN};

use crate::resolver::dnssec::fixtures;

#[test]
fn if_cd_bit_is_clear_and_data_is_not_authentic_then_respond_with_servfail() -> Result<()> {
    let needle_fqdn = FQDN("example.nameservers.com.")?;
    let needle_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);

    let (resolver, _graph) =
        fixtures::bad_signature_in_leaf_nameserver(&needle_fqdn, needle_ipv4_addr)?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;

    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver_addr, RecordType::A, &needle_fqdn)?;

    assert!(output.status.is_servfail());

    Ok(())
}
