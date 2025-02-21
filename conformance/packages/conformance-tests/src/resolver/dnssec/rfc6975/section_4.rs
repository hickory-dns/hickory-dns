use dns_test::{
    FQDN, Network, Resolver, Result,
    client::{Client, DigSettings},
    name_server::{Graph, NameServer, Sign},
    record::RecordType,
    zone_file::SignSettings,
};

/// Section 4.2.1, last paragraph, says "Validating recursive resolvers MUST NOT set the DAU, DHU,
/// and/or N3U option(s) in the final response to the stub client."
#[test]
fn no_understood_options_in_response() -> Result<()> {
    let network = Network::new()?;

    let leaf_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_DOMAIN, &network)?;

    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::Yes {
            settings: SignSettings::default(),
        },
    )?;

    let trust_anchor = trust_anchor.unwrap();
    let resolver = Resolver::new(&network, root)
        .trust_anchor(&trust_anchor)
        .start()?;
    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse();
    let output = client.dig(settings, resolver_addr, RecordType::SOA, &FQDN::TEST_DOMAIN)?;

    assert!(output.status.is_noerror());
    // Disallow DAU, DHU, and N3U.
    assert!(
        output
            .options
            .iter()
            .all(|(option_number, _)| *option_number != 5
                && *option_number != 6
                && *option_number != 7),
        "{:?}",
        output.options
    );

    Ok(())
}
