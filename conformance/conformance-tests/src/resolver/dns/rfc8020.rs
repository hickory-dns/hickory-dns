use dns_test::{
    Error, FQDN, Implementation, Network, PEER, Resolver,
    client::{Client, DigSettings, DigStatus},
    name_server::NameServer,
    record::RecordType,
};

/// See RFC 8020, "NXDOMAIN: There Really Is Nothing Underneath".
///
/// An NXDOMAIN response can carry NS records in its authority section. Those NS records are not a
/// referral to follow: nothing exists below a name that does not exist, so the resolver has to
/// answer NXDOMAIN.
///
/// Regression test for https://github.com/hickory-dns/hickory-dns/issues/3565
#[test]
fn nxdomain_with_ns_in_authority() -> Result<(), Error> {
    let cut = FQDN("nxcut.example.testing.")?;
    let needle_fqdn = FQDN("a.b.nxcut.example.testing.")?;

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&PEER, FQDN::ROOT, &network)?;

    let cut_ns = NameServer::new(
        &Implementation::test_server("nxdomain_with_ns_authority", Vec::new(), "udp"),
        cut.clone(),
        &network,
    )?;

    root_ns.referral(cut, FQDN("ns.external.testing.")?, cut_ns.ipv4_addr());

    let root_hint = root_ns.root_hint();

    let _root_ns = root_ns.start()?;
    let _cut_ns = cut_ns.start()?;

    let resolver = Resolver::new(&network, root_hint).start()?;

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse();
    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &needle_fqdn)?;

    assert_eq!(output.status, DigStatus::NXDOMAIN);

    Ok(())
}
