/// These scenarios use a single test network with the following records:
///
/// example.testing:
///  www.example.testing IN A 192.0.2.1
use std::net::Ipv4Addr;

use dns_test::{
    client::{Client, DigSettings},
    name_server::NameServer,
    record::{Record, RecordType},
    zone_file::Root,
    Implementation, Network, Resolver, Result, FQDN,
};

/// Recursive Delegation
///
/// This test simulates a potentially infinite recursive delegation for the zone example.testing.
/// The TLD name server is configured with NS records:
///
///  example.testing IN NS example2.testing.
///  example2.testing IN NS example.testing.
///
/// Querying for any host in example.testing should cause the recursor to return no answer and the
/// recursor log should contain a NoConnections error.
#[test]
fn recursive_delegation() -> Result<()> {
    let target_fqdn = FQDN("www.example.testing.")?;
    let target_ipv4 = Ipv4Addr::new(192, 0, 2, 1);

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let mut tld_ns = NameServer::new(&Implementation::test_peer(), FQDN::TEST_TLD, &network)?;

    let mut example_ns = NameServer::new(
        &Implementation::test_peer(),
        FQDN("example.testing.")?,
        &network,
    )?;

    example_ns.add(Record::a(target_fqdn.clone(), target_ipv4));

    root_ns.referral(
        FQDN::TEST_TLD,
        FQDN("primary.tld-server.testing.")?,
        tld_ns.ipv4_addr(),
    );

    tld_ns.add(Record::ns(
        FQDN("example.testing.")?,
        FQDN("example2.testing.")?,
    ));
    tld_ns.add(Record::ns(
        FQDN("example2.testing.")?,
        FQDN("example.testing.")?,
    ));

    let root_hint: Root = root_ns.root_hint();

    let resolver =
        Resolver::new(&network, root_hint).start_with_subject(&Implementation::hickory())?;

    let client = Client::new(resolver.network())?;

    let _root_ns = root_ns.start()?;
    let _tld_ns = tld_ns.start()?;
    let _example_ns = example_ns.start()?;

    let dig_settings = *DigSettings::default().recurse().authentic_data();
    let res = client.dig(
        dig_settings,
        resolver.ipv4_addr(),
        RecordType::A,
        &target_fqdn,
    );

    if let Ok(res) = &res {
        assert!(res.status.is_servfail());
        assert_eq!(res.answer.len(), 0);
    } else {
        panic!("error");
    }

    assert!(resolver.logs().unwrap().contains(
        "error resolving RecursiveError(Error { kind: Proto(ProtoError { kind: NoConnections }"
    ));

    Ok(())
}
