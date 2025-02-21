/// These scenarios use a single test network with the following records:
///
/// example.testing:
///  www.example.testing IN A 192.0.2.1
use std::{net::Ipv4Addr, thread, time::Duration};

use dns_test::{
    FQDN, Implementation, Network, Resolver, Result,
    client::{Client, DigSettings},
    name_server::NameServer,
    record::{A, NS, Record, RecordType, SOA, SoaSettings},
    zone_file::{Root, ZoneFile},
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

    thread::sleep(Duration::from_secs(2));

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

    assert!(
        resolver
            .logs()
            .unwrap()
            .contains("recursion depth exceeded for")
    );

    Ok(())
}

/// Multi-Domain delegation
///
/// This test simulates a potentially infinite recursive delegation for the zone example.testing.
/// The TLD name server is configured with NS records:
///
///  example.testing IN NS example2.testing.
///  example2.testing IN NS example3.testing.
///  example3.testing IN NS example4.testing.
///  example4.testing IN NS example5.testing.
///  example5.testing IN NS example6.testing.
///  example6.testing IN NS example7.testing.
///  example7.testing IN NS example8.testing.
///  example8.testing IN NS example9.testing.
///  example9.testing IN NS example10.testing.
///  example10.testing IN NS example11.testing.
///  example11.testing IN NS example12.testing.
///  example12.testing IN NS example13.testing.
///  example13.testing IN NS example14.testing.
///  example14.testing IN NS example15.testing.
///  example15.testing IN NS example15.testing.
///  example15.testing IN A <NS IP>
///
/// Querying for any host in example.testing should cause the recursor to return no answer and the
/// recursor log should contain a NoConnections error.
#[test]
fn multi_domain_delegation() -> Result<()> {
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
        FQDN("ns.example2.testing.")?,
    ));

    for i in 1..=15 {
        if i == 15 {
            tld_ns.referral(
                FQDN("example15.testing.")?,
                FQDN("ns.example15.testing.")?,
                example_ns.ipv4_addr(),
            );
        } else {
            tld_ns.add(Record::ns(
                FQDN(format!("example{i}.testing."))?,
                FQDN(format!("example{}.testing.", i + 1))?,
            ));
        }

        let mut zone_file = ZoneFile::new(SOA {
            zone: FQDN(format!("example{i}.testing."))?,
            ttl: 86400,
            nameserver: FQDN(format!("ns.example{i}.testing."))?,
            admin: FQDN(format!("admin.example{i}.testing."))?,
            settings: SoaSettings::default(),
        });
        zone_file.add(Record::NS(NS {
            zone: FQDN(format!("example{i}.testing."))?,
            ttl: 86400,
            nameserver: FQDN(format!("ns.example{i}.testing."))?,
        }));
        zone_file.add(Record::A(A {
            fqdn: FQDN(format!("ns.example{i}.testing."))?,
            ipv4_addr: example_ns.ipv4_addr(),
            ttl: 86400,
        }));

        example_ns.add_zone(FQDN("domain.testing.")?, zone_file);
    }

    let root_hint: Root = root_ns.root_hint();

    let resolver =
        Resolver::new(&network, root_hint).start_with_subject(&Implementation::hickory())?;

    let client = Client::new(resolver.network())?;

    let _root_ns = root_ns.start()?;
    let _tld_ns = tld_ns.start()?;
    let _example_ns = example_ns.start()?;

    thread::sleep(Duration::from_secs(2));

    let dig_settings = *DigSettings::default().recurse();
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

    assert!(
        resolver
            .logs()
            .unwrap()
            .contains("recursion depth exceeded for")
    );

    Ok(())
}
