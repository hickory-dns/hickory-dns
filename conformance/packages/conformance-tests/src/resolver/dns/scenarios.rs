use std::net::Ipv4Addr;

use dns_test::client::{Client, DigSettings};
use dns_test::name_server::{Graph, NameServer, Sign};
use dns_test::record::{Record, RecordType};
use dns_test::tshark::{Capture, Direction};
use dns_test::{FQDN, Network, Resolver, Result};

mod bad_referral;
mod packet_loss;

#[test]
fn can_resolve() -> Result<()> {
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let needle_fqdn = FQDN::EXAMPLE_SUBDOMAIN;

    let network = Network::new()?;

    let mut leaf_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_DOMAIN, &network)?;
    leaf_ns.add(Record::a(needle_fqdn.clone(), expected_ipv4_addr));

    let Graph {
        nameservers: _nameservers,
        root,
        ..
    } = Graph::build(leaf_ns, Sign::No)?;

    let resolver = Resolver::new(&network, root).start()?;
    let resolver_ip_addr = resolver.ipv4_addr();

    let client = Client::new(&network)?;

    let settings = *DigSettings::default().recurse();
    let output = client.dig(settings, resolver_ip_addr, RecordType::A, &needle_fqdn)?;

    assert!(output.status.is_noerror());

    let [answer] = output.answer.try_into().unwrap();
    let a = answer.try_into_a().unwrap();

    assert_eq!(needle_fqdn, a.fqdn);
    assert_eq!(expected_ipv4_addr, a.ipv4_addr);

    Ok(())
}

#[test]
fn nxdomain() -> Result<()> {
    let needle_fqdn = FQDN::TEST_DOMAIN.push_label("unicorn");

    let network = Network::new()?;

    let leaf_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_DOMAIN, &network)?;

    let Graph {
        nameservers: _nameservers,
        root,
        ..
    } = Graph::build(leaf_ns, Sign::No)?;

    let resolver = Resolver::new(&network, root).start()?;
    let resolver_ip_addr = resolver.ipv4_addr();

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse();
    let output = client.dig(settings, resolver_ip_addr, RecordType::A, &needle_fqdn)?;

    assert!(dbg!(output).status.is_nxdomain());

    Ok(())
}

#[test]
fn recursion_desired_flag() -> Result<()> {
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let needle_fqdn = FQDN::EXAMPLE_SUBDOMAIN;

    let network = Network::new()?;

    let mut leaf_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_DOMAIN, &network)?;
    leaf_ns.add(Record::a(needle_fqdn.clone(), expected_ipv4_addr));

    let Graph {
        nameservers, root, ..
    } = Graph::build(leaf_ns, Sign::No)?;

    let resolver = Resolver::new(&network, root).start()?;
    let resolver_ip_addr = resolver.ipv4_addr();

    let client = Client::new(&network)?;

    let mut tshark = resolver.eavesdrop()?;

    let settings = *DigSettings::default().recurse();
    let output = client.dig(settings, resolver_ip_addr, RecordType::A, &needle_fqdn)?;

    assert!(output.status.is_noerror());

    let [answer] = output.answer.try_into().unwrap();
    let a = answer.try_into_a().unwrap();

    assert_eq!(needle_fqdn, a.fqdn);
    assert_eq!(expected_ipv4_addr, a.ipv4_addr);

    tshark.wait_for_capture()?;
    let captures = tshark.terminate()?;

    // Query from client to resolver should have RD=1.
    // Queries from resolver to nameservers should have RD=0.
    let mut seen_incoming_query = false;
    let mut seen_outgoing_query = false;
    for Capture { message, direction } in captures.iter() {
        match direction {
            Direction::Incoming { source } if *source == client.ipv4_addr() => {
                seen_incoming_query = true;
                assert!(message.is_rd_flag_set(), "{message:#?}");
            }
            Direction::Outgoing { destination }
                if nameservers.iter().any(|ns| *destination == ns.ipv4_addr()) =>
            {
                seen_outgoing_query = true;
                assert!(!message.is_rd_flag_set(), "{message:#?}");
            }
            _ => {}
        }
    }
    assert!(seen_incoming_query, "{captures:#?}");
    assert!(seen_outgoing_query, "{captures:#?}");

    Ok(())
}
