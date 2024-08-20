//! Test the functionality of the `do_not_query` setting on recursors.

use std::net::Ipv4Addr;

use dns_test::{
    client::{Client, DigOutput, DigSettings},
    name_server::{Graph, NameServer, Running, Sign},
    record::{Record, RecordType},
    tshark::{Capture, Direction},
    zone_file::Root,
    Implementation, Network, Resolver, Result, FQDN,
};

fn setup_two_leaf_nameservers(
    needle_fqdn: FQDN,
    needle_ip_addr: Ipv4Addr,
    implementation: Implementation,
    network: Network,
) -> Result<(Vec<NameServer<Running>>, Root, Ipv4Addr, Ipv4Addr)> {
    // set up two equivalent name servers for "example.com.", block one of them with config later
    let mut first_leaf_ns = NameServer::new(&implementation, needle_fqdn.clone(), &network)?;
    first_leaf_ns.add(Record::a(needle_fqdn.clone(), needle_ip_addr));
    let first_leaf_addr = first_leaf_ns.ipv4_addr();
    let mut second_leaf_ns = NameServer::new(&implementation, needle_fqdn.clone(), &network)?;
    second_leaf_ns.add(Record::a(needle_fqdn.clone(), needle_ip_addr));
    let second_leaf_addr = second_leaf_ns.ipv4_addr();

    let mut domain_ns = NameServer::new(&implementation, FQDN::TEST_DOMAIN, &network)?;
    let mut tld_ns = NameServer::new(&implementation, FQDN::TEST_TLD, &network)?;
    let mut root_ns = NameServer::new(&implementation, FQDN::ROOT, &network)?;

    domain_ns.add(first_leaf_ns.a());
    domain_ns.add(second_leaf_ns.a());
    domain_ns.add(tld_ns.a());
    domain_ns.add(root_ns.a());

    // add referrals from parent to child
    tld_ns.referral_nameserver(&first_leaf_ns);
    tld_ns.referral_nameserver(&second_leaf_ns);
    tld_ns.referral_nameserver(&domain_ns);
    root_ns.referral_nameserver(&tld_ns);

    let root = root_ns.root_hint();

    // start name servers
    let nameservers = vec![
        first_leaf_ns.start()?,
        second_leaf_ns.start()?,
        domain_ns.start()?,
        tld_ns.start()?,
        root_ns.start()?,
    ];

    Ok((nameservers, root, first_leaf_addr, second_leaf_addr))
}

fn run_test(
    needle_fqdn: FQDN,
    block_addr: Ipv4Addr,
    network: Network,
    root: Root,
) -> Result<(DigOutput, Vec<Capture>)> {
    // build config file
    let config = minijinja::render!(
        include_str!("do_not_query.toml.jinja"),
        do_not_query => [format!("{block_addr}/32")],
    );

    let resolver = Resolver::new(&network, root)
        .custom_config(config)
        .start_with_subject(&Implementation::hickory())?;
    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(&network)?;

    let mut tshark = resolver.eavesdrop()?;

    let dig_settings = *DigSettings::default().recurse();

    let res = client.dig(dig_settings, resolver_addr, RecordType::A, &needle_fqdn);
    dbg!(&res);
    let logs = resolver.logs()?;
    eprintln!("resolver logs:\n{logs}");
    let ans = res?;

    tshark.wait_for_capture()?;
    let captures = tshark.terminate()?;

    dbg!(captures.len());

    Ok((ans, captures))
}

#[test]
fn do_not_query_filter_first_address() -> Result<()> {
    let needle_fqdn = FQDN("example.testing.")?;
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let implementation = Implementation::test_peer();
    let network = Network::new()?;

    let (_nameservers, root, bogus_addr, leaf_addr) = setup_two_leaf_nameservers(
        needle_fqdn.clone(),
        expected_ipv4_addr,
        implementation,
        network.clone(),
    )?;

    let (ans, captures) = run_test(needle_fqdn, bogus_addr, network, root)?;

    assert!(ans.status.is_noerror());
    let [a] = ans.answer.try_into().unwrap();
    let a = a.try_into_a().unwrap();
    assert_eq!(a.ipv4_addr, expected_ipv4_addr);

    let mut leaf_query_count = 0;
    for Capture { message, direction } in captures.iter() {
        if let Direction::Outgoing { destination } = direction {
            if destination == &bogus_addr {
                panic!("sent request to server in do_not_query list\n{message:#?}\n");
            }
            if destination == &leaf_addr {
                leaf_query_count += 1;
            }
        }
    }
    assert!(
        leaf_query_count > 0,
        "did not see any queries to {leaf_addr}\n{captures:#?}\n"
    );

    Ok(())
}

#[test]
fn do_not_query_filter_second_address() -> Result<()> {
    let needle_fqdn = FQDN("example.testing.")?;
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let implementation = Implementation::test_peer();
    let network = Network::new()?;

    let (_nameservers, root, leaf_addr, bogus_addr) = setup_two_leaf_nameservers(
        needle_fqdn.clone(),
        expected_ipv4_addr,
        implementation,
        network.clone(),
    )?;

    let (ans, captures) = run_test(needle_fqdn, bogus_addr, network, root)?;

    assert!(ans.status.is_noerror());
    let [a] = ans.answer.try_into().unwrap();
    let a = a.try_into_a().unwrap();
    assert_eq!(a.ipv4_addr, expected_ipv4_addr);

    let mut leaf_query_count = 0;
    for Capture { message, direction } in captures.iter() {
        if let Direction::Outgoing { destination } = direction {
            if destination == &bogus_addr {
                panic!("sent request to server in do_not_query list\n{message:#?}\n");
            }
            if destination == &leaf_addr {
                leaf_query_count += 1;
            }
        }
    }
    assert!(
        leaf_query_count > 0,
        "did not see any queries to {leaf_addr}\n{captures:#?}\n"
    );

    Ok(())
}

#[test]
fn do_not_query_filter_only_address() -> Result<()> {
    let needle_fqdn = FQDN("example.testing.")?;
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let implementation = Implementation::test_peer();
    let network = Network::new()?;

    let mut leaf_ns = NameServer::new(&implementation, needle_fqdn.clone(), &network)?;
    leaf_ns.add(Record::a(needle_fqdn.clone(), expected_ipv4_addr));
    let leaf_addr = leaf_ns.ipv4_addr();

    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor: _trust_anchor,
    } = Graph::build(leaf_ns, Sign::No)?;

    let (ans, captures) = run_test(needle_fqdn, leaf_addr, network, root)?;

    assert!(ans.answer.is_empty());

    for Capture { message, direction } in captures.iter() {
        if let Direction::Outgoing { destination } = direction {
            if destination == &leaf_addr {
                panic!("sent request to server in do_not_query list\n{message:#?}\n");
            }
        }
    }

    Ok(())
}
