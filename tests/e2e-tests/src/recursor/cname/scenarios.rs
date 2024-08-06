use std::net::Ipv4Addr;
use std::thread::sleep;
use std::time::Duration;

use dns_test::{
    client::{Client, DigSettings},
    name_server::{Graph, NameServer, Sign},
    record::{Record, RecordType},
    zone_file::Root,
    Implementation, Network, Resolver, Result, FQDN,
};

/// Single level CNAME tests
///
/// For a given zone example.com with records:
///
///  www.example.com IN CNAME www2.example.com.
///  www2.example.com IN A 192.0.2.1
///
/// Querying IN A www.example.com. yields:
///  www.example.com IN CNAME www2.example.com.
///  www2.example.com IN A 192.0.2.1
///
/// Querying IN CNAME www.example.com. yields:
///  www.example.com IN CNAME www2.example.com.
#[test]
fn single_level_cname_tests() -> Result<()> {
    let cname_fqdn = FQDN("www.example.com.")?;
    let cname_target = FQDN("www2.example.com.")?;

    let target_a_fqdn = FQDN("www2.example.com.")?;
    let target_a_ipv4_addr = Ipv4Addr::new(192, 0, 2, 1);

    let network = Network::new()?;

    let mut leaf_ns = NameServer::new(&Implementation::test_peer(), FQDN("example.com.")?, &network)?;
    leaf_ns.add(Record::cname(cname_fqdn.clone(), cname_target.clone()));
    leaf_ns.add(Record::a(target_a_fqdn.clone(), target_a_ipv4_addr.clone()));

    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor: _trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::No
    )?;

    let resolver = Resolver::new(&network, root)
        .start_with_subject(&Implementation::hickory())?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;

    let a_settings = *DigSettings::default().recurse().authentic_data();
    let res = client.dig(a_settings.clone(), resolver_addr, RecordType::A, &cname_fqdn);

    if let Ok(ref res) = res {
        assert!(res.status.is_noerror());
        assert_eq!(res.answer.len(), 2);
    } else {
        panic!("Error");
    }

    for answer in res.unwrap().answer {
        match answer {
            Record::A(rec) => {
                assert_eq!(rec.fqdn, target_a_fqdn);
                assert_eq!(rec.ipv4_addr, target_a_ipv4_addr);
            }
            Record::CNAME(rec) => {
                assert_eq!(cname_target, rec.target);
                assert_eq!(cname_fqdn, rec.fqdn);
            }
            _ => panic!("Unexpected record type in response: {answer:?}"),
        }
    }

    let res = client.dig(a_settings.clone(), resolver_addr, RecordType::CNAME, &cname_fqdn);

    if let Ok(ref res) = res {
        assert!(res.status.is_noerror());
        assert_eq!(res.answer.len(), 1);
    } else {
        panic!("Error");
    }

    match res.unwrap().answer.get(0).unwrap() {
        Record::CNAME(cname) => {
            assert_eq!(cname.fqdn, cname_fqdn);
            assert_eq!(cname.target, cname_target);
        }
        _ => { panic!("Unexpected record type"); }
    }

    let res = resolver.terminate();
    assert!(res.is_ok(), "server process not found");

    let logs = res.unwrap();
    assert!(!logs.contains("stack overflow"));

    Ok(())
}

/// Multi level CNAME tests
///
/// For given zones {example.com,example2.com,example3.com} with records:
///
///  example.com:
///   two.example.com.    IN CNAME two.example2.com.
///   three.example.com.  IN CNAME three.example2.com.
///
///  example2.com:
///   two.example2.com.   IN A     192.0.2.2
///   three.example2.com. IN CNAME three.example3.com.
///
///  example3.com:
///   three.example3.com. IN A     192.0.2.3
///
/// Querying IN A two.example.com. yields:
///  two.example.com IN CNAME two.example2.com.
///  two.example2.com IN A 192.0.2.2
///
/// Querying IN A three.example.com. yields:
///  three.example.com IN CNAME three.example2.com.
///  three.example2.com IN CNAME three.example3.com.
///  three.example3.com IN A 192.0.2.3
///
/// Querying IN A three.example2.com. yields:
///  three.example2.com IN CNAME three.example3.com.
///  three.example3.com IN A 192.0.2.3
///
/// Querying IN CNAME two.example.com. yields:
///  two.example.com IN CNAME two.example2.com.
///
/// Querying IN CNAME three.example.com. yields:
///  three.example.com IN CNAME three.example2.com.
///
/// Querying IN CNAME two.example2.com. yields NXDOMAIN
#[test]
fn multi_level_cname_tests() -> Result<()> {
    let example_two_fqdn = FQDN("two.example.com.")?;
    let example_two_target = FQDN("two.example2.com.")?;
    let example_three_fqdn = FQDN("three.example.com.")?;
    let example_three_target = FQDN("three.example2.com.")?;

    let example2_two_fqdn = FQDN("two.example2.com.")?;
    let example2_two_ipv4 = Ipv4Addr::new(192, 0, 2, 2);
    let example2_three_fqdn = FQDN("three.example2.com.")?;
    let example2_three_target = FQDN("three.example3.com.")?;

    let example3_three_fqdn = FQDN("three.example3.com.")?;
    let example3_three_ipv4 = Ipv4Addr::new(192, 0, 2, 3);

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let mut com_ns  = NameServer::new(&Implementation::test_peer(), FQDN::COM, &network)?;

    let mut leaf_example_ns = NameServer::new(&Implementation::test_peer(), FQDN("example.com.")?, &network)?;
    leaf_example_ns.add(Record::cname(example_two_fqdn.clone(), example_two_target.clone()));
    leaf_example_ns.add(Record::cname(example_three_fqdn.clone(), example_three_target.clone()));

    let mut leaf_example2_ns = NameServer::new(&Implementation::test_peer(), FQDN("example2.com.")?, &network)?;
    leaf_example2_ns.add(Record::a(example2_two_fqdn.clone(), example2_two_ipv4.clone()));
    leaf_example2_ns.add(Record::cname(example2_three_fqdn.clone(), example2_three_target.clone()));

    let mut leaf_example3_ns = NameServer::new(&Implementation::test_peer(), FQDN("example3.com.")?, &network)?;
    leaf_example3_ns.add(Record::a(example3_three_fqdn.clone(), example3_three_ipv4.clone()));

    root_ns.referral(FQDN::COM, FQDN("primary.tld-server.com.")?, com_ns.ipv4_addr());
    com_ns.referral(FQDN("example.com.")?, FQDN("ns.example.com.")?, leaf_example_ns.ipv4_addr());
    com_ns.referral(FQDN("example2.com.")?, FQDN("ns.example2.com.")?, leaf_example2_ns.ipv4_addr());
    com_ns.referral(FQDN("example3.com.")?, FQDN("ns.example3.com.")?, leaf_example3_ns.ipv4_addr());

    let mut root_hint: Root = root_ns.root_hint();
    let mut ns_running = vec![];
    for ns in [root_ns, com_ns, leaf_example_ns, leaf_example2_ns, leaf_example3_ns] {
        match ns.start() {
            Ok(ns) => {
                println!("Starting {}", ns.zone());
                if *ns.zone() == FQDN::ROOT {
                    println!("Resetting root hint");
                    root_hint = ns.root_hint();
                }
                ns_running.push(ns);
            }
            Err(e) => {
                panic!("ERROR Starting NS: {e:?}");
            }
        }
    }

    let resolver = Resolver::new(&network, root_hint)
        .start_with_subject(&Implementation::hickory())?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;

    let a_settings = *DigSettings::default().recurse().authentic_data();

    let res = client.dig(a_settings, resolver_addr, RecordType::A, &example_two_fqdn);
    if let Ok(ref res) = res {
        assert!(res.status.is_noerror());
        assert_eq!(res.answer.len(), 2);
    } else {
        panic!("Error");
    }

    for answer in res.unwrap().answer {
        match answer {
            Record::A(rec) => {
                assert_eq!(rec.fqdn, example2_two_fqdn);
                assert_eq!(rec.ipv4_addr, example2_two_ipv4);
            }
            Record::CNAME(rec) => {
                assert_eq!(example_two_target, rec.target);
                assert_eq!(example_two_fqdn, rec.fqdn);
            }
            _ => panic!("Unexpected record type in response: {answer:?}"),
        }
    }

    let res = client.dig(a_settings, resolver_addr, RecordType::A, &example_three_fqdn);

    if let Ok(ref res) = res {
        assert!(res.status.is_noerror());
        assert_eq!(res.answer.len(), 3);
    } else {
        panic!("Error");
    }

    for answer in res.unwrap().answer {
        match answer {
            Record::A(rec) => {
                assert_eq!(rec.fqdn, example3_three_fqdn);
                assert_eq!(rec.ipv4_addr, example3_three_ipv4);
            }
            Record::CNAME(rec) => {
                if rec.fqdn == example_three_fqdn {
                    assert_eq!(example_three_target, rec.target);
                    assert_eq!(example_three_fqdn, rec.fqdn);
                } else if rec.fqdn == example2_three_fqdn {
                    assert_eq!(example2_three_target, rec.target);
                    assert_eq!(example2_three_fqdn, rec.fqdn);
                } else {
                    panic!("Unexpected FQDN in CNAME: {}", rec.fqdn);
                }
            }
            _ => panic!("Unexpected record type in response: {answer:?}"),
        }
    }

    let res = client.dig(a_settings, resolver_addr, RecordType::A, &example2_three_fqdn);
    if let Ok(ref res) = res {
        assert!(res.status.is_noerror());
        assert_eq!(res.answer.len(), 2);
    } else {
        panic!("Error");
    }

    for answer in res.unwrap().answer {
        match answer {
            Record::A(rec) => {
                assert_eq!(rec.fqdn, example3_three_fqdn);
                assert_eq!(rec.ipv4_addr, example3_three_ipv4);
            }
            Record::CNAME(rec) => {
                assert_eq!(example2_three_target, rec.target);
                assert_eq!(example2_three_fqdn, rec.fqdn);
            }
            _ => panic!("Unexpected record type in response: {answer:?}"),
        }
    }

    let res = client.dig(a_settings, resolver_addr, RecordType::CNAME, &example_three_fqdn);
    if let Ok(ref res) = res {
        assert!(res.status.is_noerror());
        assert_eq!(res.answer.len(), 1);
    } else {
        panic!("Error");
    }

    match res.unwrap().answer.get(0).unwrap() {
        Record::CNAME(rec) => {
            assert_eq!(example_three_target, rec.target);
            assert_eq!(example_three_fqdn, rec.fqdn);
        }
        _ => { panic!("Unexpected record type in response"); }
    }

    let res = client.dig(a_settings, resolver_addr, RecordType::CNAME, &example_two_fqdn);
    if let Ok(ref res) = res {
        assert!(res.status.is_noerror());
        assert_eq!(res.answer.len(), 1);
    } else {
        panic!("Error");
    }

    match res.unwrap().answer.get(0).unwrap() {
        Record::CNAME(rec) => {
            assert_eq!(example_two_target, rec.target);
            assert_eq!(example_two_fqdn, rec.fqdn);
        }
        _ => { panic!("Unexpected record type in response"); }
    }

    let res = client.dig(a_settings, resolver_addr, RecordType::CNAME, &example2_two_fqdn);
    if let Ok(ref res) = res {
        assert!(res.status.is_nxdomain());
        assert_eq!(res.answer.len(), 0);
    } else {
        panic!("Error");
    }

    let res = resolver.terminate();
    assert!(res.is_ok(), "server process not found");

    let logs = res.unwrap();
    assert!(!logs.contains("stack overflow"));

    Ok(())
}
