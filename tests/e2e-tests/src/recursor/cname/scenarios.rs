use std::net::Ipv4Addr;
use std::time::Duration;
use std::thread::sleep;

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

    let root_hint: Root = root_ns.root_hint();
    let mut ns_running = vec![];
    for ns in [root_ns, com_ns, leaf_example_ns, leaf_example2_ns, leaf_example3_ns] {
        match ns.start() {
            Ok(ns) => {
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
        // FIXME: Need NXDOMAIN error propagation for this to work.
        //assert!(res.status.is_nxdomain());
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

/// Recursion Depth Limit Check
///
/// For given zones {example.com, example2.com, .. example13.com} with records:
///
/// example.com:
///  www.example.com IN CNAME www2.example2.com.
/// example2.com:
///  www2.example2.com IN CNAME www3.example3.com.
/// example3.com:
///  www3.example3.com IN CNAME www4.example4.com.
/// example4.com:
///  www4.example4.com IN CNAME www5.example5.com.
/// example5.com:
///  www5.example5.com IN CNAME www6.example6.com.
/// example6.com:
///  www6.example6.com IN CNAME www7.example7.com.
/// example7.com:
///  www7.example7.com IN CNAME www8.example8.com.
/// example8.com:
///  www8.example8.com IN CNAME www9.example9.com.
/// example9.com:
///  www9.example9.com IN CNAME www10.example10.com.
/// example10.com:
///  www10.example10.com IN CNAME www11.example11.com.
/// example11.com:
///  www11.example11.com IN CNAME www12.example12.com.
/// example12.com:
///  www12.example12.com IN CNAME www13.example13.com.
/// example13.com:
///  www13.example13.com IN A 192.0.2.4
///
/// Querying IN A www.example.com. yields SERVFAIL
///
/// Querying IN A www2.example2.com. yields:
///  www2.example2.com IN CNAME www3.example3.com.
///  www3.example3.com IN CNAME www4.example4.com.
///  www4.example4.com IN CNAME www5.example5.com.
///  www5.example5.com IN CNAME www6.example6.com.
///  www6.example6.com IN CNAME www7.example7.com.
///  www7.example7.com IN CNAME www8.example8.com.
///  www8.example8.com IN CNAME www9.example9.com.
///  www9.example9.com IN CNAME www10.example10.com.
///  www10.example10.com IN CNAME www11.example11.com.
///  www11.example11.com IN CNAME www12.example12.com.
///  www12.example12.com IN CNAME www13.example13.com.
///  www13.example13.com IN A 192.0.2.4

#[test]
fn recursion_limit_cname_tests() -> Result<()> {
    let www_fqdn = FQDN("www.example.com.")?;
    let www_target = FQDN("www2.example2.com.")?;
    let www2_fqdn = FQDN("www2.example2.com.")?;
    let www2_target = FQDN("www3.example3.com.")?;
    let www3_fqdn = FQDN("www3.example3.com.")?;
    let www3_target = FQDN("www4.example4.com.")?;
    let www4_fqdn = FQDN("www4.example4.com.")?;
    let www4_target = FQDN("www5.example5.com.")?;
    let www5_fqdn = FQDN("www5.example5.com.")?;
    let www5_target = FQDN("www6.example6.com.")?;
    let www6_fqdn = FQDN("www6.example6.com.")?;
    let www6_target = FQDN("www7.example7.com.")?;
    let www7_fqdn = FQDN("www7.example7.com.")?;
    let www7_target = FQDN("www8.example8.com.")?;
    let www8_fqdn = FQDN("www8.example8.com.")?;
    let www8_target = FQDN("www9.example9.com.")?;
    let www9_fqdn = FQDN("www9.example9.com.")?;
    let www9_target = FQDN("www10.example10.com.")?;
    let www10_fqdn = FQDN("www10.example10.com.")?;
    let www10_target = FQDN("www11.example11.com.")?;
    let www11_fqdn = FQDN("www11.example11.com.")?;
    let www11_target = FQDN("www12.example12.com.")?;
    let www12_fqdn = FQDN("www12.example12.com.")?;
    let www12_target = FQDN("www13.example13.com.")?;

    let www13_fqdn = FQDN("www13.example13.com.")?;
    let www13_ipv4 = Ipv4Addr::new(192, 0, 2, 4);

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let mut com_ns  = NameServer::new(&Implementation::test_peer(), FQDN::COM, &network)?;

    let mut leaf_example_ns = NameServer::new(&Implementation::test_peer(), FQDN("example.com.")?, &network)?;
    leaf_example_ns.add(Record::cname(www_fqdn.clone(), www_target.clone()));

    let mut leaf_example2_ns = NameServer::new(&Implementation::test_peer(), FQDN("example2.com.")?, &network)?;
    leaf_example2_ns.add(Record::cname(www2_fqdn.clone(), www2_target.clone()));

    let mut leaf_example3_ns = NameServer::new(&Implementation::test_peer(), FQDN("example3.com.")?, &network)?;
    leaf_example3_ns.add(Record::cname(www3_fqdn.clone(), www3_target.clone()));

    let mut leaf_example4_ns = NameServer::new(&Implementation::test_peer(), FQDN("example4.com.")?, &network)?;
    leaf_example4_ns.add(Record::cname(www4_fqdn.clone(), www4_target.clone()));

    let mut leaf_example5_ns = NameServer::new(&Implementation::test_peer(), FQDN("example5.com.")?, &network)?;
    leaf_example5_ns.add(Record::cname(www5_fqdn.clone(), www5_target.clone()));

    let mut leaf_example6_ns = NameServer::new(&Implementation::test_peer(), FQDN("example6.com.")?, &network)?;
    leaf_example6_ns.add(Record::cname(www6_fqdn.clone(), www6_target.clone()));

    let mut leaf_example7_ns = NameServer::new(&Implementation::test_peer(), FQDN("example7.com.")?, &network)?;
    leaf_example7_ns.add(Record::cname(www7_fqdn.clone(), www7_target.clone()));

    let mut leaf_example8_ns = NameServer::new(&Implementation::test_peer(), FQDN("example8.com.")?, &network)?;
    leaf_example8_ns.add(Record::cname(www8_fqdn.clone(), www8_target.clone()));

    let mut leaf_example9_ns = NameServer::new(&Implementation::test_peer(), FQDN("example9.com.")?, &network)?;
    leaf_example9_ns.add(Record::cname(www9_fqdn.clone(), www9_target.clone()));

    let mut leaf_example10_ns = NameServer::new(&Implementation::test_peer(), FQDN("example10.com.")?, &network)?;
    leaf_example10_ns.add(Record::cname(www10_fqdn.clone(), www10_target.clone()));

    let mut leaf_example11_ns = NameServer::new(&Implementation::test_peer(), FQDN("example11.com.")?, &network)?;
    leaf_example11_ns.add(Record::cname(www11_fqdn.clone(), www11_target.clone()));

    let mut leaf_example12_ns = NameServer::new(&Implementation::test_peer(), FQDN("example12.com.")?, &network)?;
    leaf_example12_ns.add(Record::cname(www12_fqdn.clone(), www12_target.clone()));

    let mut leaf_example13_ns = NameServer::new(&Implementation::test_peer(), FQDN("example13.com.")?, &network)?;
    leaf_example13_ns.add(Record::a(www13_fqdn.clone(), www13_ipv4.clone()));

    root_ns.referral(FQDN::COM, FQDN("primary.tld-server.com.")?, com_ns.ipv4_addr());
    com_ns.referral(FQDN("example.com.")?, FQDN("ns.example.com.")?, leaf_example_ns.ipv4_addr());
    com_ns.referral(FQDN("example2.com.")?, FQDN("ns.example2.com.")?, leaf_example2_ns.ipv4_addr());
    com_ns.referral(FQDN("example3.com.")?, FQDN("ns.example3.com.")?, leaf_example3_ns.ipv4_addr());
    com_ns.referral(FQDN("example4.com.")?, FQDN("ns.example4.com.")?, leaf_example4_ns.ipv4_addr());
    com_ns.referral(FQDN("example5.com.")?, FQDN("ns.example5.com.")?, leaf_example5_ns.ipv4_addr());
    com_ns.referral(FQDN("example6.com.")?, FQDN("ns.example6.com.")?, leaf_example6_ns.ipv4_addr());
    com_ns.referral(FQDN("example7.com.")?, FQDN("ns.example7.com.")?, leaf_example7_ns.ipv4_addr());
    com_ns.referral(FQDN("example8.com.")?, FQDN("ns.example8.com.")?, leaf_example8_ns.ipv4_addr());
    com_ns.referral(FQDN("example9.com.")?, FQDN("ns.example9.com.")?, leaf_example9_ns.ipv4_addr());
    com_ns.referral(FQDN("example10.com.")?, FQDN("ns.example10.com.")?, leaf_example10_ns.ipv4_addr());
    com_ns.referral(FQDN("example11.com.")?, FQDN("ns.example11.com.")?, leaf_example11_ns.ipv4_addr());
    com_ns.referral(FQDN("example12.com.")?, FQDN("ns.example12.com.")?, leaf_example12_ns.ipv4_addr());
    com_ns.referral(FQDN("example13.com.")?, FQDN("ns.example13.com.")?, leaf_example13_ns.ipv4_addr());

    let root_hint: Root = root_ns.root_hint();
    let mut ns_running = vec![];
    for ns in [root_ns, com_ns, leaf_example_ns, leaf_example2_ns, leaf_example3_ns,
               leaf_example4_ns, leaf_example5_ns, leaf_example6_ns, leaf_example7_ns,
               leaf_example8_ns, leaf_example9_ns, leaf_example10_ns, leaf_example11_ns,
               leaf_example12_ns, leaf_example13_ns]
    {
        match ns.start() {
            Ok(ns) => {
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
    let res = client.dig(a_settings.clone(), resolver_addr, RecordType::A, &www_fqdn);

    if let Ok(ref res) = res {
        // FIXME Need recursor to pass servfail responses through for this to work.
        //assert!(res.status.is_servfail());
        assert_eq!(res.answer.len(), 0);
    } else {
        panic!("Error");
    }

    let res = client.dig(a_settings.clone(), resolver_addr, RecordType::A, &www2_fqdn);

    if let Ok(ref res) = res {
        assert!(res.status.is_noerror());
        assert_eq!(res.answer.len(), 12);
    } else {
        panic!("Error");
    }

    for answer in res.unwrap().answer {
        match answer {
            Record::A(rec) => {
                assert_eq!(rec.fqdn, www13_fqdn);
                assert_eq!(rec.ipv4_addr, www13_ipv4);
            }
            Record::CNAME(rec) => {
                assert!(
                    if rec.fqdn == www2_fqdn {
                        rec.target == www2_target
                    } else if rec.fqdn == www3_fqdn {
                        rec.target == www3_target
                    } else if rec.fqdn == www4_fqdn {
                        rec.target == www4_target
                    } else if rec.fqdn == www5_fqdn {
                        rec.target == www5_target
                    } else if rec.fqdn == www6_fqdn {
                        rec.target == www6_target
                    } else if rec.fqdn == www7_fqdn {
                        rec.target == www7_target
                    } else if rec.fqdn == www8_fqdn {
                        rec.target == www8_target
                    } else if rec.fqdn == www9_fqdn {
                        rec.target == www9_target
                    } else if rec.fqdn == www10_fqdn {
                        rec.target == www10_target
                    } else if rec.fqdn == www11_fqdn {
                        rec.target == www11_target
                    } else if rec.fqdn == www12_fqdn {
                        rec.target == www12_target
                    } else {
                      false
                    }
                );
            }
            _ => panic!("Unexpected record type in response: {answer:?}"),
        }
    }

    let res = resolver.terminate();
    assert!(res.is_ok(), "server process not found");

    let logs = res.unwrap();

    // FIXME dns-test effectively doesn't support reading stdout from hickory, due to
    // the startup log check taking stdout.  To accurately verify the 1st test -- the recursion
    // limit we need to look for a log message here...
    //assert!(logs.contains("Recursion depth exceeded for"));

    assert!(!logs.contains("stack overflow"));

    Ok(())
}
