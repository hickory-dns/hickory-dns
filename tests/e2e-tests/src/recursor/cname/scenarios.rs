/// These scenarios use a single test network with the following records:
///
/// example.testing:
///  www.example.testing IN CNAME www2.example2.testing.
///  www3.example.testing IN CNAME www4.example2.testing.
///  www5.example.testing IN CNAME www6.example2.testing.
///  www7.example.testing IN CNAME www8.example2.testing.
///  www9.example.testing IN CNAME www10.example2.testing.
///  www11.example.testing IN CNAME www12.example2.testing.
///  www13.example.testing IN A 192.0.2.1
///
/// example2.testing:
///  www2.example2.testing IN CNAME www3.example.testing.
///  www4.example2.testing IN CNAME www5.example.testing.
///  www6.example2.testing IN CNAME www7.example.testing.
///  www8.example2.testing IN CNAME www9.example.testing.
///  www10.example2.testing IN CNAME www11.example.testing.
///  www12.example2.testing IN CNAME www13.example.testing.
///
use std::fs;
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

use dns_test::{
    FQDN, Implementation, Network, Resolver, Result,
    client::{Client, DigOutput, DigSettings},
    name_server::{NameServer, Running},
    record::{Record, RecordType},
    zone_file::Root,
};

/// Single level CNAME tests
///
/// Querying IN A www.example.testing. yields:
///  www12.example2.testing IN CNAME www13.example.testing.
///  www13.example.testing IN A 192.0.2.1
///
/// Querying IN CNAME www.example.testing. yields:
///  www12.example2.testing IN CNAME www13.example.testing.
#[test]
fn single_level_cname_tests() -> Result<()> {
    let cname_fqdn = FQDN("www12.example2.testing.")?;
    let cname_target = FQDN("www13.example.testing.")?;

    let target_a_fqdn = FQDN("www13.example.testing.")?;
    let target_a_ipv4_addr = Ipv4Addr::new(192, 0, 2, 1);

    let test = TestNetwork::new().unwrap();

    let res = test.dig(RecordType::A, &cname_fqdn);

    if let Ok(res) = &res {
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

    let res = test.dig(RecordType::CNAME, &cname_fqdn);

    if let Ok(res) = &res {
        assert!(res.status.is_noerror());
        assert_eq!(res.answer.len(), 1);
    } else {
        panic!("Error");
    }

    match res.unwrap().answer.first().unwrap() {
        Record::CNAME(cname) => {
            assert_eq!(cname.fqdn, cname_fqdn);
            assert_eq!(cname.target, cname_target);
        }
        _ => {
            panic!("Unexpected record type");
        }
    }

    let logs = test.logs().unwrap();
    assert!(!logs.contains("stack overflow"));

    Ok(())
}

/// Multi-level CNAME and Recursion Depth Limit Check
///
/// Querying IN A www.example.testing. yields SERVFAIL
///
/// Querying IN A www2.example2.testing. yields:
///  www2.example2.testing IN CNAME www3.example.testing.
///  www3.example.testing IN CNAME www4.example2.testing.
///  www4.example2.testing IN CNAME www5.example.testing.
///  www5.example.testing IN CNAME www6.example2.testing.
///  www6.example2.testing IN CNAME www7.example.testing.
///  www7.example.testing IN CNAME www8.example2.testing.
///  www8.example2.testing IN CNAME www9.example.testing.
///  www9.example.testing IN CNAME www10.example2.testing.
///  www10.example2.testing IN CNAME www11.example.testing.
///  www11.example.testing IN CNAME www12.example2.testing.
///  www12.example2.testing IN CNAME www13.example.testing.
///  www13.example.testing IN A 192.0.2.1
///
/// Querying IN CNAME www13.example.testing. yields NoError
#[test]
fn multi_level_cname_tests() -> Result<()> {
    let test = TestNetwork::new().unwrap();

    let res = test.dig(RecordType::A, &FQDN("www.example.testing.")?);

    if let Ok(res) = res {
        assert!(res.status.is_servfail());
        assert_eq!(res.answer.len(), 0);

        let logs = test.logs().unwrap();
        assert!(logs.contains("recursion depth exceeded for"));
    } else {
        panic!("Error");
    }

    let res = test.dig(RecordType::A, &FQDN("www2.example2.testing.")?);

    if let Ok(res) = &res {
        assert!(res.status.is_noerror());
        assert_eq!(res.answer.len(), 12);
    } else {
        panic!("Error");
    }

    for answer in res.unwrap().answer {
        match answer {
            Record::A(rec) => {
                assert_eq!(rec.fqdn, FQDN("www13.example.testing.")?);
                assert_eq!(rec.ipv4_addr, Ipv4Addr::new(192, 0, 2, 1));
            }
            Record::CNAME(rec) => {
                for (name, target) in test.cnames() {
                    if rec.fqdn == *name {
                        assert!(rec.target == *target);
                    }
                }
            }
            _ => panic!("Unexpected record type in response: {answer:?}"),
        }
    }

    let res = test.dig(RecordType::CNAME, &FQDN("www13.example.testing.")?);
    if let Ok(res) = res {
        assert_eq!(res.answer.len(), 0);
    } else {
        panic!("Error");
    }

    Ok(())
}

/// ensure that no more than MAX_CNAME_LOOKUPS will be resolved.
#[test]
fn cname_lookup_limit_test() -> Result<()> {
    let target_fqdn = FQDN("host.testing.")?;

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(&Implementation::Dnslib, FQDN::TEST_TLD, &network)?;

    let script = fs::read_to_string("src/recursor/cname/cname_loop.py")?;

    leaf_ns.cp("/script.py", &script[..])?;

    root_ns.referral(
        FQDN::TEST_TLD,
        FQDN("primary.tld-server.testing.")?,
        leaf_ns.ipv4_addr(),
    );

    let root_hint: Root = root_ns.root_hint();

    let resolver =
        Resolver::new(&network, root_hint).start_with_subject(&Implementation::hickory())?;

    let client = Client::new(resolver.network())?;

    let _root_ns = root_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;

    thread::sleep(Duration::from_secs(2));
    let a_settings = *DigSettings::default().recurse().authentic_data();
    let res = client.dig(
        a_settings,
        resolver.ipv4_addr(),
        RecordType::A,
        &target_fqdn,
    );

    match res {
        Ok(res) => {
            assert!(res.status.is_servfail());
            assert_eq!(res.answer.len(), 0);
        }
        Err(e) => panic!("error {e:?}; resolver logs: {}", resolver.logs().unwrap()),
    }

    assert!(resolver.logs().unwrap().contains("cname limit exceeded"));

    Ok(())
}

struct TestNetwork {
    _network: Network,
    _root_ns: NameServer<Running>,
    _tld_ns: NameServer<Running>,
    _example_ns: NameServer<Running>,
    _example2_ns: NameServer<Running>,
    resolver: Resolver,
    client: Client,
    cnames: Vec<(FQDN, FQDN)>,
}

impl TestNetwork {
    fn new() -> Result<Self> {
        let cnames = vec![
            (
                FQDN("www.example.testing.")?,
                FQDN("www2.example2.testing.")?,
            ),
            (
                FQDN("www2.example2.testing.")?,
                FQDN("www3.example.testing.")?,
            ),
            (
                FQDN("www3.example.testing.")?,
                FQDN("www4.example2.testing.")?,
            ),
            (
                FQDN("www4.example2.testing.")?,
                FQDN("www5.example.testing.")?,
            ),
            (
                FQDN("www5.example.testing.")?,
                FQDN("www6.example2.testing.")?,
            ),
            (
                FQDN("www6.example2.testing.")?,
                FQDN("www7.example.testing.")?,
            ),
            (
                FQDN("www7.example.testing.")?,
                FQDN("www8.example2.testing.")?,
            ),
            (
                FQDN("www8.example2.testing.")?,
                FQDN("www9.example.testing.")?,
            ),
            (
                FQDN("www9.example.testing.")?,
                FQDN("www10.example2.testing.")?,
            ),
            (
                FQDN("www10.example2.testing.")?,
                FQDN("www11.example.testing.")?,
            ),
            (
                FQDN("www11.example.testing.")?,
                FQDN("www12.example2.testing.")?,
            ),
            (
                FQDN("www12.example2.testing.")?,
                FQDN("www13.example.testing.")?,
            ),
        ];

        let www13_fqdn = FQDN("www13.example.testing.")?;
        let www13_ipv4 = Ipv4Addr::new(192, 0, 2, 1);

        let network = Network::new()?;

        let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
        let mut tld_ns = NameServer::new(&Implementation::test_peer(), FQDN::TEST_TLD, &network)?;

        let mut example_ns = NameServer::new(
            &Implementation::test_peer(),
            FQDN("example.testing.")?,
            &network,
        )?;

        for elem in [0, 2, 4, 6, 8, 10] {
            example_ns.add(Record::cname(
                cnames[elem].0.clone(),
                cnames[elem].1.clone(),
            ));
        }

        example_ns.add(Record::a(www13_fqdn, www13_ipv4));

        let mut example2_ns = NameServer::new(
            &Implementation::test_peer(),
            FQDN("example2.testing.")?,
            &network,
        )?;

        for elem in [1, 3, 5, 7, 9, 11] {
            example2_ns.add(Record::cname(
                cnames[elem].0.clone(),
                cnames[elem].1.clone(),
            ));
        }

        root_ns.referral(
            FQDN::TEST_TLD,
            FQDN("primary.tld-server.testing.")?,
            tld_ns.ipv4_addr(),
        );
        tld_ns.referral(
            FQDN("example.testing.")?,
            FQDN("ns.example.testing.")?,
            example_ns.ipv4_addr(),
        );
        tld_ns.referral(
            FQDN("example2.testing.")?,
            FQDN("ns.example2.testing.")?,
            example2_ns.ipv4_addr(),
        );

        let root_hint: Root = root_ns.root_hint();

        let resolver =
            Resolver::new(&network, root_hint).start_with_subject(&Implementation::hickory())?;

        let client = Client::new(resolver.network())?;

        let ret = Self {
            _network: network,
            _root_ns: root_ns.start()?,
            _tld_ns: tld_ns.start()?,
            _example_ns: example_ns.start()?,
            _example2_ns: example2_ns.start()?,
            resolver,
            client,
            cnames,
        };

        thread::sleep(Duration::from_secs(2));

        Ok(ret)
    }

    fn cnames(&self) -> &Vec<(FQDN, FQDN)> {
        &self.cnames
    }

    fn dig(&self, r_type: RecordType, q_name: &FQDN) -> Result<DigOutput> {
        let a_settings = *DigSettings::default().recurse().authentic_data();
        self.client
            .dig(a_settings, self.resolver.ipv4_addr(), r_type, q_name)
    }

    fn logs(&self) -> Result<String> {
        self.resolver.logs()
    }
}
