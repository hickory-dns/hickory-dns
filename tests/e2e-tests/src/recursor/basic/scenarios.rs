/// These scenarios use a single test network with the following records:
///
/// example.testing:
///  www.example.testing IN A 192.0.2.1
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

/// Error code tests
///
/// Querying IN A www.example.testing yields NOERROR and 1 answer record
/// Querying IN AAAA www.example.testing yields NOERROR and 0 answer records + 1 authority record
/// Querying IN A www2.example.testing yields NXDOMAIN and 1 authority records.
#[test]
fn error_code_tests() -> Result<()> {
    let target_fqdn = FQDN("www.example.testing.")?;
    let target_ipv4_addr = Ipv4Addr::new(192, 0, 2, 1);

    let test = TestNetwork::new().unwrap();

    let res = test.dig(RecordType::A, &target_fqdn);

    if let Ok(res) = &res {
        assert!(res.status.is_noerror());
        assert_eq!(res.answer.len(), 1);
        if let Record::A(rec) = res.answer.first().unwrap() {
            assert_eq!(rec.fqdn, target_fqdn);
            assert_eq!(rec.ipv4_addr, target_ipv4_addr);
        } else {
            panic!("error");
        }
    } else {
        panic!("error");
    }

    let res = test.dig(RecordType::AAAA, &target_fqdn);

    if let Ok(res) = &res {
        assert!(res.status.is_noerror());
        assert_eq!(res.answer.len(), 0);
        assert_eq!(res.authority.len(), 1);
        if let Record::SOA(rec) = res.authority.first().unwrap() {
            assert_eq!(rec.zone, FQDN("example.testing.")?);
        } else {
            panic!("error");
        }
    } else {
        panic!("error");
    }

    let res = test.dig(RecordType::A, &FQDN("www2.example.testing.")?);

    if let Ok(res) = &res {
        assert!(res.status.is_nxdomain());
        assert_eq!(res.answer.len(), 0);
        assert_eq!(res.authority.len(), 1);
        if let Record::SOA(rec) = res.authority.first().unwrap() {
            assert_eq!(rec.zone, FQDN("example.testing.")?);
        } else {
            panic!("error");
        }
    } else {
        panic!("error");
    }

    Ok(())
}

struct TestNetwork {
    _network: Network,
    _root_ns: NameServer<Running>,
    _tld_ns: NameServer<Running>,
    _example_ns: NameServer<Running>,
    resolver: Resolver,
    client: Client,
}

impl TestNetwork {
    fn new() -> Result<Self> {
        let www_fqdn = FQDN("www.example.testing.")?;
        let www_ipv4 = Ipv4Addr::new(192, 0, 2, 1);

        let network = Network::new()?;

        let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
        let mut tld_ns = NameServer::new(&Implementation::test_peer(), FQDN::TEST_TLD, &network)?;

        let mut example_ns = NameServer::new(
            &Implementation::test_peer(),
            FQDN("example.testing.")?,
            &network,
        )?;

        example_ns.add(Record::a(www_fqdn, www_ipv4));

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

        let root_hint: Root = root_ns.root_hint();

        let resolver =
            Resolver::new(&network, root_hint).start_with_subject(&Implementation::hickory())?;

        let client = Client::new(resolver.network())?;

        let ret = Self {
            _network: network,
            _root_ns: root_ns.start()?,
            _tld_ns: tld_ns.start()?,
            _example_ns: example_ns.start()?,
            resolver,
            client,
        };

        thread::sleep(Duration::from_secs(2));

        Ok(ret)
    }

    fn dig(&self, r_type: RecordType, q_name: &FQDN) -> Result<DigOutput> {
        let a_settings = *DigSettings::default().recurse().authentic_data();
        self.client
            .dig(a_settings, self.resolver.ipv4_addr(), r_type, q_name)
    }
}
