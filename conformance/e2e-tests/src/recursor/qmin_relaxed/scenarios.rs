//! These scenarios use a single test network with the following records:
//!
//! example.testing:
//!  sub.example.testing IN A 192.0.2.1
//!  sub.ent.example.testing IN A 192.0.3.1
//!  host1.ent.example.testing IN A 192.0.4.1
//!  host2.ent.sub.example.testing IN A 192.0.5.1
//!  host3.sub.ent.example.testing IN A 192.0.6.1
//!  host4.ent.ent.example.testing IN A 192.0.7.1
use std::{net::Ipv4Addr, thread, time::Duration};

use dns_test::{
    Error, FQDN, Implementation, Network, Resolver,
    client::{Client, DigOutput, DigSettings},
    name_server::{NameServer, Running},
    record::{Record, RecordType},
    zone_file::Root,
};

/// qname minimization relaxed mode error code tests
///
/// Querying IN A sub.example.testing yields NOERROR and 1 answer record
/// Querying IN A sub.ent.example.testing yields NOERROR and 1 answer record
/// Querying IN A host1.ent.example.testing yields NOERROR and 1 answer record
/// Querying IN A host2.ent.sub.example.testing yields NOERROR and 1 answer record
/// Querying IN A host3.sub.ent.example.testing yields NOERROR and 1 answer record
/// Querying IN A host4.ent.ent.example.testing yields NOERROR and 1 answer record
///
/// Querying IN A ent.example.testing yields NOERROR and 1 authority record
/// Querying IN A ent.sub.example.testing yields NOERROR and 1 authority record
/// Querying IN A ent.ent.example.testing yields NOERROR and 1 authority record
///
/// Querying IN A host5.example.testing yields NXDOMAIN and 1 authority record
/// Querying IN A host6.ent.example.testing yields NXDOMAIN and 1 authority record
#[test]
fn qmin_relaxed_error_code_tests() -> Result<(), Error> {
    let sub1_fqdn = FQDN("sub.example.testing.")?;
    let sub1_ipv4_addr = Ipv4Addr::new(192, 0, 2, 1);
    let sub2_fqdn = FQDN("sub.ent.example.testing.")?;
    let sub2_ipv4_addr = Ipv4Addr::new(192, 0, 3, 1);
    let host1_fqdn = FQDN("host1.ent.example.testing.")?;
    let host1_ipv4_addr = Ipv4Addr::new(192, 0, 4, 1);
    let host2_fqdn = FQDN("host2.ent.sub.example.testing.")?;
    let host2_ipv4_addr = Ipv4Addr::new(192, 0, 5, 1);
    let host3_fqdn = FQDN("host3.sub.ent.example.testing.")?;
    let host3_ipv4_addr = Ipv4Addr::new(192, 0, 6, 1);
    let host4_fqdn = FQDN("host4.ent.ent.example.testing.")?;
    let host4_ipv4_addr = Ipv4Addr::new(192, 0, 7, 1);

    let test = TestNetwork::new()?;

    let res = test.dig(RecordType::A, &sub1_fqdn)?;
    assert!(res.status.is_noerror());
    assert_eq!(res.answer.len(), 1);
    if let Record::A(rec) = res.answer.first().unwrap() {
        assert_eq!(rec.fqdn, sub1_fqdn);
        assert_eq!(rec.ipv4_addr, sub1_ipv4_addr);
    } else {
        panic!("error");
    }

    let res = test.dig(RecordType::A, &sub2_fqdn)?;
    assert!(res.status.is_noerror());
    assert_eq!(res.answer.len(), 1);
    if let Record::A(rec) = res.answer.first().unwrap() {
        assert_eq!(rec.fqdn, sub2_fqdn);
        assert_eq!(rec.ipv4_addr, sub2_ipv4_addr);
    } else {
        panic!("error");
    }

    let res = test.dig(RecordType::A, &host1_fqdn)?;
    assert!(res.status.is_noerror());
    assert_eq!(res.answer.len(), 1);
    if let Record::A(rec) = res.answer.first().unwrap() {
        assert_eq!(rec.fqdn, host1_fqdn);
        assert_eq!(rec.ipv4_addr, host1_ipv4_addr);
    } else {
        panic!("error");
    }

    let res = test.dig(RecordType::A, &host2_fqdn)?;
    assert!(res.status.is_noerror());
    assert_eq!(res.answer.len(), 1);
    if let Record::A(rec) = res.answer.first().unwrap() {
        assert_eq!(rec.fqdn, host2_fqdn);
        assert_eq!(rec.ipv4_addr, host2_ipv4_addr);
    } else {
        panic!("error");
    }

    let res = test.dig(RecordType::A, &host3_fqdn)?;
    assert!(res.status.is_noerror());
    assert_eq!(res.answer.len(), 1);
    if let Record::A(rec) = res.answer.first().unwrap() {
        assert_eq!(rec.fqdn, host3_fqdn);
        assert_eq!(rec.ipv4_addr, host3_ipv4_addr);
    } else {
        panic!("error");
    }

    let res = test.dig(RecordType::A, &host4_fqdn)?;
    assert!(res.status.is_noerror());
    assert_eq!(res.answer.len(), 1);
    if let Record::A(rec) = res.answer.first().unwrap() {
        assert_eq!(rec.fqdn, host4_fqdn);
        assert_eq!(rec.ipv4_addr, host4_ipv4_addr);
    } else {
        panic!("error");
    }

    let res = test.dig(RecordType::A, &FQDN("ent.example.testing.")?)?;
    assert!(res.status.is_noerror());
    assert_eq!(res.answer.len(), 0);
    assert_eq!(res.authority.len(), 1);
    if let Record::SOA(rec) = res.authority.first().unwrap() {
        assert_eq!(rec.zone, FQDN("example.testing.")?);
    } else {
        panic!("error");
    }

    let res = test.dig(RecordType::A, &FQDN("ent.sub.example.testing.")?)?;
    assert!(res.status.is_noerror());
    assert_eq!(res.answer.len(), 0);
    assert_eq!(res.authority.len(), 1);
    if let Record::SOA(rec) = res.authority.first().unwrap() {
        assert_eq!(rec.zone, FQDN("example.testing.")?);
    } else {
        panic!("error");
    }

    let res = test.dig(RecordType::A, &FQDN("ent.ent.example.testing.")?)?;
    assert!(res.status.is_noerror());
    assert_eq!(res.answer.len(), 0);
    assert_eq!(res.authority.len(), 1);
    if let Record::SOA(rec) = res.authority.first().unwrap() {
        assert_eq!(rec.zone, FQDN("example.testing.")?);
    } else {
        panic!("error");
    }

    let res = test.dig(RecordType::A, &FQDN("host5.example.testing.")?)?;
    assert!(res.status.is_nxdomain());
    assert_eq!(res.answer.len(), 0);
    assert_eq!(res.authority.len(), 1);
    if let Record::SOA(rec) = res.authority.first().unwrap() {
        assert_eq!(rec.zone, FQDN("example.testing.")?);
    } else {
        panic!("error");
    }

    let res = test.dig(RecordType::A, &FQDN("host6.ent.example.testing.")?)?;
    assert!(res.status.is_nxdomain());
    assert_eq!(res.answer.len(), 0);
    assert_eq!(res.authority.len(), 1);
    if let Record::SOA(rec) = res.authority.first().unwrap() {
        assert_eq!(rec.zone, FQDN("example.testing.")?);
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
    fn new() -> Result<Self, Error> {
        let sub1_fqdn = FQDN("sub.example.testing.")?;
        let sub1_ipv4_addr = Ipv4Addr::new(192, 0, 2, 1);
        let sub2_fqdn = FQDN("sub.ent.example.testing.")?;
        let sub2_ipv4_addr = Ipv4Addr::new(192, 0, 3, 1);
        let host1_fqdn = FQDN("host1.ent.example.testing.")?;
        let host1_ipv4_addr = Ipv4Addr::new(192, 0, 4, 1);
        let host2_fqdn = FQDN("host2.ent.sub.example.testing.")?;
        let host2_ipv4_addr = Ipv4Addr::new(192, 0, 5, 1);
        let host3_fqdn = FQDN("host3.sub.ent.example.testing.")?;
        let host3_ipv4_addr = Ipv4Addr::new(192, 0, 6, 1);
        let host4_fqdn = FQDN("host4.ent.ent.example.testing.")?;
        let host4_ipv4_addr = Ipv4Addr::new(192, 0, 7, 1);

        let network = Network::new()?;

        let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
        let mut tld_ns = NameServer::new(&Implementation::test_peer(), FQDN::TEST_TLD, &network)?;

        let mut example_ns = NameServer::new(
            &Implementation::test_peer(),
            FQDN("example.testing.")?,
            &network,
        )?;

        example_ns.add(Record::a(sub1_fqdn, sub1_ipv4_addr));
        example_ns.add(Record::a(sub2_fqdn, sub2_ipv4_addr));
        example_ns.add(Record::a(host1_fqdn, host1_ipv4_addr));
        example_ns.add(Record::a(host2_fqdn, host2_ipv4_addr));
        example_ns.add(Record::a(host3_fqdn, host3_ipv4_addr));
        example_ns.add(Record::a(host4_fqdn, host4_ipv4_addr));

        root_ns.referral_nameserver(&tld_ns);
        tld_ns.referral_nameserver(&example_ns);

        let root_hint: Root = root_ns.root_hint();

        let resolver = Resolver::new(&network, root_hint)
            .custom_config(HICKORY_RECURSOR_QMIN_RELAXED_CONFIG.to_string())
            .start_with_subject(&Implementation::hickory())?;

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

    fn dig(&self, r_type: RecordType, q_name: &FQDN) -> Result<DigOutput, Error> {
        let a_settings = *DigSettings::default().recurse().authentic_data();
        self.client
            .dig(a_settings, self.resolver.ipv4_addr(), r_type, q_name)
    }
}

static HICKORY_RECURSOR_QMIN_RELAXED_CONFIG: &str = r#"
user = "nobody"
group = "nogroup"

[[zones]]
zone = "."
zone_type = "External"

[zones.stores]
type = "recursor"
roots = "/etc/root.hints"
dnssec_policy = "ValidationDisabled"
allow_server = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
qname_minimization = "Relaxed"
"#;
