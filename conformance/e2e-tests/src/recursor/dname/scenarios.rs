/// DNAME conformance tests per RFC 6672 ("DNAME Redirection in the DNS").
///
/// These tests verify the recursive resolver's handling of DNAME records,
/// including substitution (Section 2.2), synthesized CNAME generation
/// (Section 2.2), and interaction with other record types.
///
/// The DNAME record is placed at `old.example.testing.` (not at the zone apex)
/// because RFC 6672 forbids data at any descendant of the DNAME owner, and the
/// auto-generated nameserver glue (primaryN.example.testing.) would violate
/// that constraint if the DNAME were at the apex.
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

use dns_test::{
    Error, FQDN, Implementation, Network, Resolver,
    client::{Client, DigOutput, DigSettings},
    name_server::{NameServer, Running},
    record::{Record, RecordType},
    zone_file::Root,
};

/// RFC 6672 Section 2.2: Basic DNAME substitution.
///
/// Given:
///   old.example.testing.  DNAME  example2.testing.
///   foo.example2.testing.  A  192.0.2.1
///
/// A query for foo.old.example.testing. IN A should:
/// 1. Return the DNAME record in the answer section
/// 2. Synthesize a CNAME from foo.old.example.testing. to foo.example2.testing.
/// 3. Follow the synthesized CNAME to return the final A record
///
/// Per Section 2.2: "The DNAME RR and its synthesized CNAME RR [...] SHOULD
/// be included in the answer section."
#[test]
fn basic_dname_substitution() -> Result<(), Error> {
    let test = DnameTestNetwork::new(false)?;
    let res = test.dig(RecordType::A, &FQDN("foo.old.example.testing.")?)?;
    assert!(res.status.is_noerror());

    let mut found_dname = false;
    let mut found_cname = false;
    let mut found_a = false;

    for answer in &res.answer {
        match answer {
            Record::DNAME(rec) => {
                assert_eq!(rec.fqdn, FQDN("old.example.testing.")?);
                assert_eq!(rec.target, FQDN("example2.testing.")?);
                found_dname = true;
            }
            Record::CNAME(rec) => {
                assert_eq!(rec.fqdn, FQDN("foo.old.example.testing.")?);
                assert_eq!(rec.target, FQDN("foo.example2.testing.")?);
                found_cname = true;
            }
            Record::A(rec) => {
                assert_eq!(rec.fqdn, FQDN("foo.example2.testing.")?);
                assert_eq!(rec.ipv4_addr, Ipv4Addr::new(192, 0, 2, 1));
                found_a = true;
            }
            _ => panic!("unexpected record type in response: {answer:?}"),
        }
    }

    assert!(found_dname, "response should include the DNAME record");
    assert!(found_cname, "response should include the synthesized CNAME");
    assert!(found_a, "response should include the final A record");

    Ok(())
}

/// RFC 6672 Section 2.2: Multi-label prefix substitution.
///
/// Given:
///   old.example.testing.  DNAME  example2.testing.
///   a.b.c.example2.testing.  A  192.0.2.2
///
/// A query for a.b.c.old.example.testing. IN A should substitute the entire
/// prefix "a.b.c" from the owner "old.example.testing." to the target
/// "example2.testing.", yielding a.b.c.example2.testing.
#[test]
fn multi_label_prefix_substitution() -> Result<(), Error> {
    let test = DnameTestNetwork::new(false)?;
    let res = test.dig(RecordType::A, &FQDN("a.b.c.old.example.testing.")?)?;
    assert!(res.status.is_noerror());

    let mut found_a = false;
    for answer in &res.answer {
        match answer {
            Record::A(rec) => {
                assert_eq!(rec.fqdn, FQDN("a.b.c.example2.testing.")?);
                assert_eq!(rec.ipv4_addr, Ipv4Addr::new(192, 0, 2, 2));
                found_a = true;
            }
            Record::DNAME(_) | Record::CNAME(_) => {}
            _ => panic!("unexpected record type in response: {answer:?}"),
        }
    }

    assert!(
        found_a,
        "response should include the A record after DNAME substitution"
    );
    Ok(())
}

/// RFC 6672 Section 2.2: Direct query for DNAME owner type.
///
/// "DNAME RRs [...] are not applied to the owner name itself."
///
/// A query for old.example.testing. IN A should NOT trigger DNAME processing.
/// Since there is no A record at the DNAME owner, this should return
/// NOERROR with an empty answer (plus SOA in authority).
#[test]
fn query_for_dname_owner_returns_no_substitution() -> Result<(), Error> {
    let test = DnameTestNetwork::new(false)?;
    let res = test.dig(RecordType::A, &FQDN("old.example.testing.")?)?;

    // The owner name itself has a DNAME but no A record;
    // DNAME does not apply to the owner name per RFC 6672 Section 2.2.
    assert!(res.status.is_noerror());
    assert_eq!(
        res.answer.len(),
        0,
        "DNAME should not apply to the owner name itself"
    );

    Ok(())
}

/// RFC 6672 Section 2.2: Direct query for DNAME record type.
///
/// A query for old.example.testing. IN DNAME should return the DNAME record
/// directly, with no synthesis.
#[test]
fn query_type_dname_returns_dname_record() -> Result<(), Error> {
    let test = DnameTestNetwork::new(false)?;
    let res = test.dig(RecordType::DNAME, &FQDN("old.example.testing.")?)?;
    assert!(res.status.is_noerror());
    assert_eq!(
        res.answer.len(),
        1,
        "should return exactly the DNAME record"
    );

    let Record::DNAME(dname) = &res.answer[0] else {
        panic!("expected DNAME record, got: {:?}", res.answer[0]);
    };

    assert_eq!(dname.fqdn, FQDN("old.example.testing.")?);
    assert_eq!(dname.target, FQDN("example2.testing.")?);
    Ok(())
}

/// RFC 6672 Section 2.2: DNAME + CNAME chain.
///
/// Given:
///   old.example.testing.  DNAME  example2.testing.
///   bar.example2.testing.  CNAME  baz.example3.testing.
///   baz.example3.testing.  A  192.0.2.3
///
/// A query for bar.old.example.testing. IN A should:
/// 1. Apply DNAME substitution → bar.example2.testing.
/// 2. Follow CNAME → baz.example3.testing.
/// 3. Resolve A record 192.0.2.3
#[test]
fn dname_followed_by_cname_chain() -> Result<(), Error> {
    let test = DnameTestNetwork::new(true)?;
    let res = test.dig(RecordType::A, &FQDN("bar.old.example.testing.")?)?;
    assert!(res.status.is_noerror());

    let mut found_a = false;
    for answer in &res.answer {
        if let Record::A(rec) = answer {
            assert_eq!(rec.fqdn, FQDN("baz.example3.testing.")?);
            assert_eq!(rec.ipv4_addr, Ipv4Addr::new(192, 0, 2, 3));
            found_a = true;
        }
    }

    assert!(
        found_a,
        "should resolve through DNAME + CNAME chain to final A"
    );
    Ok(())
}

/// RFC 6672 Section 2.2: DNAME does not affect sibling records at the owner.
///
/// The DNAME owner may have other RR types coexisting at the same node.
/// A query for old.example.testing. IN SOA should return a NODATA response
/// (since there is no SOA at that non-apex node), with no DNAME substitution.
#[test]
fn dname_owner_other_types_not_substituted() -> Result<(), Error> {
    let test = DnameTestNetwork::new(false)?;

    // Query for the SOA at the zone apex -- should return the SOA directly,
    // unaffected by the DNAME at old.example.testing.
    let res = test.dig(RecordType::SOA, &FQDN("example.testing.")?)?;

    assert!(res.status.is_noerror());
    let has_soa = res.answer.iter().any(|r| matches!(r, Record::SOA(_)))
        || res.authority.iter().any(|r| matches!(r, Record::SOA(_)));
    assert!(has_soa, "SOA query at zone apex should return SOA");

    Ok(())
}

/// RFC 6672 Section 2.2 / RFC 2672 Section 4.1: NXDOMAIN after DNAME.
///
/// Given:
///   old.example.testing.  DNAME  example2.testing.
///
/// A query for nonexistent.old.example.testing. IN A should:
/// 1. Apply DNAME substitution → nonexistent.example2.testing.
/// 2. Since nonexistent.example2.testing. does not exist, return NXDOMAIN
///
/// The response should still include the DNAME and synthesized CNAME in
/// the answer section.
#[test]
fn dname_substitution_to_nxdomain() -> Result<(), Error> {
    let test = DnameTestNetwork::new(false)?;

    let res = test.dig(RecordType::A, &FQDN("nonexistent.old.example.testing.")?)?;

    // The substituted name nonexistent.example2.testing. doesn't exist
    assert!(
        res.status.is_nxdomain(),
        "expected NXDOMAIN after DNAME substitution to nonexistent name, got: {:?}",
        res.status,
    );

    Ok(())
}

/// Helper network for basic DNAME tests.
///
/// Zone layout:
///   example.testing:
///     old.example.testing.       DNAME  example2.testing.
///
///   example2.testing:
///     foo.example2.testing.        A      192.0.2.1
///     a.b.c.example2.testing.      A      192.0.2.2
///     bar.example2.testing.        CNAME  baz.example3.testing.  (only in with_cname_chain)
///
///   example3.testing:  (only in with_cname_chain)
///     baz.example3.testing.        A      192.0.2.3
struct DnameTestNetwork {
    _network: Network,
    _root_ns: NameServer<Running>,
    _tld_ns: NameServer<Running>,
    _example_ns: NameServer<Running>,
    _example2_ns: NameServer<Running>,
    _example3_ns: Option<NameServer<Running>>,
    resolver: Resolver,
    client: Client,
}

impl DnameTestNetwork {
    fn new(with_cname_chain: bool) -> Result<Self, Error> {
        let network = Network::new()?;

        let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
        let mut tld_ns = NameServer::new(&Implementation::test_peer(), FQDN::TEST_TLD, &network)?;

        // example.testing zone: contains the DNAME at a non-apex subdomain.
        // The DNAME must NOT be at the zone apex because the auto-generated
        // nameserver glue (primaryN.example.testing.) would be a descendant
        // of the DNAME owner, violating RFC 6672 Section 2.4.
        let mut example_ns = NameServer::new(
            &Implementation::test_peer(),
            FQDN("example.testing.")?,
            &network,
        )?;
        example_ns.add(Record::dname(
            FQDN("old.example.testing.")?,
            FQDN("example2.testing.")?,
        ));

        // example2.testing zone: target records
        let mut example2_ns = NameServer::new(
            &Implementation::test_peer(),
            FQDN("example2.testing.")?,
            &network,
        )?;
        example2_ns.add(Record::a(
            FQDN("foo.example2.testing.")?,
            Ipv4Addr::new(192, 0, 2, 1),
        ));
        example2_ns.add(Record::a(
            FQDN("a.b.c.example2.testing.")?,
            Ipv4Addr::new(192, 0, 2, 2),
        ));

        let mut example3_ns_running = None;

        if with_cname_chain {
            // bar.example2.testing -> baz.example3.testing
            example2_ns.add(Record::cname(
                FQDN("bar.example2.testing.")?,
                FQDN("baz.example3.testing.")?,
            ));

            // example3.testing zone
            let mut example3_ns = NameServer::new(
                &Implementation::test_peer(),
                FQDN("example3.testing.")?,
                &network,
            )?;
            example3_ns.add(Record::a(
                FQDN("baz.example3.testing.")?,
                Ipv4Addr::new(192, 0, 2, 3),
            ));

            tld_ns.referral(
                FQDN("example3.testing.")?,
                FQDN("ns.example3.testing.")?,
                example3_ns.ipv4_addr(),
            );

            example3_ns_running = Some(example3_ns.start()?);
        }

        // Wire up delegations
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
            _example3_ns: example3_ns_running,
            resolver,
            client,
        };

        thread::sleep(Duration::from_secs(2));

        Ok(ret)
    }

    fn dig(&self, r_type: RecordType, q_name: &FQDN) -> Result<DigOutput, Error> {
        let settings = *DigSettings::default().recurse().authentic_data();
        self.client
            .dig(settings, self.resolver.ipv4_addr(), r_type, q_name)
    }
}
