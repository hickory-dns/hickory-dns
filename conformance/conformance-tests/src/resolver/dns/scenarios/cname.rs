use std::net::Ipv4Addr;

use dns_test::{
    Error, FQDN, Network, PEER, Resolver,
    client::{Client, DigSettings, DigStatus},
    name_server::{Graph, NameServer, Running, Sign},
    record::{A, CNAME, NSEC3, RRSIG, Record, RecordType},
    zone_file::SignSettings,
};

#[test]
fn basic() -> Result<(), Error> {
    let (_network, _graph, resolver, client) = setup_cname()?;
    let output = client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("alias"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 2, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output.answer.iter().any(|record| {
            if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("host")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    assert!(
        output.answer.iter().any(|record| {
            if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    Ok(())
}

#[test]
fn longer_chain() -> Result<(), Error> {
    let (_network, _graph, resolver, client) = setup_cname()?;
    let output = client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("alias2"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 3, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output.answer.iter().any(|record| {
            if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("host")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    assert!(
        output.answer.iter().any(|record| {
            if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    assert!(
        output.answer.iter().any(|record| {
            if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias2")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    Ok(())
}

#[test]
fn basic_cached() -> Result<(), Error> {
    let (_network, _graph, resolver, client) = setup_cname()?;
    client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("alias"),
    )?;
    let output = client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("alias"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 2, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output.answer.iter().any(|record| {
            if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("host")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    assert!(
        output.answer.iter().any(|record| {
            if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    Ok(())
}

#[test]
fn longer_chain_cached() -> Result<(), Error> {
    let (_network, _graph, resolver, client) = setup_cname()?;
    client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("alias2"),
    )?;
    let output = client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN.push_label("alias2"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 3, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output.answer.iter().any(|record| {
            if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("host")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    assert!(
        output.answer.iter().any(|record| {
            if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    assert!(
        output.answer.iter().any(|record| {
            if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("alias2")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    Ok(())
}

fn setup_cname() -> Result<(Network, Graph, Resolver, Client), Error> {
    let network = Network::new()?;
    let mut leaf_ns = NameServer::new(&PEER, FQDN::TEST_DOMAIN, &network)?;
    leaf_ns.add(A {
        fqdn: FQDN::TEST_DOMAIN.push_label("host"),
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 168, 1, 1),
    });
    leaf_ns.add(CNAME {
        fqdn: FQDN::TEST_DOMAIN.push_label("alias"),
        ttl: 3600,
        target: FQDN::TEST_DOMAIN.push_label("host"),
    });
    leaf_ns.add(CNAME {
        fqdn: FQDN::TEST_DOMAIN.push_label("alias2"),
        ttl: 3600,
        target: FQDN::TEST_DOMAIN.push_label("alias"),
    });

    let graph = Graph::build(leaf_ns, Sign::No)?;

    let resolver = Resolver::new(&network, graph.root.clone()).start()?;
    let client = Client::new(&network)?;

    Ok((network, graph, resolver, client))
}

#[test]
fn basic_cross_zone() -> Result<(), Error> {
    let (_network, _nameservers, resolver, client) = setup_cname_cross_zone()?;
    let output = client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::EXAMPLE_SUBDOMAIN.push_label("alias"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 2, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output.answer.iter().any(|record| {
            if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("other").push_label("host")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    assert!(
        output.answer.iter().any(|record| {
            if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::EXAMPLE_SUBDOMAIN.push_label("alias")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    Ok(())
}

#[test]
fn basic_cross_zone_cached() -> Result<(), Error> {
    let (_network, _nameservers, resolver, client) = setup_cname_cross_zone()?;
    client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::EXAMPLE_SUBDOMAIN.push_label("alias"),
    )?;
    let output = client.dig(
        *DigSettings::default().recurse(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::EXAMPLE_SUBDOMAIN.push_label("alias"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);
    assert_eq!(output.answer.len(), 2, "{:?}", output.answer);
    assert!(output.authority.is_empty(), "{:?}", output.authority);
    assert!(output.additional.is_empty(), "{:?}", output.additional);
    assert!(
        output.answer.iter().any(|record| {
            if let Record::A(A { fqdn, .. }) = record {
                fqdn == &FQDN::TEST_DOMAIN.push_label("other").push_label("host")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    assert!(
        output.answer.iter().any(|record| {
            if let Record::CNAME(CNAME { fqdn, .. }) = record {
                fqdn == &FQDN::EXAMPLE_SUBDOMAIN.push_label("alias")
            } else {
                false
            }
        }),
        "{:?}",
        output.answer
    );
    Ok(())
}

#[allow(clippy::type_complexity)]
fn setup_cname_cross_zone() -> Result<(Network, Vec<NameServer<Running>>, Resolver, Client), Error>
{
    let network = Network::new()?;
    let mut leaf_1_ns = NameServer::new(&PEER, FQDN::EXAMPLE_SUBDOMAIN, &network)?;
    leaf_1_ns.add(CNAME {
        fqdn: FQDN::EXAMPLE_SUBDOMAIN.push_label("alias"),
        ttl: 3600,
        target: FQDN::TEST_DOMAIN.push_label("other").push_label("host"),
    });
    let mut leaf_2_ns = NameServer::new(&PEER, FQDN::TEST_DOMAIN.push_label("other"), &network)?;
    leaf_2_ns.add(A {
        fqdn: FQDN::TEST_DOMAIN.push_label("other").push_label("host"),
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 168, 1, 1),
    });

    let mut domain_ns = NameServer::new(&PEER, FQDN::TEST_DOMAIN, &network)?;
    domain_ns.referral_nameserver(&leaf_1_ns);
    domain_ns.referral_nameserver(&leaf_2_ns);

    let mut tld_ns = NameServer::new(&PEER, FQDN::TEST_TLD, &network)?;
    tld_ns.referral_nameserver(&domain_ns);

    let mut root_ns = NameServer::new(&PEER, FQDN::ROOT, &network)?;
    root_ns.referral_nameserver(&tld_ns);
    let root = root_ns.root_hint();

    let nameservers = vec![
        leaf_1_ns.start()?,
        leaf_2_ns.start()?,
        domain_ns.start()?,
        tld_ns.start()?,
        root_ns.start()?,
    ];

    let resolver = Resolver::new(&network, root).start()?;
    let client = Client::new(&network)?;

    Ok((network, nameservers, resolver, client))
}

/// Tests how a non-validating resolver handles DNSSEC records when following a CNAME alias and
/// getting a positive response.
#[test]
fn signed_zone_positive() -> Result<(), Error> {
    let (_network, _nameservers, resolver, client) = setup_signed_zone()?;
    let output = client.dig(
        *DigSettings::default().recurse().dnssec(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::EXAMPLE_SUBDOMAIN.push_label("alias"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR, "{output:#?}");
    assert!(
        output.answer.iter().any(|record| {
            let Record::CNAME(CNAME { fqdn, .. }) = record else {
                return false;
            };
            fqdn.as_str() == "alias.example.hickory-dns.testing."
        }),
        "CNAME record is missing {output:#?}"
    );
    assert!(
        output.answer.iter().any(|record| {
            let Record::RRSIG(RRSIG { fqdn, .. }) = record else {
                return false;
            };
            fqdn.as_str() == "alias.example.hickory-dns.testing."
        }),
        "RRSIG record for CNAME is missing {output:#?}"
    );
    assert!(
        output.answer.iter().any(|record| {
            let Record::A(A { fqdn, .. }) = record else {
                return false;
            };
            fqdn.as_str() == "host.other.hickory-dns.testing."
        }),
        "A record is missing {output:#?}"
    );
    assert!(
        output.answer.iter().any(|record| {
            let Record::RRSIG(RRSIG { fqdn, .. }) = record else {
                return false;
            };
            fqdn.as_str() == "host.other.hickory-dns.testing."
        }),
        "RRSIG record for A is missing {output:#?}"
    );
    Ok(())
}

/// Tests how a non-validating resolver handles DNSSEC records when following a CNAME alias and
/// getting a negative response.
#[test]
fn signed_zone_negative() -> Result<(), Error> {
    let (_network, _nameservers, resolver, client) = setup_signed_zone()?;
    let output = client.dig(
        *DigSettings::default().recurse().dnssec(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::EXAMPLE_SUBDOMAIN.push_label("alias-negative"),
    )?;
    assert_eq!(output.status, DigStatus::NXDOMAIN, "{output:#?}");
    assert!(
        output.answer.iter().any(|record| {
            let Record::CNAME(CNAME { fqdn, .. }) = record else {
                return false;
            };
            fqdn.as_str() == "alias-negative.example.hickory-dns.testing."
        }),
        "CNAME record is missing {output:#?}"
    );
    assert!(
        output.answer.iter().any(|record| {
            let Record::RRSIG(RRSIG { fqdn, .. }) = record else {
                return false;
            };
            fqdn.as_str() == "alias-negative.example.hickory-dns.testing."
        }),
        "RRSIG record for CNAME is missing {output:#?}"
    );
    // Covers the target of the CNAME record:
    //
    //   $ nsec3hash -r 1 0 1 - wrong.other.hickory-dns.testing.
    //   wrong.other.hickory-dns.testing. NSEC3 1 0 1 - TV5CS5RQP27NUBADJ7H0Q3DE7T7F8VNA
    assert!(
        output.authority.iter().any(|record| {
            let Record::NSEC3(NSEC3 {
                fqdn,
                next_hashed_owner_name,
                ..
            }) = record
            else {
                return false;
            };
            fqdn.as_str() == "722c77kkod0lhnnr7d9rnbit9647rdus.other.hickory-dns.testing."
                && next_hashed_owner_name == "UVQ6A2S4RMV0MRON9KOT3N6TH7RGC8QM"
        }),
        "NSEC3 record covering name is missing {output:#?}"
    );
    assert!(
        output.authority.iter().any(|record| {
            let Record::RRSIG(RRSIG { fqdn, .. }) = record else {
                return false;
            };
            fqdn.as_str() == "722c77kkod0lhnnr7d9rnbit9647rdus.other.hickory-dns.testing."
        }),
        "RRSIG record for NSEC3 is missing {output:#?}"
    );
    // Matches the next closest encloser and covers the wildcard at it.
    //
    //   $ nsec3hash -r 1 0 1 - other.hickory-dns.testing.
    //   other.hickory-dns.testing. NSEC3 1 0 1 - UVQ6A2S4RMV0MRON9KOT3N6TH7RGC8QM
    //   $ nsec3hash -r 1 0 1 - *.other.hickory-dns.testing.
    //   *.other.hickory-dns.testing. NSEC3 1 0 1 - V5O27Q1MQGOT5GN79U1QIQEM1TKQHNAK
    assert!(
        output.authority.iter().any(|record| {
            let Record::NSEC3(NSEC3 {
                fqdn,
                next_hashed_owner_name,
                ..
            }) = record
            else {
                return false;
            };
            fqdn.as_str() == "uvq6a2s4rmv0mron9kot3n6th7rgc8qm.other.hickory-dns.testing."
                && next_hashed_owner_name == "3F1DNPG4E4GP4AU4IHFBSR2MEJLQTFOC"
        }),
        "NSEC3 record for wildcard proof is missing {output:#?}"
    );
    assert!(
        output.authority.iter().any(|record| {
            let Record::RRSIG(RRSIG { fqdn, .. }) = record else {
                return false;
            };
            fqdn.as_str() == "uvq6a2s4rmv0mron9kot3n6th7rgc8qm.other.hickory-dns.testing."
        }),
        "RRSIG record for NSEC3 is missing {output:#?}"
    );
    Ok(())
}

/// Tests how a non-validating resolver handles DNSSEC records when following a CNAME alias at a
/// wildcard name, and getting a positive response.
#[test]
fn signed_wildcard_cname_positive() -> Result<(), Error> {
    let (_network, _nameservers, resolver, client) = setup_signed_zone()?;
    let output = client.dig(
        *DigSettings::default().recurse().dnssec(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::EXAMPLE_SUBDOMAIN
            .push_label("wildcard")
            .push_label("a"),
    )?;
    assert_eq!(output.status, DigStatus::NOERROR, "{output:#?}");
    assert!(
        output.answer.iter().any(|record| {
            let Record::CNAME(CNAME { fqdn, .. }) = record else {
                return false;
            };
            fqdn.as_str() == "a.wildcard.example.hickory-dns.testing."
        }),
        "CNAME record is missing {output:#?}"
    );
    assert!(
        output.answer.iter().any(|record| {
            let Record::RRSIG(RRSIG { fqdn, .. }) = record else {
                return false;
            };
            fqdn.as_str() == "a.wildcard.example.hickory-dns.testing."
        }),
        "RRSIG record for CNAME is missing {output:#?}"
    );
    assert!(
        output.answer.iter().any(|record| {
            let Record::A(A { fqdn, .. }) = record else {
                return false;
            };
            fqdn.as_str() == "host.other.hickory-dns.testing."
        }),
        "A record is missing {output:#?}"
    );
    assert!(
        output.answer.iter().any(|record| {
            let Record::RRSIG(RRSIG { fqdn, .. }) = record else {
                return false;
            };
            fqdn.as_str() == "host.other.hickory-dns.testing."
        }),
        "RRSIG record for A is missing {output:#?}"
    );
    // Covers the query name:
    //
    //   $ nsec3hash -r 1 0 1 - a.wildcard.example.hickory-dns.testing.
    //   a.wildcard.example.hickory-dns.testing. NSEC3 1 0 1 - GUAC3Q6G2FI6QTTH3JSJ242EFP6R57I2
    assert!(
        output.authority.iter().any(|record| {
            let Record::NSEC3(NSEC3 {
                fqdn,
                next_hashed_owner_name,
                ..
            }) = record
            else {
                return false;
            };
            fqdn.as_str() == "8hk47tugdqehn13l08a2l9a7l29q25rj.example.hickory-dns.testing."
                && next_hashed_owner_name == "L8L2LQT9T5KG7FK253IDLC5534CQ3RNN"
        }),
        "NSEC3 record from zone with CNAME is missing {output:#?}"
    );
    assert!(
        output.authority.iter().any(|record| {
            let Record::RRSIG(RRSIG { fqdn, .. }) = record else {
                return false;
            };
            fqdn.as_str() == "8hk47tugdqehn13l08a2l9a7l29q25rj.example.hickory-dns.testing."
        }),
        "RRSIG record for NSEC3 is missing {output:#?}"
    );
    Ok(())
}

/// Tests how a non-validating resolver handles DNSSEC records when following a CNAME alias at a
/// wildcard name, and getting a negative response.
#[test]
fn signed_wildcard_cname_negative() -> Result<(), Error> {
    let (_network, _nameservers, resolver, client) = setup_signed_zone()?;
    let output = client.dig(
        *DigSettings::default().recurse().dnssec(),
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN::EXAMPLE_SUBDOMAIN
            .push_label("wildcard-negative")
            .push_label("a"),
    )?;
    assert_eq!(output.status, DigStatus::NXDOMAIN, "{output:#?}");
    assert!(
        output.answer.iter().any(|record| {
            let Record::CNAME(CNAME { fqdn, target, .. }) = record else {
                return false;
            };
            fqdn.as_str() == "a.wildcard-negative.example.hickory-dns.testing."
                && target.as_str() == "wrong.other.hickory-dns.testing."
        }),
        "CNAME record is missing {output:#?}"
    );
    assert!(
        output.answer.iter().any(|record| {
            let Record::RRSIG(RRSIG { fqdn, .. }) = record else {
                return false;
            };
            fqdn.as_str() == "a.wildcard-negative.example.hickory-dns.testing."
        }),
        "RRSIG record for CNAME is missing {output:#?}"
    );
    // Covers the query name:
    //
    //   $ nsec3hash -r 1 0 1 - a.wildcard-negative.example.hickory-dns.testing.
    //   a.wildcard-negative.example.hickory-dns.testing. NSEC3 1 0 1 - 8RLUPEAJKRATE893HJ62EIAUIQCJM676
    assert!(
        output.authority.iter().any(|record| {
            let Record::NSEC3(NSEC3 {
                fqdn,
                next_hashed_owner_name,
                ..
            }) = record
            else {
                return false;
            };
            fqdn.as_str() == "8hk47tugdqehn13l08a2l9a7l29q25rj.example.hickory-dns.testing."
                && next_hashed_owner_name == "L8L2LQT9T5KG7FK253IDLC5534CQ3RNN"
        }),
        "NSEC3 record from zone with CNAME is missing {output:#?}"
    );
    assert!(
        output.authority.iter().any(|record| {
            let Record::RRSIG(RRSIG { fqdn, .. }) = record else {
                return false;
            };
            fqdn.as_str() == "8hk47tugdqehn13l08a2l9a7l29q25rj.example.hickory-dns.testing."
        }),
        "RRSIG record for NSEC3 is missing {output:#?}"
    );
    // Covers the target of the CNAME record:
    //
    //   $ nsec3hash -r 1 0 1 - wrong.other.hickory-dns.testing.
    //   wrong.other.hickory-dns.testing. NSEC3 1 0 1 - TV5CS5RQP27NUBADJ7H0Q3DE7T7F8VNA
    assert!(
        output.authority.iter().any(|record| {
            let Record::NSEC3(NSEC3 {
                fqdn,
                next_hashed_owner_name,
                ..
            }) = record
            else {
                return false;
            };
            fqdn.as_str() == "722c77kkod0lhnnr7d9rnbit9647rdus.other.hickory-dns.testing."
                && next_hashed_owner_name == "UVQ6A2S4RMV0MRON9KOT3N6TH7RGC8QM"
        }),
        "NSEC3 record covering target name is missing {output:#?}"
    );
    assert!(
        output.authority.iter().any(|record| {
            let Record::RRSIG(RRSIG { fqdn, .. }) = record else {
                return false;
            };
            fqdn.as_str() == "722c77kkod0lhnnr7d9rnbit9647rdus.other.hickory-dns.testing."
        }),
        "RRSIG record for NSEC3 is missing {output:#?}"
    );
    // Matches the next closest encloser and covers the wildcard at it.
    //
    //   $ nsec3hash -r 1 0 1 - other.hickory-dns.testing.
    //   other.hickory-dns.testing. NSEC3 1 0 1 - UVQ6A2S4RMV0MRON9KOT3N6TH7RGC8QM
    //   $ nsec3hash -r 1 0 1 - *.other.hickory-dns.testing.
    //   *.other.hickory-dns.testing. NSEC3 1 0 1 - V5O27Q1MQGOT5GN79U1QIQEM1TKQHNAK
    assert!(
        output.authority.iter().any(|record| {
            let Record::NSEC3(NSEC3 {
                fqdn,
                next_hashed_owner_name,
                ..
            }) = record
            else {
                return false;
            };
            fqdn.as_str() == "uvq6a2s4rmv0mron9kot3n6th7rgc8qm.other.hickory-dns.testing."
                && next_hashed_owner_name == "3F1DNPG4E4GP4AU4IHFBSR2MEJLQTFOC"
        }),
        "NSEC3 record for wildcard proof is missing {output:#?}"
    );
    assert!(
        output.authority.iter().any(|record| {
            let Record::RRSIG(RRSIG { fqdn, .. }) = record else {
                return false;
            };
            fqdn.as_str() == "uvq6a2s4rmv0mron9kot3n6th7rgc8qm.other.hickory-dns.testing."
        }),
        "RRSIG record for NSEC3 is missing {output:#?}"
    );
    Ok(())
}

#[allow(clippy::type_complexity)]
fn setup_signed_zone() -> Result<(Network, Vec<NameServer<Running>>, Resolver, Client), Error> {
    let network = Network::new()?;

    let mut leaf_1_ns = NameServer::new(&PEER, FQDN::EXAMPLE_SUBDOMAIN, &network)?;
    leaf_1_ns.add(CNAME {
        fqdn: FQDN::EXAMPLE_SUBDOMAIN.push_label("alias"),
        ttl: 3600,
        target: FQDN::TEST_DOMAIN.push_label("other").push_label("host"),
    });
    leaf_1_ns.add(CNAME {
        fqdn: FQDN::EXAMPLE_SUBDOMAIN.push_label("alias-negative"),
        ttl: 3600,
        target: FQDN::TEST_DOMAIN.push_label("other").push_label("wrong"),
    });
    leaf_1_ns.add(CNAME {
        fqdn: FQDN::EXAMPLE_SUBDOMAIN
            .push_label("wildcard")
            .push_label("*"),
        ttl: 3600,
        target: FQDN::TEST_DOMAIN.push_label("other").push_label("host"),
    });
    leaf_1_ns.add(CNAME {
        fqdn: FQDN::EXAMPLE_SUBDOMAIN
            .push_label("wildcard-negative")
            .push_label("*"),
        ttl: 3600,
        target: FQDN::TEST_DOMAIN.push_label("other").push_label("wrong"),
    });
    let leaf_1_ns = leaf_1_ns.sign(SignSettings::default())?;

    let mut leaf_2_ns = NameServer::new(&PEER, FQDN::TEST_DOMAIN.push_label("other"), &network)?;
    leaf_2_ns.add(A {
        fqdn: FQDN::TEST_DOMAIN.push_label("other").push_label("host"),
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 168, 1, 1),
    });
    let leaf_2_ns = leaf_2_ns.sign(SignSettings::default())?;

    let mut domain_ns = NameServer::new(&PEER, FQDN::TEST_DOMAIN, &network)?;
    domain_ns.referral_nameserver(&leaf_1_ns);
    domain_ns.add(leaf_1_ns.ds().ksk.clone());
    domain_ns.referral_nameserver(&leaf_2_ns);
    domain_ns.add(leaf_2_ns.ds().ksk.clone());
    let domain_ns = domain_ns.sign(SignSettings::default())?;

    let mut tld_ns = NameServer::new(&PEER, FQDN::TEST_TLD, &network)?;
    tld_ns.referral_nameserver(&domain_ns);
    tld_ns.add(domain_ns.ds().ksk.clone());
    let tld_ns = tld_ns.sign(SignSettings::default())?;

    let mut root_ns = NameServer::new(&PEER, FQDN::ROOT, &network)?;
    root_ns.referral_nameserver(&tld_ns);
    root_ns.add(tld_ns.ds().ksk.clone());
    let root_ns = root_ns.sign(SignSettings::default())?;

    let root = root_ns.root_hint();
    let nameservers = vec![
        leaf_1_ns.start()?,
        leaf_2_ns.start()?,
        domain_ns.start()?,
        tld_ns.start()?,
        root_ns.start()?,
    ];

    let resolver = Resolver::new(&network, root).start()?;
    let client = Client::new(&network)?;

    Ok((network, nameservers, resolver, client))
}
