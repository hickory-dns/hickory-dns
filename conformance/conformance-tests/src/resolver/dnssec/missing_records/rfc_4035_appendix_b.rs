use std::net::{Ipv4Addr, Ipv6Addr};

use dns_test::{
    Error, FQDN, Network, PEER,
    client::DigStatus,
    name_server::{NameServer, Signed},
    record::{A, AAAA, DS, HINFO, MX, NS, NSEC, Record, RecordType, SOA, SoaSettings},
    zone_file::{Nsec, SignSettings},
};

use crate::resolver::dnssec::missing_records::test_record_removal_validation_failure;

#[test]
fn test_zone_construction() -> Result<(), Error> {
    let network = Network::new()?;
    let ns = build_zone(&network)?;
    let zone = ns.signed_zone_file();
    let mut nsec_records = zone
        .records
        .iter()
        .filter_map(|record| {
            if let Record::NSEC(nsec) = record {
                Some(nsec.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let mut expected = [
        NSEC {
            fqdn: FQDN("example.")?,
            ttl: 3600,
            next_domain: FQDN("a.example.")?,
            record_types: vec![
                RecordType::NS,
                RecordType::SOA,
                RecordType::MX,
                RecordType::RRSIG,
                RecordType::NSEC,
                RecordType::DNSKEY,
            ],
        },
        NSEC {
            fqdn: FQDN("a.example.")?,
            ttl: 3600,
            next_domain: FQDN("ai.example.")?,
            record_types: vec![
                RecordType::NS,
                RecordType::DS,
                RecordType::RRSIG,
                RecordType::NSEC,
            ],
        },
        NSEC {
            fqdn: FQDN("ai.example.")?,
            ttl: 3600,
            next_domain: FQDN("b.example.")?,
            record_types: vec![
                RecordType::A,
                RecordType::HINFO,
                RecordType::AAAA,
                RecordType::RRSIG,
                RecordType::NSEC,
            ],
        },
        NSEC {
            fqdn: FQDN("b.example.")?,
            ttl: 3600,
            next_domain: FQDN("ns1.example.")?,
            record_types: vec![RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
        },
        NSEC {
            fqdn: FQDN("ns1.example.")?,
            ttl: 3600,
            next_domain: FQDN("ns2.example.")?,
            record_types: vec![RecordType::A, RecordType::RRSIG, RecordType::NSEC],
        },
        NSEC {
            fqdn: FQDN("ns2.example.")?,
            ttl: 3600,
            next_domain: FQDN("*.w.example.")?,
            record_types: vec![RecordType::A, RecordType::RRSIG, RecordType::NSEC],
        },
        NSEC {
            fqdn: FQDN("*.w.example.")?,
            ttl: 3600,
            next_domain: FQDN("x.w.example.")?,
            record_types: vec![RecordType::MX, RecordType::RRSIG, RecordType::NSEC],
        },
        NSEC {
            fqdn: FQDN("x.w.example.")?,
            ttl: 3600,
            next_domain: FQDN("x.y.w.example.")?,
            record_types: vec![RecordType::MX, RecordType::RRSIG, RecordType::NSEC],
        },
        NSEC {
            fqdn: FQDN("x.y.w.example.")?,
            ttl: 3600,
            next_domain: FQDN("xx.example.")?,
            record_types: vec![RecordType::MX, RecordType::RRSIG, RecordType::NSEC],
        },
        NSEC {
            fqdn: FQDN("xx.example.")?,
            ttl: 3600,
            next_domain: FQDN("example.")?,
            record_types: vec![
                RecordType::A,
                RecordType::HINFO,
                RecordType::AAAA,
                RecordType::RRSIG,
                RecordType::NSEC,
            ],
        },
    ];

    let cmp = |a: &NSEC, b: &NSEC| a.fqdn.as_str().cmp(b.fqdn.as_str());
    nsec_records.sort_by(cmp);
    expected.sort_by(cmp);

    assert_eq!(nsec_records, expected);
    Ok(())
}

/// Based on RFC 4035 section B.2.
#[test]
fn name_error() -> Result<(), Error> {
    let network = Network::new()?;
    let leaf_ns = build_zone(&network)?;
    let original_response = test_record_removal_validation_failure(
        vec![leaf_ns],
        Vec::new(),
        FQDN("ml.example.")?,
        RecordType::A,
        &[
            // Proves name does not exist.
            (FQDN("b.example.")?, RecordType::NSEC),
            // Proves covering wildcard name does not exist.
            (FQDN("example.")?, RecordType::NSEC),
        ],
        &network,
    )?;
    assert_eq!(original_response.status, DigStatus::NXDOMAIN);
    Ok(())
}

/// Based on RFC 4035 section B.3.
#[test]
fn no_data_error() -> Result<(), Error> {
    let network = Network::new()?;
    let leaf_ns = build_zone(&network)?;
    let original_response = test_record_removal_validation_failure(
        vec![leaf_ns],
        Vec::new(),
        FQDN("ns1.example.")?,
        RecordType::MX,
        &[
            // Proves the requested RR type does not exist.
            (FQDN("ns1.example.")?, RecordType::NSEC),
        ],
        &network,
    )?;
    assert_eq!(original_response.status, DigStatus::NOERROR);
    Ok(())
}

/// Based on RFC 4035 section B.6.
#[test]
#[ignore = "hickory recursor does not include NSEC record proving wildcard expansion"]
fn wildcard_expansion() -> Result<(), Error> {
    let network = Network::new()?;
    let leaf_ns = build_zone(&network)?;
    let original_response = test_record_removal_validation_failure(
        vec![leaf_ns],
        Vec::new(),
        FQDN("a.z.w.example.")?,
        RecordType::MX,
        &[
            // Proves the requested RR type does not exist.
            (FQDN("x.y.w.example.")?, RecordType::NSEC),
        ],
        &network,
    )?;
    assert_eq!(original_response.status, DigStatus::NOERROR);
    assert!(!original_response.answer.is_empty());
    Ok(())
}

/// Based on RFC 4035 section B.7.
#[test]
fn wildcard_no_data_error() -> Result<(), Error> {
    let network = Network::new()?;
    let leaf_ns = build_zone(&network)?;
    let original_response = test_record_removal_validation_failure(
        vec![leaf_ns],
        Vec::new(),
        FQDN("a.z.w.example.")?,
        RecordType::AAAA,
        &[
            // Proves that the matching wildcard name does not have the requested RR type.
            (FQDN("x.y.w.example.")?, RecordType::NSEC),
            // Proves that no closer match exists.
            (FQDN("*.w.example.")?, RecordType::NSEC),
        ],
        &network,
    )?;
    assert_eq!(original_response.status, DigStatus::NOERROR);
    assert!(original_response.answer.is_empty());
    Ok(())
}

/// Construct a name server with a zone similar to that in RFC 4035 Appendix A.
fn build_zone(network: &Network) -> Result<NameServer<Signed>, Error> {
    let mut ns = NameServer::builder(PEER.clone(), FQDN("example.")?, network.clone())
        .nameserver_fqdn(FQDN("ns1.example.")?)
        .rname_fqdn(FQDN("admin.nameservers.net.")?)
        .build()?;
    // Remove NS and A record automatically added when building server.
    ns.zone_file_mut().records.clear();

    ns.zone_file_mut().soa = SOA {
        zone: FQDN("example.")?,
        ttl: 3600,
        nameserver: FQDN("ns1.example.")?,
        admin: FQDN("bugs.x.w.example.")?,
        settings: SoaSettings {
            serial: 1081539377,
            refresh: 3600,
            retry: 300,
            expire: 3600000,
            minimum: 3600,
        },
    };

    ns.add(NS {
        zone: FQDN("example.")?,
        ttl: 3600,
        nameserver: FQDN("ns1.example.")?,
    });
    ns.add(NS {
        zone: FQDN("example.")?,
        ttl: 3600,
        nameserver: FQDN("ns2.example.")?,
    });
    ns.add(MX {
        fqdn: FQDN("example.")?,
        ttl: 3600,
        preference: 1,
        exchange: FQDN("xx.example.")?,
    });
    ns.add(NS {
        zone: FQDN("a.example.")?,
        ttl: 3600,
        nameserver: FQDN("ns1.a.example.")?,
    });
    ns.add(NS {
        zone: FQDN("a.example.")?,
        ttl: 3600,
        nameserver: FQDN("ns2.a.example.")?,
    });
    ns.add(DS {
        zone: FQDN("a.example.")?,
        ttl: 3600,
        key_tag: 57855,
        algorithm: 5,
        digest_type: 1,
        digest: "B6DCD485719ADCA18E5F3D48A2331627FDD3636B".to_string(),
    });
    ns.add(A {
        fqdn: FQDN("ns1.a.example.")?,
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 0, 2, 5),
    });
    ns.add(A {
        fqdn: FQDN("ns2.a.example.")?,
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 0, 2, 6),
    });
    ns.add(A {
        fqdn: FQDN("ai.example.")?,
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 0, 2, 9),
    });
    ns.add(HINFO {
        fqdn: FQDN("ai.example.")?,
        ttl: 3600,
        cpu: "KLH-10".to_string(),
        os: "ITS".to_string(),
    });
    ns.add(AAAA {
        fqdn: FQDN("ai.example.")?,
        ttl: 3600,
        ipv6_addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0xf00, 0xbaa9),
    });
    ns.add(NS {
        zone: FQDN("b.example.")?,
        ttl: 3600,
        nameserver: FQDN("ns1.b.example.")?,
    });
    ns.add(NS {
        zone: FQDN("b.example.")?,
        ttl: 3600,
        nameserver: FQDN("ns2.b.example.")?,
    });
    ns.add(A {
        fqdn: FQDN("ns1.b.example.")?,
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 0, 2, 7),
    });
    ns.add(A {
        fqdn: FQDN("ns2.b.example.")?,
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 0, 2, 8),
    });
    ns.add(A {
        fqdn: FQDN("ns1.example.")?,
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 0, 2, 1),
    });
    ns.add(A {
        fqdn: FQDN("ns2.example.")?,
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 0, 2, 2),
    });
    ns.add(MX {
        fqdn: FQDN("*.w.example.")?,
        ttl: 3600,
        preference: 1,
        exchange: FQDN("ai.example.")?,
    });
    ns.add(MX {
        fqdn: FQDN("x.w.example.")?,
        ttl: 3600,
        preference: 1,
        exchange: FQDN("xx.example.")?,
    });
    ns.add(MX {
        fqdn: FQDN("x.y.w.example.")?,
        ttl: 3600,
        preference: 1,
        exchange: FQDN("xx.example.")?,
    });
    ns.add(A {
        fqdn: FQDN("xx.example.")?,
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 0, 2, 10),
    });
    ns.add(HINFO {
        fqdn: FQDN("xx.example.")?,
        ttl: 3600,
        cpu: "KLH-10".to_string(),
        os: "TOPS-20".to_string(),
    });
    ns.add(AAAA {
        fqdn: FQDN("xx.example.")?,
        ttl: 3600,
        ipv6_addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0xf00, 0xbaaa),
    });

    // Use dnssec-signzone instead of ldns-signzone again. It seems ldns-signzone is including
    // occluded records below referrals in the NSEC chain. This causes differences from the zone in
    // Appendix A.
    let ns = ns.sign(SignSettings::ecdsap256sha256_nsec3_optout().nsec(Nsec::_1))?;
    Ok(ns)
}
