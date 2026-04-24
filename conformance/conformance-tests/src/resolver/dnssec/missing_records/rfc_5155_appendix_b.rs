use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
};

use dns_test::{
    Error, FQDN, Network, PEER,
    client::DigStatus,
    name_server::{NameServer, Signed},
    record::{A, AAAA, DS, HINFO, MX, NS, NSEC3PARAM, RecordType, SOA, SoaSettings},
    zone_file::SignSettings,
};

use crate::resolver::dnssec::missing_records::test_record_removal_validation_failure;

#[test]
fn test_zone_construction() -> Result<(), Error> {
    let network = Network::new()?;
    let ns = build_zone(&network)?;
    let zone = ns.signed_zone_file();
    let names = zone
        .records
        .iter()
        .map(|record| record.name().as_str().to_lowercase())
        .collect::<HashSet<_>>();

    let expected = [
        "example.",
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.",
        "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.",
        "2vptu5timamqttgl4luu9kg21e0aor3s.example.",
        "35mthgpgcu1qg68fab165klnsnk3dpvl.example.",
        "a.example.",
        "ns1.a.example.",
        "ns2.a.example.",
        "ai.example.",
        "b4um86eghhds6nea196smvmlo4ors995.example.",
        "c.example.",
        "ns1.c.example.",
        "ns2.c.example.",
        "gjeqe526plbf1g8mklp59enfd789njgi.example.",
        "ji6neoaepv8b5o6k4ev33abha8ht9fgc.example.",
        "k8udemvp1j2f7eg6jebps17vp3n8i58h.example.",
        "kohar7mbb8dc2ce8a9qvl8hon4k53uhi.example.",
        "ns1.example.",
        "ns2.example.",
        "q04jkcevqvmu85r014c7dkba38o0ji5r.example.",
        "r53bq7cc2uvmubfu5ocmm6pers9tk9en.example.",
        "t644ebqk9bibcna874givr6joj62mlhv.example.",
        "*.w.example.",
        "x.w.example.",
        "x.y.w.example.",
        "xx.example.",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<HashSet<_>>();

    assert_eq!(
        names,
        expected,
        "differences: {:?} {:?}",
        names.difference(&expected),
        expected.difference(&names)
    );

    Ok(())
}

/// Based on RFC 5155 section B.1.
#[test]
fn name_error() -> Result<(), Error> {
    let network = Network::new()?;
    let leaf_ns = build_zone(&network)?;
    let original_response = test_record_removal_validation_failure(
        vec![leaf_ns],
        Vec::new(),
        FQDN("a.c.x.w.example.")?,
        RecordType::A,
        &[
            // Covers "next closer" name.
            (
                FQDN("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.")?,
                RecordType::NSEC3,
            ),
            // Matches closest encloser.
            (
                FQDN("b4um86eghhds6nea196smvmlo4ors995.example.")?,
                RecordType::NSEC3,
            ),
            // Covers wildcard at closest encloser.
            (
                FQDN("35mthgpgcu1qg68fab165klnsnk3dpvl.example.")?,
                RecordType::NSEC3,
            ),
        ],
        &network,
    )?;
    assert_eq!(original_response.status, DigStatus::NXDOMAIN);
    Ok(())
}

/// Based on RFC 5155 section B.2.
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
            // Matches query.
            (
                FQDN("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.")?,
                RecordType::NSEC3,
            ),
        ],
        &network,
    )?;
    assert_eq!(original_response.status, DigStatus::NOERROR);
    Ok(())
}

/// Based on RFC 5155 section B.2.1.
#[test]
fn no_data_error_empty_non_terminal() -> Result<(), Error> {
    let network = Network::new()?;
    let leaf_ns = build_zone(&network)?;
    let original_response = test_record_removal_validation_failure(
        vec![leaf_ns],
        Vec::new(),
        FQDN("y.w.example.")?,
        RecordType::A,
        &[
            // Matches query.
            (
                FQDN("ji6neoaepv8b5o6k4ev33abha8ht9fgc.example.")?,
                RecordType::NSEC3,
            ),
        ],
        &network,
    )?;
    assert_eq!(original_response.status, DigStatus::NOERROR);
    assert!(original_response.answer.is_empty());
    Ok(())
}

/// Based on RFC 5155 section B.4.
#[test]
#[ignore = "hickory recursor does not include NSEC3 records proving wildcard expansion"]
fn wildcard_expansion() -> Result<(), Error> {
    let network = Network::new()?;
    let leaf_ns = build_zone(&network)?;
    let original_response = test_record_removal_validation_failure(
        vec![leaf_ns],
        Vec::new(),
        FQDN("a.z.w.example.")?,
        RecordType::MX,
        &[
            // Covers "next closer" name.
            (
                FQDN("q04jkcevqvmu85r014c7dkba38o0ji5r.example.")?,
                RecordType::NSEC3,
            ),
        ],
        &network,
    )?;
    assert_eq!(original_response.status, DigStatus::NOERROR);
    assert!(!original_response.answer.is_empty());
    Ok(())
}

/// Based on RFC 5155 section B.5.
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
            // Matches closest encloser.
            (
                FQDN("k8udemvp1j2f7eg6jebps17vp3n8i58h.example.")?,
                RecordType::NSEC3,
            ),
            // Covers "next closer" name.
            (
                FQDN("q04jkcevqvmu85r014c7dkba38o0ji5r.example.")?,
                RecordType::NSEC3,
            ),
            // Matches wildcard at closest encloser.
            //
            // Excluding this record doesn't cause validation failures with any
            // server for unknown reasons.
            // (
            //     FQDN("r53bq7cc2uvmubfu5ocmm6pers9tk9en.example.")?,
            //     RecordType::NSEC3,
            // ),
        ],
        &network,
    )?;
    assert_eq!(original_response.status, DigStatus::NOERROR);
    assert!(original_response.answer.is_empty());
    Ok(())
}

/// Construct a name server with a zone similar to that in RFC 5155 Appendix A.
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
            serial: 0,
            refresh: 3600,
            retry: 300,
            expire: 3600000,
            minimum: 3600,
        },
    };

    ns.add(NSEC3PARAM {
        zone: FQDN("example.")?,
        ttl: 3600,
        hash_alg: 1,
        flags: 0,
        iterations: 12,
        salt: b"\xaa\xbb\xcc\xdd".to_vec(),
    });
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
    ns.add(A {
        fqdn: FQDN("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.")?,
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 0, 2, 127),
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
        key_tag: 58470,
        algorithm: 5,
        digest_type: 1,
        digest: "3079F1593EBAD6DC121E202A8B766A6A4837206C".to_owned(),
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
        cpu: "KLH-10".to_owned(),
        os: "ITS".to_owned(),
    });
    ns.add(AAAA {
        fqdn: FQDN("ai.example.")?,
        ttl: 3600,
        ipv6_addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0xf00, 0xbaa9),
    });
    ns.add(NS {
        zone: FQDN("c.example.")?,
        ttl: 3600,
        nameserver: FQDN("ns1.c.example.")?,
    });
    ns.add(NS {
        zone: FQDN("c.example.")?,
        ttl: 3600,
        nameserver: FQDN("ns2.c.example.")?,
    });
    ns.add(A {
        fqdn: FQDN("ns1.c.example.")?,
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 0, 2, 7),
    });
    ns.add(A {
        fqdn: FQDN("ns2.c.example.")?,
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
        cpu: "KLH-10".to_owned(),
        os: "TOPS-20".to_owned(),
    });
    ns.add(AAAA {
        fqdn: FQDN("xx.example.")?,
        ttl: 3600,
        ipv6_addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0xf00, 0xbaaa),
    });

    let sign_settings =
        SignSettings::ecdsap256sha256_nsec3_optout().nsec(dns_test::zone_file::Nsec::_3 {
            iterations: 12,
            opt_out: true,
            salt: Some("aabbccdd".to_owned()),
        });
    let ns = ns.sign(sign_settings)?;
    Ok(ns)
}
