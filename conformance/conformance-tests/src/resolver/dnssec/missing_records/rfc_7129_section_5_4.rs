use std::net::Ipv4Addr;

use dns_test::{
    Error, FQDN, Network, PEER, SUBJECT,
    name_server::{NameServer, Signed},
    record::{A, CNAME, Record, RecordType, TXT},
    zone_file::{Nsec, SignSettings},
};

use crate::resolver::dnssec::missing_records::test_record_removal_validation_failure;

#[test]
#[ignore = "hickory does not include all NSEC records from CNAME chasing"]
fn wildcard_cname() -> Result<(), Error> {
    if SUBJECT.is_unbound() {
        // Excluding NSEC records from this response doesn't cause failures in Unbound. The RFCs are
        // not clear on what responses should be treated as valid or bogus, especially when CNAME
        // records are involved.
        //
        // For example, note that an authoritative server's response would typically only include a
        // CNAME record, and not any records at the CNAME record's target name, while most recursive
        // resolvers will perform CNAME chasing, and include records at the target name.
        //
        // When responses in this test have certain NSEC records excluded, the response could be
        // viewed as a resolver response that stopped CNAME chasing early, plus some additional
        // records that have a valid RRSIG, but no valid wildcard proof. It is not clear from the
        // response itself what intent the server had regarding how many steps of CNAME chasing to
        // perform, and whether the response's response code reflects the presence of a CNAME
        // record, or the presence of the ultimate A record at the end of the CNAME chain. It is
        // also not clear whether the presence of "extra" records in a response should cause a
        // SERVFAIL response if they are bogus, if they lack a wildcard proof, or if they are in
        // different sections of the response.
        return Ok(());
    }

    let network = Network::new()?;
    let leaf_ns = build_zone(&network)?;
    let original_response = test_record_removal_validation_failure(
        vec![leaf_ns],
        Vec::new(),
        FQDN("w.hickory-dns.testing.")?,
        RecordType::A,
        &[
            (FQDN("*.a.hickory-dns.testing.")?, RecordType::NSEC),
            (FQDN("*.b.hickory-dns.testing.")?, RecordType::NSEC),
            (FQDN("*.c.hickory-dns.testing.")?, RecordType::NSEC),
        ],
        &network,
    )?;
    assert!(
        original_response
            .answer
            .iter()
            .any(|record| matches!(record, Record::A(_)))
    );
    assert!(original_response.answer.iter().any(|record| {
        let Record::CNAME(cname) = record else {
            return false;
        };
        cname.fqdn.as_str() == "w.hickory-dns.testing."
    }));
    assert!(original_response.answer.iter().any(|record| {
        let Record::CNAME(cname) = record else {
            return false;
        };
        cname.fqdn.as_str() == "w.a.hickory-dns.testing."
    }));
    assert!(original_response.answer.iter().any(|record| {
        let Record::CNAME(cname) = record else {
            return false;
        };
        cname.fqdn.as_str() == "w.b.hickory-dns.testing."
    }));
    Ok(())
}

/// Construct a name server with a zone similar to that described in RFC 7129 section 5.4.
fn build_zone(network: &Network) -> Result<NameServer<Signed>, Error> {
    let mut ns = NameServer::new(&PEER, FQDN::TEST_DOMAIN, network)?;
    ns.add(TXT {
        fqdn: FQDN("*.hickory-dns.testing.")?,
        ttl: 3600,
        character_strings: vec!["wildcard record".to_string()],
    });
    ns.add(A {
        fqdn: FQDN("a.hickory-dns.testing.")?,
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 0, 2, 1),
    });
    ns.add(TXT {
        fqdn: FQDN("a.hickory-dns.testing.")?,
        ttl: 3600,
        character_strings: vec!["a record".to_string()],
    });
    ns.add(CNAME {
        fqdn: FQDN("*.a.hickory-dns.testing.")?,
        ttl: 3600,
        target: FQDN("w.b.hickory-dns.testing.")?,
    });
    ns.add(CNAME {
        fqdn: FQDN("*.b.hickory-dns.testing.")?,
        ttl: 3600,
        target: FQDN("w.c.hickory-dns.testing.")?,
    });
    ns.add(A {
        fqdn: FQDN("*.c.hickory-dns.testing.")?,
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 0, 2, 1),
    });
    ns.add(A {
        fqdn: FQDN("d.hickory-dns.testing.")?,
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 0, 2, 1),
    });
    ns.add(TXT {
        fqdn: FQDN("d.hickory-dns.testing.")?,
        ttl: 3600,
        character_strings: vec!["d record".to_string()],
    });
    ns.add(CNAME {
        fqdn: FQDN("w.hickory-dns.testing.")?,
        ttl: 3600,
        target: FQDN("w.a.hickory-dns.testing.")?,
    });

    let ns = ns.sign(SignSettings::default().nsec(Nsec::_1))?;

    Ok(ns)
}
