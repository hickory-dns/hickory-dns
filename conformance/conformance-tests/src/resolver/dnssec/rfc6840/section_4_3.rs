//! These tests checks whether a resolver correctly treats responses as bogus if
//! an NSEC or NSEC3 record indicates there is a CNAME record at the QNAME, but
//! the response does not include it.
//!
//! > 4.3.  Check for CNAME
//!
//! > Section 5 of RFC4035 says nothing explicit about validating
//! > responses based on (or that should be based on) CNAMEs.  When
//! > validating a NOERROR/NODATA response, validators MUST check the CNAME
//! > bit in the matching NSEC or NSEC3 RR's type bitmap in addition to the
//! > bit for the query type.
//!
//! > Without this check, an attacker could successfully transform a
//! > positive CNAME response into a NOERROR/NODATA response by (for
//! > example) simply stripping the CNAME RRset from the response.  A naive
//! > validator would then note that the QTYPE was not present in the
//! > matching NSEC/NSEC3 RR, but fail to notice that the CNAME bit was
//! > set; thus, the response should have been a positive CNAME response.
//!
//! <https://datatracker.ietf.org/doc/html/rfc6840#section-4.3>
//!
//! A proxy server sits in front of the authoritative server in order to forge
//! responses that exercise checks related to this requirement. When the
//! resolver sends a request for `alias.hickory-dns.testing.`, instead of
//! returning the correct CNAME record, the proxy will make a request for a
//! different name, and use the DNSSEC records it receives to craft its own
//! response.

use std::net::Ipv4Addr;

use dns_test::{
    Error, FQDN, Implementation, Network, PEER, Resolver,
    client::{Client, DigSettings, DigStatus},
    name_server::NameServer,
    record::{A, CNAME, Record, RecordType},
    zone_file::{Nsec, SignSettings},
};

#[test]
fn nodata_check_cname_bit_nsec() -> Result<(), Error> {
    nodata_check_cname_bit(Nsec::_1)
}

#[test]
fn nodata_check_cname_bit_nsec3() -> Result<(), Error> {
    nodata_check_cname_bit(Nsec::_3 {
        iterations: 1,
        opt_out: false,
        salt: None,
    })
}

fn nodata_check_cname_bit(nsec: Nsec) -> Result<(), Error> {
    let network = Network::new()?;
    let mut leaf_ns = NameServer::new(&PEER, FQDN::TEST_DOMAIN, &network)?;
    leaf_ns.add(CNAME {
        fqdn: FQDN("alias.hickory-dns.testing.")?,
        ttl: 3600,
        target: FQDN("www.hickory-dns.testing.")?,
    });
    leaf_ns.add(A {
        fqdn: FQDN("www.hickory-dns.testing.")?,
        ttl: 3600,
        ipv4_addr: Ipv4Addr::new(192, 168, 0, 1),
    });

    let leaf_ns = leaf_ns.sign(SignSettings::default().nsec(nsec))?;
    let proxy_ns = NameServer::new(
        &Implementation::test_server(
            "bogus_no_data_instead_of_cname",
            vec![leaf_ns.ipv4_addr().to_string()],
            "both",
        ),
        leaf_ns.zone().clone(),
        &network,
    )?;
    let mut root_ns = NameServer::new(&PEER, FQDN::ROOT, &network)?;
    root_ns.referral_nameserver(&proxy_ns);
    root_ns.add(leaf_ns.ds().ksk.clone());
    let root_ns = root_ns.sign(SignSettings::default())?;
    let trust_anchor = root_ns.trust_anchor();
    let root_ns = root_ns.start()?;
    let leaf_ns = leaf_ns.start()?;
    let proxy_ns = proxy_ns.start()?;

    let client = Client::new(&network)?;

    // Confirm the authoritative server and proxy are producing the expected NSEC or NSEC3 records
    // in their responses.
    //
    // The "real" query is for `alias.hickory-dns.testing.`, while the proxy queries for
    // `alias9.hickory-dns.testing.` in order to fetch the DNSSEC records it needs. The latter name
    // was chosen so that it includes whichever NSEC or NSEC3 record matches the name
    // `alias.hickory-dns.testing.`. Note that if we queried the real authoritative name server for
    // this same name, we would not get any NSEC or NSEC3 records at all, just the CNAME record and
    // its RRSIG, since we'd get a positive response. By instead making a query for a name that
    // doesn't exist, we ensure that we'll get some record nonexistence proof.
    //
    // When we use NSEC records, `alias9.hickory-dns.testing.` follows shortly after
    // `alias.hickory-dns.testing.` due to the canonical DNS name order. When we use NSEC3 records,
    // `alias9.hickory-dns.testing.` follows shortly after `alias.hickory-dns.testing.` because the
    // relevant hash values are as follows.
    //
    //   $ nsec3hash -r 1 0 1 - alias.hickory-dns.testing.
    //   alias.hickory-dns.testing. NSEC3 1 0 1 - 2K7LM9HEA6P5C02C1UFTIABK7MMQ98QC
    //   $ nsec3hash -r 1 0 1 - alias9.hickory-dns.testing.
    //   alias9.hickory-dns.testing. NSEC3 1 0 1 - 2NTM19O86SIHKN6OEDAFCUS4E81J0F2H
    //
    // In both cases, we get the record matching the original query name, so we can build our bogus
    // no data response.
    let auth_dig_settings = *DigSettings::default().dnssec();
    let response = client.dig(
        auth_dig_settings,
        leaf_ns.ipv4_addr(),
        RecordType::A,
        &FQDN("alias9.hickory-dns.testing.")?,
    )?;
    let nsec_present = response.authority.iter().any(|record| {
        let Record::NSEC(nsec) = record else {
            return false;
        };
        nsec.fqdn.as_str() == "alias.hickory-dns.testing."
    });
    let nsec3_present = response.authority.iter().any(|record| {
        let Record::NSEC3(nsec3) = record else {
            return false;
        };
        nsec3.fqdn.as_str().to_lowercase()
            == "2k7lm9hea6p5c02c1uftiabk7mmq98qc.hickory-dns.testing."
    });
    assert!(
        nsec_present || nsec3_present,
        "expected NSEC/NSEC3 records missing from authoritative server response\n{response:#?}"
    );

    let response = client.dig(
        auth_dig_settings,
        proxy_ns.ipv4_addr(),
        RecordType::A,
        &FQDN("alias.hickory-dns.testing.")?,
    )?;
    let nsec_present = response.authority.iter().any(|record| {
        let Record::NSEC(nsec) = record else {
            return false;
        };
        nsec.fqdn.as_str() == "alias.hickory-dns.testing."
    });
    let nsec3_present = response.authority.iter().any(|record| {
        let Record::NSEC3(nsec3) = record else {
            return false;
        };
        nsec3.fqdn.as_str().to_lowercase()
            == "2k7lm9hea6p5c02c1uftiabk7mmq98qc.hickory-dns.testing."
    });
    assert!(
        nsec_present || nsec3_present,
        "expected NSEC/NSEC3 records missing from proxy server response\n{response:#?}"
    );

    let resolver = Resolver::new(&network, root_ns.root_hint())
        .trust_anchor(&trust_anchor)
        .start()?;
    let recursive_dig_settings = *DigSettings::default().recurse().dnssec().authentic_data();
    let response = client.dig(
        recursive_dig_settings,
        resolver.ipv4_addr(),
        RecordType::A,
        &FQDN("alias.hickory-dns.testing.")?,
    )?;

    assert_eq!(response.status, DigStatus::SERVFAIL, "{response:#?}");

    Ok(())
}
