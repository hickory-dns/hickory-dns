//! These tests check DNSSEC validation of bogus positive responses with wildcard expansion, where
//! the zone dictates a NODATA response should be returned, with no wildcard expansion.
//!
//! In these tests, a query is made for some name that exists, and a malicious party repurposes
//! records to forge a positive response with a wildcard-expanded record. Since the queried name
//! exists, wildcard expansion should not be performed, even if no records of the queried type exist
//! at the query name.
//!
//! Forged responses are formed by a malicious proxy in front of an honest name server. The answer
//! section of the forged response is taken from an honest response for a different query name which
//! should trigger wildcard expansion. NSEC3 (and RRSIG) records for the query name are taken from
//! an honest response for the original query.

use std::net::Ipv4Addr;

use dns_test::{
    Error, FQDN, Implementation, Network, PEER, Resolver, SUBJECT,
    client::{Client, DigSettings, DigStatus},
    name_server::NameServer,
    record::{Record, RecordType, TXT},
    zone_file::{Nsec, SignSettings},
};

#[test]
fn bogus_wildcard_expansion_qname_exists_one_label() -> Result<(), Error> {
    bogus_wildcard_expansion_qname_exists(
        FQDN::TEST_DOMAIN.push_label("*"),
        FQDN::TEST_DOMAIN.push_label("a"),
    )
}

#[test]
fn bogus_wildcard_expansion_qname_exists_many_labels() -> Result<(), Error> {
    bogus_wildcard_expansion_qname_exists(
        FQDN::TEST_DOMAIN
            .push_label("a")
            .push_label("b")
            .push_label("c")
            .push_label("*"),
        FQDN::TEST_DOMAIN
            .push_label("a")
            .push_label("b")
            .push_label("c")
            .push_label("d"),
    )
}

#[test]
fn bogus_wildcard_expansion_qname_exists_expand_multiple_labels() -> Result<(), Error> {
    bogus_wildcard_expansion_qname_exists(
        FQDN::TEST_DOMAIN.push_label("a").push_label("*"),
        FQDN::TEST_DOMAIN
            .push_label("a")
            .push_label("b")
            .push_label("c")
            .push_label("d"),
    )
}

fn bogus_wildcard_expansion_qname_exists(
    wildcard_name: FQDN,
    query_name: FQDN,
) -> Result<(), Error> {
    let network = Network::new()?;
    let sign_settings = SignSettings::default().nsec(Nsec::_3 {
        iterations: 1,
        opt_out: false,
        salt: None,
    });

    let mut leaf_ns = NameServer::new(&PEER, FQDN::TEST_DOMAIN, &network)?;
    leaf_ns.add(Record::a(
        wildcard_name.clone(),
        Ipv4Addr::new(192, 168, 1, 1),
    ));
    leaf_ns.add(TXT {
        zone: query_name.clone(),
        ttl: 86400,
        character_strings: vec!["placeholder".to_owned()],
    });
    let leaf_ns = leaf_ns.sign(sign_settings.clone())?;

    let proxy_ns = NameServer::new(
        &Implementation::test_server(
            "bogus_wildcard_expansion_qname_exists",
            vec![
                leaf_ns.ipv4_addr().to_string(),
                wildcard_name.to_string(),
                query_name.to_string(),
            ],
            "both",
        ),
        FQDN::TEST_DOMAIN,
        &network,
    )?;

    let mut tld_ns = NameServer::new(&PEER, FQDN::TEST_TLD, &network)?;
    tld_ns.referral_nameserver(&proxy_ns);
    tld_ns.add(leaf_ns.ds().ksk.clone());
    let tld_ns = tld_ns.sign(sign_settings.clone())?;

    let mut root_ns = NameServer::new(&PEER, FQDN::ROOT, &network)?;
    root_ns.referral_nameserver(&tld_ns);
    root_ns.add(tld_ns.ds().ksk.clone());
    let root_ns = root_ns.sign(sign_settings)?;
    let root_hint = root_ns.root_hint();
    let trust_anchor = root_ns.trust_anchor();

    let _leaf_ns = leaf_ns.start()?;
    let _proxy_ns = proxy_ns.start()?;
    let _tld_ns = tld_ns.start()?;
    let _root_ns = root_ns.start()?;

    let resolver = Resolver::new(&network, root_hint)
        .trust_anchor(&trust_anchor)
        .start()?;

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().dnssec();
    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &query_name)?;

    if SUBJECT.is_unbound() && output.status == DigStatus::NOERROR {
        // For one of these queries, Unbound catches that the "positive response was wildcard
        // expansion and did not prove original data did not exist", then tries again and assembles
        // a correct NODATA response from cached records.
        assert!(output.answer.is_empty(), "{output:?}");
    } else {
        assert_eq!(output.status, DigStatus::SERVFAIL);
    }

    Ok(())
}
