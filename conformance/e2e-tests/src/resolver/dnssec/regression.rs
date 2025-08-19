use std::net::Ipv4Addr;

use dns_test::{
    Error, FQDN, Implementation, Network, Resolver,
    client::{Client, DigSettings},
    name_server::{Graph, NameServer, Sign},
    record::{Record, RecordType},
    tshark::{Capture, Direction},
    zone_file::SignSettings,
};

/// regression test for https://github.com/hickory-dns/hickory-dns/issues/3090
#[test]
fn infinite_recursion_with_unsigned_ds_record() -> Result<(), Error> {
    let needle_fqdn = FQDN::EXAMPLE_SUBDOMAIN;
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let network = Network::new()?;

    let mut leaf_ns = NameServer::new(&Implementation::test_peer(), FQDN::TEST_DOMAIN, &network)?;
    leaf_ns.add(Record::a(needle_fqdn.clone(), expected_ipv4_addr));

    let Graph {
        nameservers,
        root,
        trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::AndAmend {
            settings: SignSettings::default(),
            mutate: &|zone, records| {
                if zone == &FQDN::TEST_TLD {
                    let mut did_remove_rrsig = false;
                    let mut did_set_ttl_0 = false;

                    for record in records.iter_mut() {
                        if let Record::RRSIG(rrsig) = record {
                            if rrsig.type_covered == RecordType::DS
                                && rrsig.fqdn == FQDN::TEST_DOMAIN
                            {
                                let mut rrsig = rrsig.clone();
                                rrsig.fqdn = FQDN("invalid.name.testing.").unwrap();
                                *record = Record::RRSIG(rrsig);
                                did_remove_rrsig = true;
                            }
                        }
                        if let Record::DS(ds) = record {
                            if ds.zone == FQDN::TEST_DOMAIN {
                                let mut ds = ds.clone();
                                ds.ttl = 0;
                                *record = Record::DS(ds);
                                did_set_ttl_0 = true;
                            }
                        }
                    }

                    assert!(
                        did_remove_rrsig,
                        "did not find an RRSIG covering a DS record"
                    );
                    assert!(did_set_ttl_0, "did not find an RRSIG covering a DS record");
                }
            },
        },
    )?;

    let trust_anchor = trust_anchor.unwrap();
    let resolver = Resolver::new(&network, root)
        .trust_anchor(&trust_anchor)
        .start_with_subject(&Implementation::hickory())?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;

    let mut tshark = None;
    for ns in nameservers.iter() {
        if *ns.zone() == FQDN::TEST_TLD {
            tshark = Some(ns.eavesdrop_udp()?);
        }
    }

    let Some(mut tshark) = tshark else {
        panic!(
            "could not attach tshark capture to {} server",
            FQDN::TEST_TLD
        );
    };

    // pre-condition: `DS FQDN::TEST_DOMAIN` must return servfail when querying DS record
    let ds_settings = *DigSettings::default().recurse();
    let output = client.dig(
        ds_settings,
        resolver_addr,
        RecordType::DS,
        &FQDN::TEST_DOMAIN,
    )?;

    assert!(output.status.is_servfail());

    tshark.wait_for_capture()?;

    let captures = tshark.terminate()?;

    // We should see exactly one inbound DS query for FQDN::TEST_DOMAIN
    let mut ds_count = 0;
    for capture in captures {
        let Capture {
            direction: Direction::Incoming { .. },
            ..
        } = capture
        else {
            continue;
        };

        let message = capture.message.as_value().as_object().unwrap();
        let queries = message.get("Queries").unwrap().as_object().unwrap();
        let query = queries.values().next().unwrap().as_object().unwrap();

        // These are represented as a &str but contain the numeric record type.
        if query.get("dns.qry.type").unwrap() == "43" {
            ds_count += 1;
        }
    }

    assert_eq!(ds_count, 1);

    let logs = resolver.logs()?;
    assert!(!logs.contains("exceeded max validation depth"));

    Ok(())
}

/// regression test for https://github.com/hickory-dns/hickory-dns/issues/2252
#[test]
fn infinite_recursion_with_deprecated_algorithm() -> Result<(), Error> {
    let needle_fqdn = FQDN::EXAMPLE_SUBDOMAIN;
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let network = Network::new()?;

    let mut leaf_ns = NameServer::new(&Implementation::test_peer(), FQDN::TEST_DOMAIN, &network)?;
    leaf_ns.add(Record::a(needle_fqdn.clone(), expected_ipv4_addr));

    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::Yes {
            settings: SignSettings::rsasha1_nsec3(),
        },
    )?;

    let trust_anchor = trust_anchor.unwrap();
    let resolver = Resolver::new(&network, root)
        .trust_anchor(&trust_anchor)
        .start_with_subject(&Implementation::hickory())?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;

    // pre-condition: `DS .` must return an empty answer section
    let ds_settings = *DigSettings::default().recurse();
    let output = client.dig(ds_settings, resolver_addr, RecordType::DS, &FQDN::ROOT)?;

    assert!(output.answer.is_empty());

    // bug: this triggers infinite recursion
    let a_settings = *DigSettings::default().recurse().authentic_data();
    let res = client.dig(a_settings, resolver_addr, RecordType::A, &needle_fqdn);

    // we are not interested in the actual answer; just that the server does not crash
    assert!(res.is_ok(), "server did not answer query");

    let logs = resolver.logs()?;

    assert!(!logs.contains("stack overflow"));
    assert!(!logs.contains("panicked"));

    Ok(())
}
