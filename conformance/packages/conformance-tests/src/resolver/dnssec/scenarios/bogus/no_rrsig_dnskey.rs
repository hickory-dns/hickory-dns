//! the RRSIGs that cover the DNSKEY have been removed

use std::net::Ipv4Addr;

use dns_test::{
    FQDN, Implementation, Network, Resolver, Result,
    client::{Client, DigSettings, ExtendedDnsError},
    name_server::{Graph, NameServer, Sign},
    record::{Record, RecordType},
    zone_file::SignSettings,
};

#[test]
fn query_dnskey_record() -> Result<()> {
    let network = Network::new()?;

    let leaf_zone = FQDN::TEST_TLD.push_label("no-rrsig-dnskey");

    let leaf_ns = NameServer::new(&dns_test::PEER, leaf_zone.clone(), &network)?;

    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::AndAmend {
            settings: SignSettings::default(),
            mutate: &|zone, records| {
                if *zone == leaf_zone {
                    let mut remove_count = 0;
                    for index in (0..records.len()).rev() {
                        if let Record::RRSIG(rrsig) = &records[index] {
                            if rrsig.type_covered == RecordType::DNSKEY {
                                records.swap_remove(index);
                                remove_count += 1;
                            }
                        }
                    }
                    // sanity check
                    assert_ne!(0, remove_count);
                }
            },
        },
    )?;

    let trust_anchor = trust_anchor.unwrap();
    let mut resolver = Resolver::new(&network, root);

    if dns_test::SUBJECT.is_unbound() {
        resolver.extended_dns_errors();
    }

    let resolver = resolver.trust_anchor(&trust_anchor).start()?;

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(
        settings,
        resolver.ipv4_addr(),
        RecordType::DNSKEY,
        &leaf_zone,
    )?;

    dbg!(&output);

    assert!(output.status.is_servfail());

    if dns_test::SUBJECT.is_unbound() {
        // check that this failed for the right reason
        assert!(output.ede.iter().eq(&[ExtendedDnsError::RrsigsMissing]));
    }

    Ok(())
}

#[test]
fn query_other_record() -> Result<()> {
    let network = Network::new()?;

    let leaf_zone = FQDN::TEST_TLD.push_label("no-rrsig-dnskey");

    // other implementations fail the PRE-CONDITION below
    let peer = Implementation::Bind;
    let mut leaf_ns = NameServer::new(&peer, leaf_zone.clone(), &network)?;
    leaf_ns.add(Record::a(leaf_zone.clone(), Ipv4Addr::new(1, 2, 3, 4)));
    let leaf_ns_addr = leaf_ns.ipv4_addr();

    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::AndAmend {
            settings: SignSettings::default(),
            mutate: &|zone, records| {
                if *zone == leaf_zone {
                    let mut remove_count = 0;
                    for index in (0..records.len()).rev() {
                        if let Record::RRSIG(rrsig) = &records[index] {
                            if rrsig.type_covered == RecordType::DNSKEY {
                                records.swap_remove(index);
                                remove_count += 1;
                            }
                        }
                    }
                    // sanity check
                    assert_ne!(0, remove_count);
                }
            },
        },
    )?;

    let trust_anchor = trust_anchor.unwrap();
    let mut resolver = Resolver::new(&network, root);

    if dns_test::SUBJECT.is_unbound() {
        resolver.extended_dns_errors();
    }

    let resolver = resolver.trust_anchor(&trust_anchor).start()?;

    let client = Client::new(&network)?;
    // PRE-CONDITION the authoritative server must include the RRSIG records
    let settings = *DigSettings::default().dnssec();
    let output = client.dig(settings, leaf_ns_addr, RecordType::A, &leaf_zone)?;
    assert!(output.status.is_noerror());
    assert!(
        output
            .answer
            .iter()
            .any(|record| matches!(record, Record::RRSIG(_))),
        "peer name server fails PRE-CONDITION"
    );

    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &leaf_zone)?;

    dbg!(&output);

    assert!(output.status.is_servfail());

    if dns_test::SUBJECT.is_unbound() {
        // check that this failed for the right reason
        assert!(output.ede.iter().eq(&[ExtendedDnsError::RrsigsMissing]));
    }

    Ok(())
}
