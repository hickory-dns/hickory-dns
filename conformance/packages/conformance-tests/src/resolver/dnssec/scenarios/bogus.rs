use dns_test::{
    client::{Client, DigSettings, ExtendedDnsError},
    name_server::{Graph, NameServer, Sign},
    record::{Record, RecordType},
    zone_file::SignSettings,
    Network, Resolver, Result, FQDN,
};

// the RRSIGs that cover the DNSKEY have been removed
#[test]
#[ignore]
fn no_rrsig_dnskey() -> Result<()> {
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
        assert_eq!(Some(ExtendedDnsError::RrsigsMissing), output.ede);
    }

    Ok(())
}
