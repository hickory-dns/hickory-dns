use std::net::Ipv4Addr;

use dns_test::client::{Client, DigSettings, ExtendedDnsError};
use dns_test::name_server::{Graph, NameServer, Sign};
use dns_test::record::{Record, RecordType};
use dns_test::zone_file::SignSettings;
use dns_test::{Network, Resolver, Result, FQDN};

#[ignore]
#[test]
fn dnskey_missing() -> Result<()> {
    fixture(
        ExtendedDnsError::DnskeyMissing,
        |_needle_fqdn, zone, records| {
            if zone == &FQDN::NAMESERVERS {
                // remove the DNSKEY record that contains the ZSK
                let mut remove_count = 0;
                *records = records
                    .drain(..)
                    .filter(|record| {
                        let remove = if let Record::DNSKEY(dnskey) = record {
                            dnskey.is_zone_signing_key()
                        } else {
                            false
                        };

                        if remove {
                            remove_count += 1;
                        }

                        !remove
                    })
                    .collect();
                assert_eq!(1, remove_count, "sanity check");
            }
        },
    )
}

#[ignore]
#[test]
fn rrsigs_missing() -> Result<()> {
    fixture(
        ExtendedDnsError::RrsigsMissing,
        |needle_fqdn, zone, records| {
            if zone == &FQDN::NAMESERVERS {
                // remove the RRSIG records that covers the needle record
                let mut remove_count = 0;
                *records = records
                    .drain(..)
                    .filter(|record| {
                        let remove = if let Record::RRSIG(rrsig) = record {
                            rrsig.type_covered == RecordType::A && rrsig.fqdn == *needle_fqdn
                        } else {
                            false
                        };

                        if remove {
                            remove_count += 1;
                        }

                        !remove
                    })
                    .collect();
                assert_eq!(1, remove_count, "sanity check");
            }
        },
    )
}

#[ignore]
#[test]
fn unsupported_dnskey_algorithm() -> Result<()> {
    fixture(
        ExtendedDnsError::UnsupportedDnskeyAlgorithm,
        |needle_fqdn, zone, records| {
            if zone == &FQDN::NAMESERVERS {
                // lie about the algorithm that was used to sign the needle record
                let mut modified_count = 0;
                for record in records {
                    if let Record::RRSIG(rrsig) = record {
                        if rrsig.type_covered == RecordType::A && rrsig.fqdn == *needle_fqdn {
                            assert_ne!(1, rrsig.algorithm, "modify the value below");
                            rrsig.algorithm = 1;
                            modified_count += 1;
                        }
                    }
                }
                assert_eq!(1, modified_count, "sanity check");
            }
        },
    )
}

#[ignore]
#[test]
fn dnssec_bogus() -> Result<()> {
    fixture(
        ExtendedDnsError::DnssecBogus,
        |needle_fqdn, zone, records| {
            if zone == &FQDN::NAMESERVERS {
                // corrupt the RRSIG record that covers the needle record
                let mut modified_count = 0;
                for record in records {
                    if let Record::RRSIG(rrsig) = record {
                        if rrsig.type_covered == RecordType::A && rrsig.fqdn == *needle_fqdn {
                            rrsig.signature_expiration = rrsig.signature_inception - 1;
                            modified_count += 1;
                        }
                    }
                }
                assert_eq!(1, modified_count, "sanity check");
            }
        },
    )
}

// Sets up a minimal, DNSSEC-enabled DNS graph where the leaf zone contains a "needle" A record
// that we'll search for
//
// `amend` can be used to modify zone files *after* they have been signed. it's used to introduce
// errors in the signed zone files
//
// the query for the needle record is expected to fail with the `expected` Extended DNS Error
fn fixture(
    expected: ExtendedDnsError,
    amend: fn(needle_fqdn: &FQDN, zone: &FQDN, records: &mut Vec<Record>),
) -> Result<()> {
    let subject = &dns_test::SUBJECT;
    let supports_ede = subject.supports_ede();

    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let needle_fqdn = FQDN("example.nameservers.com.")?;

    let network = Network::new()?;
    let mut leaf_ns = NameServer::new(&dns_test::PEER, FQDN::NAMESERVERS, &network)?;
    leaf_ns.add(Record::a(needle_fqdn.clone(), expected_ipv4_addr));

    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::AndAmend {
            settings: SignSettings::default(),
            mutate: &|zone, records| {
                amend(&needle_fqdn, zone, records);
            },
        },
    )?;

    let mut resolver = Resolver::new(&network, root);

    if supports_ede {
        resolver.extended_dns_errors();
    }

    let trust_anchor = &trust_anchor.unwrap();
    let resolver = resolver.trust_anchor(trust_anchor).start()?;
    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(&network)?;

    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver_addr, RecordType::A, &needle_fqdn)?;

    assert!(output.status.is_servfail());

    if supports_ede {
        assert_eq!(Some(expected), output.ede);
    }

    Ok(())
}
