use std::net::Ipv4Addr;

use dns_test::client::{Client, DigSettings, ExtendedDnsError};
use dns_test::name_server::{Graph, NameServer, Sign};
use dns_test::record::{Record, RecordType};
use dns_test::{Network, Resolver, Result, FQDN};

#[ignore]
#[test]
fn dnskey_missing() -> Result<()> {
    let subject = dns_test::subject();
    let supports_ede = subject.supports_ede();

    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let needle_fqdn = FQDN("example.nameservers.com.")?;

    let network = Network::new()?;
    let mut leaf_ns = NameServer::new(&dns_test::peer(), FQDN::NAMESERVERS, &network)?;
    leaf_ns.add(Record::a(needle_fqdn.clone(), expected_ipv4_addr));

    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::AndAmend(&|zone, records| {
            // remove the ZSK DNSKEY record
            if zone == &FQDN::NAMESERVERS {
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
                assert_eq!(1, remove_count);
            }
        }),
    )?;

    let mut resolver = Resolver::new(&network, root);

    if supports_ede {
        resolver.extended_dns_errors();
    }

    let trust_anchor = &trust_anchor.unwrap();
    let resolver = resolver.trust_anchor(trust_anchor).start(&subject)?;
    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(&network)?;

    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver_addr, RecordType::A, &needle_fqdn)?;

    assert!(output.status.is_servfail());

    if supports_ede {
        assert_eq!(Some(ExtendedDnsError::DnskeyMissing), output.ede);
    }

    Ok(())
}
