use std::net::Ipv4Addr;

use base64::prelude::*;
use dns_test::client::{Client, DigSettings};
use dns_test::name_server::{Graph, NameServer, Sign};
use dns_test::record::{Record, RecordType};
use dns_test::{Network, Resolver, Result, FQDN};

#[ignore]
#[test]
fn bad_signature_in_leaf_nameserver() -> Result<()> {
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let needle_fqdn = FQDN("example.nameservers.com.")?;

    let network = Network::new()?;
    let peer = dns_test::peer();

    let mut leaf_ns = NameServer::new(&peer, FQDN::NAMESERVERS, &network)?;
    leaf_ns.add(Record::a(needle_fqdn.clone(), expected_ipv4_addr));

    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::AndAmend(&|zone, records| {
            if zone == &FQDN::NAMESERVERS {
                let mut modified = 0;
                for record in records {
                    if let Record::RRSIG(rrsig) = record {
                        if rrsig.fqdn == needle_fqdn {
                            let mut signature = BASE64_STANDARD.decode(&rrsig.signature).unwrap();
                            let last = signature.last_mut().expect("empty signature");
                            *last = !*last;

                            rrsig.signature = BASE64_STANDARD.encode(&signature);
                            modified += 1;
                        }
                    }
                }

                assert_eq!(modified, 1, "sanity check");
            }
        }),
    )?;

    let trust_anchor = &trust_anchor.unwrap();
    let resolver = Resolver::new(&network, root)
        .trust_anchor(trust_anchor)
        .start(&dns_test::subject())?;
    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(&network)?;

    let mut settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver_addr, RecordType::A, &needle_fqdn)?;

    // the resolver will try to validate the chain of trust; the validation fails so it responds
    // with SERVFAIL
    assert!(output.status.is_servfail());

    // avoids a SERVFAIL response
    settings.checking_disabled();

    let output = client.dig(settings, resolver_addr, RecordType::A, &needle_fqdn)?;

    // when the CD (Checking Disabled) bit is set the server won't respond with SERVFAIL on
    // validation errors. the outcome of the validation process is reported in the AD bit
    assert!(output.status.is_noerror());
    assert!(!output.flags.authenticated_data);

    Ok(())
}
