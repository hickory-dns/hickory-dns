use std::net::Ipv4Addr;

use base64::prelude::*;
use dns_test::client::{Client, DigSettings};
use dns_test::name_server::NameServer;
use dns_test::record::{Record, RecordType};
use dns_test::zone_file::Root;
use dns_test::{Network, Resolver, Result, TrustAnchor, FQDN};

#[ignore]
#[test]
fn bad_signature_in_leaf_nameserver() -> Result<()> {
    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let needle_fqdn = FQDN("example.nameservers.com.")?;

    let network = Network::new()?;
    let peer = dns_test::peer();
    let mut root_ns = NameServer::new(&peer, FQDN::ROOT, &network)?;
    let mut com_ns = NameServer::new(&peer, FQDN::COM, &network)?;

    let mut nameservers_ns = NameServer::new(&peer, FQDN("nameservers.com.")?, &network)?;
    nameservers_ns
        .add(Record::a(root_ns.fqdn().clone(), root_ns.ipv4_addr()))
        .add(Record::a(com_ns.fqdn().clone(), com_ns.ipv4_addr()))
        .add(Record::a(needle_fqdn.clone(), expected_ipv4_addr));
    let mut nameservers_ns = nameservers_ns.sign()?;

    // fault injection: change the signature field of the RRSIG that covers the A record we'll query
    let mut modified = 0;
    for record in &mut nameservers_ns.signed_zone_file_mut().records {
        if let Record::RRSIG(rrsig) = record {
            if rrsig.fqdn == needle_fqdn {
                let mut signature = BASE64_STANDARD.decode(&rrsig.signature)?;
                let last = signature.last_mut().expect("empty signature");
                *last = !*last;

                rrsig.signature = BASE64_STANDARD.encode(&signature);
                modified += 1;
            }
        }
    }
    assert_eq!(modified, 1, "sanity check");

    let nameservers_ds = nameservers_ns.ds().clone();
    let nameservers_ns = nameservers_ns.start()?;

    com_ns
        .referral(
            nameservers_ns.zone().clone(),
            nameservers_ns.fqdn().clone(),
            nameservers_ns.ipv4_addr(),
        )
        .add(nameservers_ds);
    let com_ns = com_ns.sign()?;
    let com_ds = com_ns.ds().clone();
    let com_ns = com_ns.start()?;

    root_ns
        .referral(FQDN::COM, com_ns.fqdn().clone(), com_ns.ipv4_addr())
        .add(com_ds);
    let root_ns = root_ns.sign()?;
    let root_ksk = root_ns.key_signing_key().clone();
    let root_zsk = root_ns.zone_signing_key().clone();

    let root_ns = root_ns.start()?;

    let roots = &[Root::new(root_ns.fqdn().clone(), root_ns.ipv4_addr())];

    let trust_anchor = TrustAnchor::from_iter([root_ksk.clone(), root_zsk.clone()]);
    let resolver = Resolver::start(&dns_test::subject(), roots, &trust_anchor, &network)?;
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
